#!/usr/bin/env python3
"""Single-browser CDP pipe adapter. Rotating control disconnects old clients.

Not a same-uid security boundary: the service and its private Unix control
socket must be trusted. Chromium has no TCP debugging listener. No sessions,
cookies, or protocol bodies are logged. Rotation is a synchronous detach barrier.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading

from aiohttp import web


class PipeBrowser:
    def __init__(self, command, **kwargs):
        child_read, self.write_fd = os.pipe()
        self.read_fd, child_write = os.pipe()
        # dup in a fresh interpreter, not preexec_fn in a threaded process.
        wrapper = [
            sys.executable,
            str(Path(__file__).resolve()),
            "pipe-exec",
            str(child_read),
            str(child_write),
            *command,
        ]
        try:
            self.process = subprocess.Popen(
                wrapper, pass_fds=(child_read, child_write), **kwargs
            )
        except BaseException:
            os.close(self.write_fd)
            os.close(self.read_fd)
            raise
        finally:
            os.close(child_read)
            os.close(child_write)
        self.loop = asyncio.new_event_loop()
        self.pending = {}
        self.serial = 0
        self.clients = {}
        self.roots = {}
        self.token = secrets.token_urlsafe(32)
        self.rotating = False
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        buffer = b""
        try:
            while chunk := os.read(self.read_fd, 65536):
                buffer += chunk
                while b"\0" in buffer:
                    message, buffer = buffer.split(b"\0", 1)
                    self.loop.call_soon_threadsafe(self._received, json.loads(message))
        finally:
            os.close(self.read_fd)
            self.loop.call_soon_threadsafe(self._disconnected)

    def _disconnected(self):
        for future in list(self.pending.values()):
            if not future.done():
                future.set_exception(ConnectionError("Chromium pipe closed"))

    def _received(self, message):
        future = self.pending.pop(message.get("id"), None)
        if future is not None:
            if not future.done():
                future.set_result(message)
            return
        session = message.get("sessionId")
        for ws, owned in list(self.clients.items()):
            if session in owned:
                params = message.get("params", {})
                if message.get("method") == "Target.attachedToTarget":
                    owned.add(params["sessionId"])
                event = dict(message)
                if session == self.roots.get(ws):
                    event.pop("sessionId", None)
                asyncio.create_task(ws.send_json(event))

    async def call(self, method, params=None, session=None, generation=None):
        self.serial += 1
        identifier = self.serial
        future = self.loop.create_future()
        self.pending[identifier] = future
        message = {"id": identifier, "method": method, "params": params or {}}
        if session:
            message["sessionId"] = session
        try:
            data = json.dumps(message).encode() + b"\0"
            # Commands are bounded by aiohttp's message limit; pipe writes run
            # outside the event loop and serialize to avoid interleaving.
            async with self.write_lock:
                if generation is not None and (
                    generation != self.token or self.rotating
                ):
                    raise ConnectionError("Controller generation revoked")
                writing = asyncio.create_task(asyncio.to_thread(self._write, data))
                try:
                    await asyncio.shield(writing)
                except asyncio.CancelledError:
                    # Finish the one NUL-delimited message before releasing
                    # the write lock; cancellation must not splice messages.
                    await writing
                    raise
            return await asyncio.wait_for(future, 60)
        finally:
            self.pending.pop(identifier, None)

    def _write(self, data):
        while data:
            data = data[os.write(self.write_fd, data) :]

    async def route(self, request):
        if self.rotating or request.match_info["token"] != self.token:
            raise web.HTTPGone()
        suffix = request.match_info["suffix"]
        base = f"http://127.0.0.1:{self.port}/{self.token}"
        if suffix in ("json/version", "json/version/"):
            reply = await self.call("Browser.getVersion")
            if "result" not in reply:
                raise web.HTTPServiceUnavailable()
            return web.json_response(
                {
                    "Browser": reply.get("result", {}).get("product"),
                    "Protocol-Version": "1.3",
                    "webSocketDebuggerUrl": base.replace("http:", "ws:")
                    + "/devtools/browser",
                }
            )
        if suffix in ("json", "json/list"):
            reply = await self.call("Target.getTargets")
            return web.json_response(
                [
                    {
                        **t,
                        "id": t["targetId"],
                        "webSocketDebuggerUrl": base.replace("http:", "ws:")
                        + "/devtools/page/"
                        + t["targetId"],
                    }
                    for t in reply.get("result", {}).get("targetInfos", [])
                ]
            )
        if not suffix.startswith("devtools/"):
            raise web.HTTPNotFound()
        generation = self.token
        if suffix.startswith("devtools/page/"):
            reply = await self.call(
                "Target.attachToTarget",
                {"targetId": suffix.rsplit("/", 1)[1], "flatten": True},
            )
        else:
            reply = await self.call("Target.attachToBrowserTarget")
        root = reply.get("result", {}).get("sessionId")
        if not root:
            raise web.HTTPServiceUnavailable()
        if generation != self.token or self.rotating:
            await self.call("Target.detachFromTarget", {"sessionId": root})
            raise web.HTTPGone()
        ws = web.WebSocketResponse(max_msg_size=4 * 1024 * 1024)
        await ws.prepare(request)
        self.clients[ws] = {root}
        self.roots[ws] = root
        tasks = set()
        slots = asyncio.Semaphore(128)

        async def dispatch(command):
            try:
                session = command.get("sessionId", root)
                if session not in self.clients.get(ws, set()):
                    await ws.send_json(
                        {
                            "id": command.get("id"),
                            "error": {"code": -32000, "message": "Unowned session"},
                        }
                    )
                    return
                answer = await self.call(
                    command["method"], command.get("params"), session, generation
                )
                if generation != self.token or self.rotating or ws.closed:
                    return
                child = answer.get("result", {}).get("sessionId")
                if child:
                    self.clients[ws].add(child)
                answer["id"] = command["id"]
                if session == root:
                    answer.pop("sessionId", None)
                await ws.send_json(answer)
            except (ConnectionError, TimeoutError, KeyError, TypeError):
                # Do not return protocol bodies or token-bearing request paths.
                await ws.close(code=1011, message=b"CDP command unavailable")
            finally:
                slots.release()

        try:
            async for event in ws:
                if generation != self.token or self.rotating:
                    break
                if event.type != web.WSMsgType.TEXT:
                    break
                command = json.loads(event.data)
                await slots.acquire()
                # CDP is multiplexed: an awaited navigation may need another
                # command to resume an auto-attached target. Never serialize
                # command responses behind that navigation.
                task = asyncio.create_task(dispatch(command))
                tasks.add(task)
                task.add_done_callback(tasks.discard)
        finally:
            self.clients.pop(ws, None)
            self.roots.pop(ws, None)
            for task in list(tasks):
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self.call("Target.detachFromTarget", {"sessionId": root})
            await ws.close()
        return ws

    async def detach(self, session):
        reply = await self.call("Target.detachFromTarget", {"sessionId": session})
        error = reply.get("error")
        missing = {"session with given id not found", "no session with given id"}
        if error and str(error.get("message", "")).lower().rstrip(".") not in missing:
            raise RuntimeError("CDP session detach failed")

    async def rotate(self, request):
        # Only served on a mode-0600 Unix socket, never on the public TCP site.
        self.rotating = True
        self.token = secrets.token_urlsafe(32)
        try:
            for ws, sessions in list(self.clients.items()):
                for session in list(sessions):
                    await self.detach(session)
                await ws.close()
            self.clients.clear()
            barrier = await self.call("Browser.getVersion")
            if "result" not in barrier:
                raise RuntimeError("CDP fence barrier failed")
            return web.json_response(
                {
                    "cdp_url": f"http://127.0.0.1:{self.port}/{self.token}",
                    "fenced": True,
                }
            )
        finally:
            self.rotating = False

    async def _serve(self, port, socket_path):
        self.write_lock = asyncio.Lock()
        app = web.Application()
        app.router.add_route("*", "/{token}/{suffix:.*}", self.route)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", port)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]
        control = web.Application()
        control.router.add_post("/rotate", self.rotate)
        self.control_runner = web.AppRunner(control, access_log=None)
        await self.control_runner.setup()
        await web.UnixSite(self.control_runner, str(socket_path)).start()
        os.chmod(socket_path, 0o600)
        # Browser startup and pipe readiness are verified before publication.
        await self.call("Browser.getVersion")
        return f"http://127.0.0.1:{self.port}/{self.token}"

    def serve(self, port, socket_path):
        return asyncio.run_coroutine_threadsafe(
            self._serve(port, socket_path), self.loop
        ).result(40)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.wait(timeout=10)
        for runner in (
            getattr(self, "runner", None),
            getattr(self, "control_runner", None),
        ):
            if runner:
                asyncio.run_coroutine_threadsafe(runner.cleanup(), self.loop).result(15)
        os.close(self.write_fd)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=5)


def rotate_control(socket_path):
    import httpx

    with httpx.Client(
        transport=httpx.HTTPTransport(uds=str(socket_path)), timeout=20
    ) as client:
        response = client.post("http://localhost/rotate")
        response.raise_for_status()
        return response.json()


if __name__ == "__main__":
    if len(sys.argv) < 5 or sys.argv[1] != "pipe-exec":
        raise SystemExit("Internal Chromium pipe exec adapter")
    # Copy first because inherited source descriptors may themselves be 3/4.
    read_fd, write_fd = os.dup(int(sys.argv[2])), os.dup(int(sys.argv[3]))
    os.dup2(read_fd, 3, inheritable=True)
    os.dup2(write_fd, 4, inheritable=True)
    os.set_inheritable(3, True)
    os.set_inheritable(4, True)
    for descriptor in {read_fd, write_fd, int(sys.argv[2]), int(sys.argv[3])} - {3, 4}:
        os.close(descriptor)
    os.execv(sys.argv[4], sys.argv[4:])
