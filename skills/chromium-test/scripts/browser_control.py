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
import select
import subprocess
import sys
import threading
import time


# Discovery/transport upkeep is not evidence of user work. Other caller-issued
# CDP commands (including reads such as screenshots/evaluation) are activity.
PASSIVE_METHODS = {"Browser.getVersion", "Target.getTargets", "Target.getTargetInfo",
                   "Target.attachToTarget", "Target.attachToBrowserTarget",
                   "Target.detachFromTarget", "Target.setDiscoverTargets",
                   "Target.setAutoAttach"}


def meaningful(method):
    return method not in PASSIVE_METHODS and not method.endswith((".enable", ".disable"))

from aiohttp import web


class PipeBrowser:
    def __init__(self, command, diagnostics=None, **kwargs):
        from browser_lifecycle import StartupDiagnostics
        self.diagnostics = diagnostics or StartupDiagnostics("launcher")
        if self.diagnostics.path:
            kwargs["stderr"] = subprocess.PIPE
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
        if self.diagnostics.path:
            self.stderr_thread = self.diagnostics.drain_stderr(self.process.stderr)
        os.set_blocking(self.write_fd, False)
        self.loop = asyncio.new_event_loop()
        self.pending = {}
        self.serial = 0
        self.clients = {}
        self.roots = {}
        self.token = secrets.token_urlsafe(32)
        self.rotating = False
        self.frozen = False
        self.transfer = None
        self.transfer_destination = False
        self.quarantined = False
        self.epoch = 0
        self.last_activity = time.time()
        self.last_use = time.monotonic()
        self.inflight = 0
        self.reserved_until = 0.0
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

    async def call(self, method, params=None, session=None, generation=None, epoch=None):
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
                    generation != self.token or epoch != self.epoch or self.rotating
                    or self.frozen or self.transfer or self.quarantined
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
        deadline = time.monotonic() + 60
        while data:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [self.write_fd], [], remaining)[1]:
                # A partially written frame cannot safely be followed by another.
                # Fail the owned browser closed, rather than leave an operation
                # registered forever behind a blocked OS pipe.
                self.process.terminate()
                raise TimeoutError("Chromium pipe write deadline")
            try:
                data = data[os.write(self.write_fd, data):]
            except BlockingIOError:
                continue

    async def route(self, request):
        if self.rotating or self.transfer or self.quarantined or request.match_info["token"] != self.token:
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
        epoch = self.epoch
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
        if generation != self.token or epoch != self.epoch or self.rotating or self.transfer or self.quarantined:
            await self.call("Target.detachFromTarget", {"sessionId": root})
            raise web.HTTPGone()
        ws = web.WebSocketResponse(max_msg_size=4 * 1024 * 1024)
        await ws.prepare(request)
        # prepare yields to transfer_begin. Admission and registration must be
        # on the same loop turn as begin's clients/inflight check.
        if generation != self.token or epoch != self.epoch or self.rotating or self.transfer or self.quarantined:
            await ws.close()
            await self.detach(root)
            return ws
        self.clients[ws] = {root}
        self.roots[ws] = root
        tasks = set()
        slots = asyncio.Semaphore(128)

        async def dispatch(command):
            try:
                if not isinstance(command, dict) or not isinstance(command.get("method"), str):
                    raise TypeError("CDP method required")
                activity = meaningful(command["method"])
                session = command.get("sessionId", root)
                if session not in self.clients.get(ws, set()):
                    await ws.send_json(
                        {
                            "id": command.get("id"),
                            "error": {"code": -32000, "message": "Unowned session"},
                        }
                    )
                    return
                if (generation != self.token or epoch != self.epoch or self.rotating
                        or self.frozen or self.transfer or self.quarantined):
                    raise ConnectionError("Controller unavailable")
                # No await between admission and registration: freeze/recheck runs
                # on this same loop, so a command cannot enter through the gap.
                self.inflight += 1
                if activity:
                    self.mark_activity()
                try:
                    answer = await asyncio.wait_for(self.call(
                        command["method"], command.get("params"), session, generation, epoch
                    ), 120)
                finally:
                    self.inflight -= 1
                    if activity:
                        self.mark_activity()
                if generation != self.token or epoch != self.epoch or self.rotating or ws.closed:
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
                if generation != self.token or epoch != self.epoch or self.rotating:
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

    def mark_activity(self):
        self.last_activity = time.time()
        self.last_use = time.monotonic()

    def activity_status(self):
        return {"last_activity": self.last_activity,
                "idle_seconds": max(0, time.monotonic() - self.last_use),
                "inflight": self.inflight,
                "reserved_seconds": max(0, self.reserved_until - time.monotonic()),
                "frozen": self.frozen}

    async def identity(self, request):
        # Private Unix socket only: bind consumers to this exact process and
        # generation without rotating control or manufacturing browser activity.
        from browser_lifecycle import process_identity
        return web.json_response({
            "process_identity": process_identity(self.process.pid),
            "cdp_url": f"http://127.0.0.1:{self.port}/{self.token}",
            "available": not self.rotating and not self.frozen and not self.transfer and not self.quarantined,
            "quarantined": self.quarantined,
        })

    async def activity(self, request):
        return web.json_response(self.activity_status())

    async def freeze(self, request):
        if self.transfer or self.quarantined:
            raise web.HTTPConflict()
        data = await request.json()
        idle = float(data["idle_seconds"])
        if not 0 <= idle <= 7200:
            raise web.HTTPBadRequest()
        state = self.activity_status()
        if state["inflight"] or state["reserved_seconds"] or state["idle_seconds"] < idle:
            return web.json_response({"frozen": False, "reason": "activity-changed"})
        self.frozen = True
        return web.json_response({"frozen": True})

    async def thaw(self, request):
        if self.transfer or self.quarantined:
            raise web.HTTPConflict()
        # Manager uses this only after a failed stop and fresh exact runtime
        # health verification. Ownership and generation remain unchanged.
        self.frozen = False
        return web.json_response({"frozen": False})

    async def reserve(self, request):
        if self.transfer or self.quarantined:
            raise web.HTTPConflict()
        data = await request.json()
        seconds = float(data["seconds"])
        if not 0 <= seconds <= 3600 or self.frozen:
            raise web.HTTPConflict()
        # Repeated requests cannot slide an existing bound forward.
        if seconds == 0:
            self.reserved_until = 0
        elif self.reserved_until <= time.monotonic():
            self.reserved_until = time.monotonic() + seconds
        return web.json_response(self.activity_status())

    async def rotate(self, request):
        # Only served on a mode-0600 Unix socket, never on the public TCP site.
        if self.transfer or self.quarantined:
            raise web.HTTPConflict()
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
            self.frozen = False
            self.reserved_until = 0
            self.mark_activity()

    async def transfer_begin(self, request):
        """Exclusive adapter generation for a synchronous manager transaction."""
        data = await request.json()
        if self.transfer or self.quarantined or self.rotating or self.frozen or self.inflight or self.clients:
            raise web.HTTPConflict()
        self.rotating = True
        self.epoch += 1
        self.transfer = secrets.token_urlsafe(32)
        self.transfer_destination = data.get('destination') is True
        try:
            if "result" not in await self.call("Browser.getVersion"):
                raise web.HTTPServiceUnavailable()
            return web.json_response({"ticket": self.transfer})
        except BaseException:
            self.transfer = None
            self.transfer_destination = False
            raise
        finally:
            self.rotating = False

    async def transfer_call(self, request):
        data = await request.json()
        method = data.get("method")
        if method not in {"Runtime.evaluate", "Network.getAllCookies",
                          "Network.setCookies", "Network.deleteCookies"}:
            raise web.HTTPBadRequest()
        async with self.transfer_lock:
            if not self.transfer or data.get("ticket") != self.transfer:
                raise web.HTTPForbidden()
            targets = await self.call("Target.getTargets")
            pages = [t for t in targets.get("result", {}).get("targetInfos", []) if t.get("type") == "page"]
            if len(pages) != 1:
                raise web.HTTPConflict()
            attachment = await self.call("Target.attachToTarget", {"targetId": pages[0]["targetId"], "flatten": True})
            session = attachment.get("result", {}).get("sessionId")
            if not session:
                raise web.HTTPServiceUnavailable()
            try:
                reply = await self.call(method, data.get("params", {}), session)
            finally:
                await self.detach(session)
        return web.json_response(reply)

    async def transfer_end(self, request):
        data = await request.json()
        async with self.transfer_lock:
            if not self.transfer or data.get("ticket") != self.transfer:
                raise web.HTTPForbidden()
            if self.transfer_destination:
                self.quarantined = True
            else:
                self.transfer = None
                self.transfer_destination = False
            self.mark_activity()
        return web.json_response({"ended": True})

    async def transfer_commit(self, request):
        """Rotate public control without yet exposing imported auth."""
        data = await request.json()
        async with self.transfer_lock:
            if not self.quarantined or not self.transfer or data.get('ticket') != self.transfer:
                raise web.HTTPForbidden()
            self.token = secrets.token_urlsafe(32)
            self.epoch += 1
            return web.json_response({'cdp_url': f'http://127.0.0.1:{self.port}/{self.token}',
                                      'quarantined': True})

    async def transfer_abort(self, request):
        """Release only a manager-verified empty destination, never an uncertain one."""
        data = await request.json()
        async with self.transfer_lock:
            if not self.transfer or data.get('ticket') != self.transfer or not self.transfer_destination:
                raise web.HTTPForbidden()
            self.transfer = None
            self.transfer_destination = False
            self.quarantined = False
            self.mark_activity()
        return web.json_response({'aborted': True})

    async def transfer_activate(self, request):
        data = await request.json()
        async with self.transfer_lock:
            if not self.quarantined or not self.transfer or data.get('ticket') != self.transfer:
                raise web.HTTPForbidden()
            self.transfer = None
            self.transfer_destination = False
            self.quarantined = False
            self.mark_activity()
        return web.json_response({'activated': True})

    async def _serve(self, port, socket_path):
        self.diagnostics.mark("adapter-bind")
        self.write_lock = asyncio.Lock()
        self.transfer_lock = asyncio.Lock()
        app = web.Application()
        app.router.add_route("*", "/{token}/{suffix:.*}", self.route)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", port)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]
        control = web.Application()
        control.router.add_get("/identity", self.identity)
        control.router.add_post("/rotate", self.rotate)
        control.router.add_get("/activity", self.activity)
        control.router.add_post("/freeze", self.freeze)
        control.router.add_post("/thaw", self.thaw)
        control.router.add_post("/reserve", self.reserve)
        control.router.add_post("/transfer/begin", self.transfer_begin)
        control.router.add_post("/transfer/call", self.transfer_call)
        control.router.add_post("/transfer/end", self.transfer_end)
        control.router.add_post("/transfer/commit", self.transfer_commit)
        control.router.add_post("/transfer/abort", self.transfer_abort)
        control.router.add_post("/transfer/activate", self.transfer_activate)
        self.control_runner = web.AppRunner(control, access_log=None)
        await self.control_runner.setup()
        await web.UnixSite(self.control_runner, str(socket_path)).start()
        os.chmod(socket_path, 0o600)
        # Browser startup and pipe readiness are verified before publication.
        self.diagnostics.mark("adapter-bind", "ready")
        with self.diagnostics.phase("pipe-ready"):
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
        if getattr(self, "stderr_thread", None):
            self.stderr_thread.join(timeout=1)
        for runner in (
            getattr(self, "runner", None),
            getattr(self, "control_runner", None),
        ):
            if runner:
                asyncio.run_coroutine_threadsafe(runner.cleanup(), self.loop).result(15)
        os.close(self.write_fd)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=5)


def activity_control(socket_path, action="activity", **data):
    import httpx

    with httpx.Client(transport=httpx.HTTPTransport(uds=str(socket_path)), timeout=5) as client:
        response = (client.get("http://localhost/activity") if action == "activity"
                    else client.post("http://localhost/" + action, json=data))
        response.raise_for_status()
        return response.json()


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
    from browser_lifecycle import StartupDiagnostics
    with StartupDiagnostics("exec").phase("exec"):
        os.execv(sys.argv[4], sys.argv[4:])
