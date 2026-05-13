"""Read-only Electron CDP transport helpers."""

from __future__ import annotations

import json
from itertools import count
from typing import Any
from urllib import request

try:
    import websocket
except ImportError:  # pragma: no cover - fallback handled at runtime
    websocket = None

try:
    from websockets.sync.client import connect as websockets_sync_connect
except Exception:  # pragma: no cover - fallback handled at runtime
    websockets_sync_connect = None


class CDPTransportError(RuntimeError):
    """Raised when CDP HTTP or WebSocket endpoints return invalid data."""


class ElectronCDPTransport:
    _message_ids = count(1)

    def __init__(self, base_url: str, *, timeout: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _read_json(self, path: str) -> Any:
        url = f"{self.base_url}{path}"
        try:
            with request.urlopen(url, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
        except OSError as exc:
            raise CDPTransportError(f"failed to read {url}") from exc
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CDPTransportError(f"invalid JSON from {url}") from exc

    def json_version(self) -> dict[str, Any]:
        payload = self._read_json("/json/version")
        if not isinstance(payload, dict):
            raise CDPTransportError("/json/version must return an object")
        return payload

    def json_list(self) -> list[dict[str, Any]]:
        payload = self._read_json("/json/list")
        if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
            raise CDPTransportError("/json/list must return a list of objects")
        return payload

    def target_snapshots(self) -> list[dict[str, Any]]:
        snapshots: list[dict[str, Any]] = []
        for item in self.json_list():
            snapshots.append(
                {
                    "id": item.get("id", ""),
                    "type": item.get("type", ""),
                    "title": item.get("title", ""),
                    "url": item.get("url", ""),
                    "webSocketDebuggerUrl": item.get("webSocketDebuggerUrl", ""),
                    "devtoolsFrontendUrl": item.get("devtoolsFrontendUrl", ""),
                }
            )
        return snapshots

    def snapshot(self) -> dict[str, Any]:
        return {
            "version": self.json_version(),
            "targets": self.target_snapshots(),
        }

    def build_read_only_evaluate(self, expression: str, *, await_promise: bool = False) -> dict[str, Any]:
        if not str(expression).strip():
            raise ValueError("expression is required")
        return {
            "id": next(self._message_ids),
            "method": "Runtime.evaluate",
            "params": {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": await_promise,
                "userGesture": False,
            },
        }

    @staticmethod
    def build_screenshot_command(*, image_format: str = "png", from_surface: bool = True) -> dict[str, Any]:
        return {
            "id": 1,
            "method": "Page.captureScreenshot",
            "params": {
                "format": image_format,
                "fromSurface": from_surface,
            },
        }

    def runtime_evaluate(
        self,
        websocket_url: str,
        expression: str,
        *,
        await_promise: bool = False,
    ) -> dict[str, Any]:
        if not str(websocket_url or "").strip():
            raise CDPTransportError("webSocketDebuggerUrl is required for Runtime.evaluate")
        command = self.build_read_only_evaluate(expression, await_promise=await_promise)
        response = self._send_websocket_command(websocket_url, command)
        result = response.get("result")
        if not isinstance(result, dict):
            raise CDPTransportError("Runtime.evaluate did not return a result object")
        exception_details = result.get("exceptionDetails")
        if isinstance(exception_details, dict):
            text = exception_details.get("text") or "Runtime.evaluate raised an exception"
            raise CDPTransportError(str(text))
        return response

    def capture_screenshot(
        self,
        websocket_url: str,
        *,
        image_format: str = "png",
        from_surface: bool = True,
    ) -> dict[str, Any]:
        if not str(websocket_url or "").strip():
            raise CDPTransportError("webSocketDebuggerUrl is required for Page.captureScreenshot")
        command = self.build_screenshot_command(image_format=image_format, from_surface=from_surface)
        response = self._send_websocket_command(websocket_url, command)
        result = response.get("result")
        if not isinstance(result, dict):
            raise CDPTransportError("Page.captureScreenshot did not return a result object")
        if not isinstance(result.get("data"), str):
            raise CDPTransportError("Page.captureScreenshot did not return screenshot data")
        return response

    def _send_websocket_command(self, websocket_url: str, command: dict[str, Any]) -> dict[str, Any]:
        command_id = command.get("id")
        try:
            for raw_message in self._websocket_messages(websocket_url, command):
                try:
                    payload = json.loads(raw_message)
                except json.JSONDecodeError as exc:
                    raise CDPTransportError("invalid JSON from CDP WebSocket") from exc
                if not isinstance(payload, dict):
                    raise CDPTransportError("CDP WebSocket response must be an object")
                if payload.get("id") != command_id:
                    continue
                error = payload.get("error")
                if isinstance(error, dict):
                    message = error.get("message") or "CDP command failed"
                    raise CDPTransportError(str(message))
                return payload
        except CDPTransportError:
            raise
        except Exception as exc:  # pragma: no cover - backend specific
            raise CDPTransportError(f"Runtime.evaluate failed over CDP WebSocket: {exc}") from exc
        raise CDPTransportError("Runtime.evaluate did not receive a matching CDP response")

    def _websocket_messages(self, websocket_url: str, command: dict[str, Any]):
        if websocket is not None:
            connection = websocket.create_connection(
                websocket_url,
                timeout=self.timeout,
                suppress_origin=True,
            )
            try:
                set_timeout = getattr(connection, "settimeout", None)
                if callable(set_timeout):
                    set_timeout(self.timeout)
                connection.send(json.dumps(command))
                while True:
                    yield connection.recv()
            finally:
                connection.close()
            return
        if websockets_sync_connect is not None:
            with websockets_sync_connect(
                websocket_url,
                open_timeout=self.timeout,
                close_timeout=self.timeout,
                origin=None,
            ) as connection:
                connection.send(json.dumps(command))
                while True:
                    yield connection.recv(timeout=self.timeout)
            return
        raise CDPTransportError("no supported WebSocket client is available for CDP Runtime.evaluate")
