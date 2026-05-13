"""Shared playbook typing helpers."""

from __future__ import annotations

from typing import Protocol


class TransportLike(Protocol):
    def json_version(self) -> dict:
        ...

    def target_snapshots(self) -> list[dict]:
        ...

    def snapshot(self) -> dict:
        ...

    def runtime_evaluate(self, websocket_url: str, expression: str, *, await_promise: bool = False) -> dict:
        ...

    def build_screenshot_command(self, *, image_format: str = "png", from_surface: bool = True) -> dict:
        ...

    def capture_screenshot(
        self,
        websocket_url: str,
        *,
        image_format: str = "png",
        from_surface: bool = True,
    ) -> dict:
        ...
