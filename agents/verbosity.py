"""Shared verbosity helpers for connected team modules."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Verbosity:
    level: int = 0

    @property
    def verbose(self) -> bool:
        return self.level >= 1

    @property
    def very_verbose(self) -> bool:
        return self.level >= 2

    def log(self, message: str, *, level: int = 1) -> None:
        if self.level >= level:
            print(message)


def clamp_verbosity(value: int | None) -> Verbosity:
    try:
        level = int(value or 0)
    except (TypeError, ValueError):
        level = 0
    return Verbosity(level=max(0, min(level, 2)))
