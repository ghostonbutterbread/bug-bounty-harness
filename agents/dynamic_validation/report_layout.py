"""Helpers for live-validation report layout constraints."""

from __future__ import annotations

from pathlib import Path

from agents.report_paths import is_generated_report_navigation, is_seeded_report_index


LEGACY_STATUS_FIRST_REPORT_DIRS = (
    "active",
    "confirmed",
    "dormant",
    "novel",
    "raw",
    "archive",
    "complete",
    "index",
)


def legacy_status_first_dirs(reports_root: Path) -> list[Path]:
    matches: list[Path] = []
    for name in LEGACY_STATUS_FIRST_REPORT_DIRS:
        legacy_root = reports_root / name
        if not legacy_root.exists():
            continue
        if legacy_root.is_file():
            matches.append(legacy_root)
            continue
        for candidate in legacy_root.rglob("*.md"):
            if is_seeded_report_index(candidate) or is_generated_report_navigation(candidate):
                continue
            matches.append(candidate)
    return matches


def assert_no_legacy_status_first_dirs(reports_root: Path) -> None:
    legacy_paths = legacy_status_first_dirs(reports_root)
    if legacy_paths:
        rendered = ", ".join(str(path.relative_to(reports_root)) for path in legacy_paths)
        raise RuntimeError(
            f"live validation must not create legacy status-first report bodies: {rendered}"
        )
