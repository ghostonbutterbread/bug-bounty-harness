"""Shared reporting/findings compatibility helpers extracted from older team modules."""

from __future__ import annotations

from typing import Any, Sequence


def safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def split_file_reference(file_value: Any) -> tuple[str, int]:
    raw = str(file_value or "").strip()
    if not raw:
        return "", 0

    parts = raw.rsplit(":", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1])
    return raw, 0


def display_file_reference(finding: dict[str, Any]) -> str:
    file_path, inline_line = split_file_reference(finding.get("file", ""))
    line_number = safe_int(finding.get("line")) or inline_line
    if line_number > 0:
        return f"{file_path}:{line_number}"
    return file_path


def is_placeholder_finding(finding: dict[str, Any]) -> bool:
    title = str(finding.get("title") or finding.get("type") or "").strip()
    title_lc = title.lower()
    file_ref = str(finding.get("file_ref") or finding.get("file") or "").strip()
    description = str(finding.get("description") or "").strip()
    combined = f"{title} {description}".lower()
    markers = (
        "path:123",
        "identified source",
        "dangerous sink category",
        "what boundary is crossed",
        "how the data moves",
        "none provided.",
    )

    if title_lc in {"short vulnerability label", "short novel pattern label", "placeholder"}:
        return True
    if file_ref in {"path:123", ""}:
        return True
    return any(marker in combined for marker in markers)
