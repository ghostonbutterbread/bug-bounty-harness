"""Small markdown helpers shared by report readers."""

from __future__ import annotations

import re
from urllib.parse import unquote


def markdown_link_destinations(text: str) -> list[str]:
    """Return normalized local or remote destinations from markdown links."""
    destinations: list[str] = []
    for match in re.finditer(r"\[[^\]]+\]\(([^)]*)\)", text):
        raw = match.group(1).strip()
        if not raw:
            continue
        if raw.startswith("<") and raw.endswith(">"):
            raw = raw[1:-1].strip()
        raw = raw.split("#", 1)[0].strip()
        if raw:
            destinations.append(unquote(raw))
    return destinations
