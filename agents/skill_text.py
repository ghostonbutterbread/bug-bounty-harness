"""Normalised reads for tests that assert claims about skill markdown.

Tests that match raw substrings against skill prose end up pinning line-wrap
positions and markdown emphasis, which makes the skill unrewrappable: reflowing
a paragraph or bolding a phrase breaks a test whose claim is still true. Routing
both sides of a comparison through `norm` keeps the claim pinned and makes
presentation free.

Use `raw` instead wherever a check genuinely depends on line structure, such as
counting table rows or slicing on a heading that must start a line.

Converting an existing test: normalise the haystack, the needles, and any
section-slicing delimiters **together**. A half-conversion, where needles lose
their emphasis but a read stays raw, is worse than leaving the test alone: the
positive assertions fail loudly, but a `not in` or `absent` check silently
passes while guarding nothing. Verify a conversion by reflowing the skill at
two widths and confirming the test still passes, and by breaking the claim and
confirming it fails. Do not batch-convert files that mainly test Python
behaviour and merely happen to read one skill file.
"""

from __future__ import annotations

import re
from pathlib import Path

# Underscore is stripped alongside asterisk and backtick. It is an identifier
# character here (source_sites, vuln_class) rather than emphasis, so stripping
# it looks wrong in a diff, but it is applied to BOTH the needle and the
# haystack, so an identifier still matches and a negative guard still fires.
# Converted needles depend on it; do not narrow this set without re-verifying
# every converted test.
_EMPHASIS = re.compile(r"[*`_]")


def norm(text: str) -> str:
    """Collapse all whitespace and strip markdown emphasis and code fences."""
    return " ".join(_EMPHASIS.sub("", text).split())


def read_norm(path: str | Path) -> str:
    """Read a markdown file as normalised text."""
    return norm(Path(path).read_text(encoding="utf-8"))


def raw(path: str | Path) -> str:
    """Read a markdown file preserving line structure."""
    return Path(path).read_text(encoding="utf-8")


def claims(text: str, *fragments: str) -> None:
    """Assert each fragment appears, comparing normalised forms."""
    missing = [f for f in fragments if norm(f) not in text]
    assert not missing, f"missing claims: {missing}"


def absent(text: str, *fragments: str) -> None:
    """Assert each fragment does not appear, comparing normalised forms."""
    present = [f for f in fragments if norm(f) in text]
    assert not present, f"should no longer appear: {present}"
