"""Focused tests for reporting markdown helpers."""

from __future__ import annotations

from agents.reporting.markdown import markdown_link_destinations


def test_markdown_link_destinations_extracts_normalized_targets() -> None:
    text = "\n".join(
        [
            "[plain](reports/finding.md)",
            "[fragment](reports/chain.md#evidence)",
            "[encoded](reports/a%20b.md)",
            "[angle](<reports/with space.md#part>)",
            "[empty]()",
        ]
    )

    assert markdown_link_destinations(text) == [
        "reports/finding.md",
        "reports/chain.md",
        "reports/a b.md",
        "reports/with space.md",
    ]
