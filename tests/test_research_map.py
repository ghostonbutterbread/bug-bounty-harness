"""Behavior tests for the Markdown-backed ResearchMap CLI."""

from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "research_map.py"
SPEC = importlib.util.spec_from_file_location("research_map", SCRIPT_PATH)
assert SPEC and SPEC.loader
research_map = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(research_map)


def write_card(root: Path, relative_path: str, content: str) -> Path:
    path = root / "cards" / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_init_creates_synced_markdown_layout_without_database(tmp_path: Path) -> None:
    root = tmp_path / "research"

    research_map.initialize_corpus(root)

    assert (root / "cards").is_dir()
    assert (root / "sources").is_dir()
    assert (root / "templates" / "research-card.md").is_file()
    assert not (root / "indexes" / "research.sqlite").exists()


def test_index_and_query_rank_matching_card_and_preserve_citation(tmp_path: Path) -> None:
    root = tmp_path / "research"
    research_map.initialize_corpus(root)
    write_card(
        root,
        "xss/parser-differential.md",
        """---
id: xss.parser-differential.invalid-javascript-url
title: Invalid JavaScript URL accepted by partial protocol parser
class: xss
tags:
  - dom-xss
  - url-parsing
  - parser-differential
status: credible-source-reported
confidence: medium
sources:
  - https://example.test/sanitizer-writeup
code_signals:
  - custom protocol parser
  - parse failure maps to safe
---

## Mechanism
A partial protocol parser rejects malformed input while browser normalization
later accepts it as a JavaScript URL.

## Test direction
Compare validator output against the eventual browser URL consumer.
""",
    )
    write_card(
        root,
        "ssrf/redirect.md",
        """---
id: ssrf.redirect-chain
title: Redirect-chain SSRF
class: ssrf
tags: [redirect, url-validation]
status: validated
sources: [https://example.test/ssrf]
---

## Mechanism
A redirect may reach a blocked destination.
""",
    )

    indexed = research_map.build_index(root)
    matches = research_map.query_cards(
        root,
        terms="partial protocol parser",
        classes=["xss"],
        tags=["parser-differential"],
        limit=5,
    )

    punctuation_matches = research_map.query_cards(
        root,
        terms="Next.js __BUILD_MANIFEST",
        limit=5,
    )

    assert indexed == 2
    assert [match.card.id for match in matches] == [
        "xss.parser-differential.invalid-javascript-url"
    ]
    assert punctuation_matches == []
    briefing = research_map.render_briefing(matches)
    assert "https://example.test/sanitizer-writeup" in briefing
    assert "source-reported" in briefing
    assert "Test direction" in briefing


def test_empty_briefing_describes_corpus_coverage_not_target_safety() -> None:
    briefing = research_map.render_briefing([])

    assert "no matching cards" in briefing
    assert "does not establish target safety" in briefing
    assert "does not establish that a technique is absent" in briefing


def test_validate_reports_missing_required_metadata(tmp_path: Path) -> None:
    root = tmp_path / "research"
    research_map.initialize_corpus(root)
    write_card(
        root,
        "xss/incomplete.md",
        """---
title: Untitled mechanism
class: xss
---

Body.
""",
    )

    problems = research_map.validate_cards(root)

    assert len(problems) == 1
    assert "missing required field: id" in problems[0]
    assert "missing required field: status" in problems[0]
