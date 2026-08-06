#!/usr/bin/env python3
"""Markdown-backed, locally indexed research-card corpus.

The Markdown files under a synced research root are authoritative. This utility
creates the corpus layout, validates card metadata, rebuilds a local SQLite FTS
index, and returns compact cited research briefings for agents.

Examples:
    python3 scripts/research_map.py init
    python3 scripts/research_map.py validate
    python3 scripts/research_map.py index
    python3 scripts/research_map.py query --terms "custom protocol parser" --class xss
"""

from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

DEFAULT_ROOT = Path.home() / "notes" / "appsec" / "research"
INDEX_RELATIVE_PATH = Path("indexes") / "research.sqlite"
REQUIRED_FIELDS = ("id", "title", "class", "status")
VALID_STATUSES = {
    "draft",
    "source-reported",
    "credible-source-reported",
    "validated",
    "reproduced",
    "stale",
    "superseded",
}

CARD_TEMPLATE = """---
id: <class>.<short-mechanism-slug>
title: <concise mechanism title>
class: <xss|ssrf|auth|...>
tags:
  - <portable-technique-tag>
status: draft
confidence: low
sources: []
code_signals: []
technologies: []
---

## Mechanism
Describe **one narrow, technology-specific vector or provider-specific
capability-validation guide**: an endpoint/header, parser/resolver differential,
platform quirk, configuration interaction, workflow sequence, or a focused
service-specific question (for example, how a Gemini API key is recognized and
its restrictions/impact are safely distinguished).

Do not write generic advice, architecture guidance, tool overviews, broad
methodology, or “look harder” prompts. Those belong in sources, workflow notes,
or mindset deliveries—not ResearchMap cards.

## Preconditions
- State the conditions required for the mechanism to matter.

## Recognition questions
- What exact product/version, endpoint/path, header, API, parser, SDK, or code
  shape makes this vector relevant?
- What observable condition distinguishes the real vector from a superficial
  technology match?

## Test direction
Describe the smallest safe discriminating check for this exact vector. State
what outcome would support it and what result should cause a pivot.

## Limits / caveats
State version, context, or source limitations.
"""

README = """# ResearchMap

This directory is the synced, Markdown-authoritative portable AppSec research
corpus. `cards/` contains small, cited mechanism cards. `sources/` contains raw
or summarized source captures. `indexes/research.sqlite` is generated local
search state and may be regenerated at any time.

Use the BBH CLI:

```bash
python3 scripts/research_map.py validate
python3 scripts/research_map.py index
python3 scripts/research_map.py query --terms "sanitizer svg" --class xss
```

Card statuses: `draft`, `source-reported`, `credible-source-reported`,
`validated`, `reproduced`, `stale`, and `superseded`. Research cards are
hypothesis inputs, not facts about a live target.
"""


class Card:
    def __init__(self, path: Path, metadata: dict[str, Any], body: str) -> None:
        self.path = path
        self.metadata = metadata
        self.body = body.strip()

    @property
    def id(self) -> str:
        return str(self.metadata.get("id", ""))

    @property
    def title(self) -> str:
        return str(self.metadata.get("title", ""))

    @property
    def class_name(self) -> str:
        return str(self.metadata.get("class", ""))

    def values(self, name: str) -> list[str]:
        value = self.metadata.get(name, [])
        if isinstance(value, list):
            return [str(item) for item in value]
        if value in (None, ""):
            return []
        return [str(value)]


class QueryMatch:
    def __init__(self, card: Card, score: float) -> None:
        self.card = card
        self.score = score


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if value == "[]":
        return []
    if value.startswith("[") and value.endswith("]"):
        return [item.strip().strip("\"'") for item in value[1:-1].split(",") if item.strip()]
    return value.strip("\"'")


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---\n"):
        raise ValueError("missing YAML frontmatter opening delimiter")
    closing = text.find("\n---", 4)
    if closing < 0:
        raise ValueError("missing YAML frontmatter closing delimiter")
    raw_metadata = text[4:closing]
    body = text[closing + 4 :].lstrip("\n")
    metadata: dict[str, Any] = {}
    current_list: str | None = None
    for raw_line in raw_metadata.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        list_item = re.match(r"^\s+-\s+(.+?)\s*$", raw_line)
        if list_item:
            if current_list is None:
                raise ValueError(f"list item without a key: {raw_line}")
            metadata.setdefault(current_list, []).append(parse_scalar(list_item.group(1)))
            continue
        key_value = re.match(r"^([A-Za-z][A-Za-z0-9_-]*):(?:\s*(.*))?$", raw_line)
        if not key_value:
            raise ValueError(f"unsupported frontmatter line: {raw_line}")
        key, value = key_value.groups()
        if value is None or not value.strip():
            metadata[key] = []
            current_list = key
            continue
        metadata[key] = parse_scalar(value)
        current_list = None
    return metadata, body


def read_card(path: Path) -> Card:
    metadata, body = parse_frontmatter(path.read_text(encoding="utf-8"))
    return Card(path, metadata, body)


def card_paths(root: Path) -> list[Path]:
    cards_root = root / "cards"
    return sorted(path for path in cards_root.rglob("*.md") if path.is_file()) if cards_root.exists() else []


def initialize_corpus(root: Path) -> None:
    for relative in ("cards", "sources", "indexes", "templates"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    (root / "templates" / "research-card.md").write_text(CARD_TEMPLATE, encoding="utf-8")
    readme = root / "README.md"
    if not readme.exists():
        readme.write_text(README, encoding="utf-8")


def validate_card(card: Card) -> list[str]:
    problems = [f"missing required field: {field}" for field in REQUIRED_FIELDS if not card.metadata.get(field)]
    status = str(card.metadata.get("status", ""))
    if status and status not in VALID_STATUSES:
        problems.append(f"unknown status: {status}")
    if status in {"source-reported", "credible-source-reported", "validated", "reproduced"} and not card.values("sources"):
        problems.append(f"status {status} requires at least one source")
    return problems


def validate_cards(root: Path) -> list[str]:
    problems: list[str] = []
    seen_ids: set[str] = set()
    for path in card_paths(root):
        try:
            card = read_card(path)
        except ValueError as exc:
            problems.append(f"{path}: {exc}")
            continue
        card_problems = validate_card(card)
        if card.id and card.id in seen_ids:
            card_problems.append(f"duplicate card id: {card.id}")
        seen_ids.add(card.id)
        if card_problems:
            problems.append(f"{path}: " + "; ".join(card_problems))
    return problems


def index_path(root: Path) -> Path:
    return root / INDEX_RELATIVE_PATH


def build_index(root: Path) -> int:
    problems = validate_cards(root)
    if problems:
        raise ValueError("cannot index invalid cards:\n" + "\n".join(problems))
    database = index_path(root)
    database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            DROP TABLE IF EXISTS cards;
            DROP TABLE IF EXISTS cards_fts;
            CREATE TABLE cards (
                id TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                title TEXT NOT NULL,
                class_name TEXT NOT NULL,
                tags TEXT NOT NULL,
                status TEXT NOT NULL,
                confidence TEXT NOT NULL,
                sources TEXT NOT NULL,
                code_signals TEXT NOT NULL,
                technologies TEXT NOT NULL,
                body TEXT NOT NULL
            );
            CREATE VIRTUAL TABLE cards_fts USING fts5(
                id, title, tags, code_signals, technologies, body,
                content='cards', content_rowid='rowid'
            );
            """
        )
        count = 0
        for path in card_paths(root):
            card = read_card(path)
            packed = lambda name: "|" + "|".join(value.lower() for value in card.values(name)) + "|"
            cursor = connection.execute(
                """INSERT INTO cards
                (id, path, title, class_name, tags, status, confidence, sources, code_signals, technologies, body)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    card.id,
                    str(path.relative_to(root)),
                    card.title,
                    card.class_name.lower(),
                    packed("tags"),
                    str(card.metadata.get("status", "")),
                    str(card.metadata.get("confidence", "")),
                    "\n".join(card.values("sources")),
                    packed("code_signals"),
                    packed("technologies"),
                    card.body,
                ),
            )
            connection.execute(
                "INSERT INTO cards_fts(rowid, id, title, tags, code_signals, technologies, body) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (cursor.lastrowid, card.id, card.title, packed("tags"), packed("code_signals"), packed("technologies"), card.body),
            )
            count += 1
    return count


def fts_match_query(terms: str) -> str:
    """Turn free-form agent search text into safe token-AND FTS syntax."""
    tokens = re.findall(r"[A-Za-z0-9]+", terms)
    return " AND ".join(f'"{token}"' for token in tokens)


def query_cards(root: Path, *, terms: str = "", classes: list[str] | None = None, tags: list[str] | None = None, limit: int = 8) -> list[QueryMatch]:
    database = index_path(root)
    if not database.exists():
        build_index(root)
    filters: list[str] = []
    parameters: list[Any] = []
    if classes:
        placeholders = ", ".join("?" for _ in classes)
        filters.append(f"c.class_name IN ({placeholders})")
        parameters.extend(value.lower() for value in classes)
    for tag in tags or []:
        filters.append("c.tags LIKE ?")
        parameters.append(f"%|{tag.lower()}|%")
    where = " AND ".join(filters) if filters else "1 = 1"
    join = "JOIN cards_fts f ON f.rowid = c.rowid"
    if terms.strip():
        fts_terms = fts_match_query(terms)
        if fts_terms:
            where = f"f.cards_fts MATCH ? AND {where}"
            parameters.insert(0, fts_terms)
    sql = f"""SELECT c.path, c.id, c.title, c.class_name, c.tags, c.status,
                      c.confidence, c.sources, c.code_signals, c.technologies, c.body,
                      bm25(cards_fts) AS score
               FROM cards c {join}
               WHERE {where}
               ORDER BY score, c.title
               LIMIT ?"""
    parameters.append(limit)
    matches: list[QueryMatch] = []
    with sqlite3.connect(database) as connection:
        for row in connection.execute(sql, parameters):
            metadata: dict[str, Any] = {
                "id": row[1], "title": row[2], "class": row[3],
                "tags": [item for item in row[4].strip("|").split("|") if item],
                "status": row[5], "confidence": row[6],
                "sources": row[7].splitlines() if row[7] else [],
                "code_signals": [item for item in row[8].strip("|").split("|") if item],
                "technologies": [item for item in row[9].strip("|").split("|") if item],
            }
            matches.append(QueryMatch(Card(root / row[0], metadata, row[10]), float(row[11])))
    return matches


def section(body: str, heading: str) -> str:
    pattern = rf"(?ms)^## {re.escape(heading)}\s*\n(.*?)(?=^## |\Z)"
    found = re.search(pattern, body)
    return found.group(1).strip() if found else ""


def render_briefing(matches: list[QueryMatch]) -> str:
    if not matches:
        return (
            "ResearchMap: no matching cards. This describes only the searched corpus and "
            "does not establish target safety and does not establish that a technique is absent. "
            "remove a filter, or query the external Preview source."
        )
    lines = [f"ResearchMap: {len(matches)} matching card(s)"]
    for number, match in enumerate(matches, 1):
        card = match.card
        lines.extend([
            "",
            f"{number}. {card.title}",
            f"   ID: {card.id} | class: {card.class_name} | status: {card.metadata.get('status', '')} | confidence: {card.metadata.get('confidence', 'unspecified')}",
        ])
        signals = card.values("code_signals")
        if signals:
            lines.append("   Code signals: " + "; ".join(signals))
        mechanism = section(card.body, "Mechanism")
        if mechanism:
            lines.append("   Mechanism: " + " ".join(mechanism.split()))
        direction = section(card.body, "Test direction")
        if direction:
            lines.append("   Test direction: " + " ".join(direction.split()))
        sources = card.values("sources")
        if sources:
            lines.append("   Sources: " + "; ".join(sources))
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help=f"Research corpus root (default: {DEFAULT_ROOT})")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("init", help="Create the Markdown corpus layout and card template")
    subcommands.add_parser("validate", help="Validate Markdown card metadata")
    subcommands.add_parser("index", help="Rebuild the local SQLite FTS index")
    query = subcommands.add_parser("query", help="Search indexed cards and print a cited briefing")
    query.add_argument("--terms", default="", help="FTS search terms")
    query.add_argument("--class", dest="classes", action="append", default=[], help="Class filter; repeatable")
    query.add_argument("--tag", dest="tags", action="append", default=[], help="Tag filter; repeatable")
    query.add_argument("--limit", type=int, default=8, help="Maximum cards to return")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    root = args.root.expanduser().resolve()
    if args.command == "init":
        initialize_corpus(root)
        print(f"Initialized ResearchMap corpus: {root}")
        return 0
    if args.command == "validate":
        problems = validate_cards(root)
        if problems:
            print("ResearchMap validation failed:", *problems, sep="\n", file=sys.stderr)
            return 1
        print(f"ResearchMap validation passed: {len(card_paths(root))} card(s)")
        return 0
    if args.command == "index":
        try:
            count = build_index(root)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"Indexed {count} card(s): {index_path(root)}")
        return 0
    if args.command == "query":
        if args.limit < 1:
            print("--limit must be at least 1", file=sys.stderr)
            return 2
        try:
            matches = query_cards(root, terms=args.terms, classes=args.classes, tags=args.tags, limit=args.limit)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(render_briefing(matches))
        return 0
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
