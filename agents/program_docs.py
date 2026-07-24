#!/usr/bin/env python3
"""Create and retrieve linked program documentation for Bug Bounty Harness.

Program docs preserve longer, target-specific integration and architecture models
without turning MapStore into a verbose ledger. They live at::

    <lane-root>/docs/<topic>.md

Examples::

    python3 agents/program_docs.py init --program poster
    python3 agents/program_docs.py write --program poster \
      --topic integrations/poster-sdk-export-flow \
      --title "Poster SDK export integration" \
      --body-file /tmp/model.md \
      --source https://docs.poster.example/sdk \
      --mapstore-ref recon/maps/_app/sdk-poster/index.md
    python3 agents/program_docs.py search --program poster --query "poster sdk export"
    python3 agents/program_docs.py show --program poster \
      --topic integrations/poster-sdk-export-flow

This CLI writes the fixed document structure. Agents supply only the scoped
working model, sources, and optional MapStore reference. It never fetches third-
party documentation: external material must be reviewed before promotion.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.storage_resolver import resolve_storage  # noqa: E402

INDEX_NAME = "index.md"
README_NAME = "README.md"
VALID_STATUSES = {"draft", "observed", "partially-verified", "verified", "stale", "superseded"}


def iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def split_csv(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        result.extend(part.strip() for part in value.split(",") if part.strip())
    return result


def safe_topic(value: str) -> str:
    topic = value.strip().strip("/")
    if not topic or topic.endswith(".md"):
        topic = topic[:-3] if topic.endswith(".md") else topic
    if not topic or topic.startswith("/") or ".." in Path(topic).parts:
        raise ValueError("topic must be a non-empty relative path without '..'")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_./-]*", topic):
        raise ValueError("topic may contain lowercase letters, digits, '.', '_', '/', and '-'")
    return topic


def docs_root(*, program: str, family: str, lane: str, root: str | None) -> Path:
    layout = resolve_storage(
        program, family=family, lane=lane, root_override=root, create=False
    )
    return layout.lane_root / "docs"


def topic_path(root: Path, topic: str) -> Path:
    path = (root / f"{safe_topic(topic)}.md").resolve()
    if root.resolve() not in path.parents:
        raise ValueError("topic resolves outside the docs root")
    return path


def render_readme() -> str:
    return """# Program Documentation

This directory contains concise, target-specific working models that expand a
linked MapStore observation: SDK and provider integrations, object and
authorization models, architecture, callback flows, and other reconstructed
program knowledge.

Do not read this directory broadly at startup. Retrieve a document only when a
concrete technology, integration, URL, or surface matches. Treat each document
as a scoped model, validate material claims against current evidence, and update
its status or content when it diverges.

MapStore remains the compact, queryable source for target facts. Each durable
document should include a MapStore reference where one exists; its corresponding
MapStore observation should point back to the document with a relative `docs/`
path.
"""


def render_document(*, title: str, topic: str, status: str, body: str, sources: list[str], mapstore_refs: list[str]) -> str:
    source_lines = "\n".join(f"  - {source}" for source in sources) or "  - none recorded"
    mapstore_lines = "\n".join(f"  - {ref}" for ref in mapstore_refs) or "  - none yet"
    body = body.strip()
    return f"""---
title: {title.strip()}
topic: {topic}
status: {status}
last_verified: {iso_now()}
sources:
{source_lines}
mapstore_refs:
{mapstore_lines}
---

# {title.strip()}

## Scope
This is a program-specific working model for `{topic}`. It is not a complete
provider reference and is not proof that unobserved flows behave the same way.

## Model
{body}

## Recognition signals
- Add concrete SDK names, endpoint prefixes, headers, object names, UI flows, or
  code signals that tell a future agent this document is relevant.

## Security-relevant questions
- Add the next bounded questions that this model makes cheaper to test.

## Limits and freshness
- Status: `{status}`.
- Revalidate material behavior when the integration, version, role, or flow changes.
- Sources are provenance and hypothesis input; current target evidence controls.

## Links
### Program documentation
{source_lines}

### MapStore
{mapstore_lines}
"""


def parse_frontmatter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}
    fields: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if ":" in line and not line.startswith((" ", "-")):
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
    return fields


def document_summary(path: Path, root: Path) -> dict[str, str]:
    fields = parse_frontmatter(path)
    text = path.read_text(encoding="utf-8")
    return {
        "topic": str(path.relative_to(root)).removesuffix(".md"),
        "title": fields.get("title", path.stem.replace("-", " ")),
        "status": fields.get("status", "unknown"),
        "path": str(path),
        "search_text": text.lower(),
    }


def search(root: Path, query: str) -> list[dict[str, str]]:
    terms = [term.lower() for term in query.split() if term.strip()]
    results = []
    for path in sorted(root.rglob("*.md")):
        if path.name == README_NAME:
            continue
        summary = document_summary(path, root)
        if all(term in summary["search_text"] for term in terms):
            results.append(summary)
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    def common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--program", required=True)
        command.add_argument("--family", default="web_bounty")
        command.add_argument("--lane", default="web")
        command.add_argument("--root", default=None)

    init = sub.add_parser("init", help="Create the program docs directory and README")
    common(init)

    write = sub.add_parser("write", help="Create a structured program documentation entry")
    common(write)
    write.add_argument("--topic", required=True, help="Relative docs topic, e.g. integrations/poster-sdk")
    write.add_argument("--title", required=True)
    write.add_argument("--status", default="observed", choices=sorted(VALID_STATUSES))
    body = write.add_mutually_exclusive_group(required=True)
    body.add_argument("--body")
    body.add_argument("--body-file")
    body.add_argument("--body-stdin", action="store_true")
    write.add_argument("--source", action="append", default=[], help="Source/program documentation URL or sanitized artifact path; repeatable or comma-separated")
    write.add_argument("--mapstore-ref", action="append", default=[], help="Relative MapStore observation path; repeatable or comma-separated")
    write.add_argument("--overwrite", action="store_true", help="Replace an existing topic deliberately")

    show = sub.add_parser("show", help="Print one documentation entry")
    common(show)
    show.add_argument("--topic", required=True)

    find = sub.add_parser("search", help="Search program documentation by concrete terms")
    common(find)
    find.add_argument("--query", required=True)
    find.add_argument("--limit", type=int, default=10)
    find.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = docs_root(program=args.program, family=args.family, lane=args.lane, root=args.root)
    if args.command == "init":
        root.mkdir(parents=True, exist_ok=True)
        readme = root / README_NAME
        if not readme.exists():
            readme.write_text(render_readme(), encoding="utf-8")
        print(root)
        return 0

    if args.command == "write":
        root.mkdir(parents=True, exist_ok=True)
        readme = root / README_NAME
        if not readme.exists():
            readme.write_text(render_readme(), encoding="utf-8")
        body = args.body
        if args.body_file:
            body = Path(args.body_file).read_text(encoding="utf-8")
        elif args.body_stdin:
            body = sys.stdin.read()
        if not body or not body.strip():
            raise ValueError("documentation body cannot be empty")
        path = topic_path(root, args.topic)
        if path.exists() and not args.overwrite:
            raise FileExistsError(f"documentation already exists: {path}; use --overwrite to replace it")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            render_document(
                title=args.title,
                topic=safe_topic(args.topic),
                status=args.status,
                body=body,
                sources=split_csv(args.source),
                mapstore_refs=split_csv(args.mapstore_ref),
            ),
            encoding="utf-8",
        )
        print(path)
        print(f"MapStore pointer: docs/{path.relative_to(root)}")
        return 0

    if args.command == "show":
        path = topic_path(root, args.topic)
        if not path.exists():
            raise FileNotFoundError(f"documentation not found: {path}")
        print(path.read_text(encoding="utf-8"), end="")
        return 0

    if args.command == "search":
        if not root.exists():
            print("(no program documentation found)")
            return 0
        results = search(root, args.query)[: args.limit]
        if args.json:
            import json
            print(json.dumps([{key: value for key, value in row.items() if key != "search_text"} for row in results], indent=2))
            return 0
        if not results:
            print("(no matching program documentation found)")
            return 0
        for row in results:
            print(f"{row['topic']} | {row['status']} | {row['title']} | {row['path']}")
        return 0

    raise AssertionError(f"unsupported command: {args.command}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, FileExistsError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
