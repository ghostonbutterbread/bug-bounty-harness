#!/usr/bin/env python3
"""Write bug bounty notes into the canonical lane layout."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.storage_resolver import ensure_layout, resolve_storage, write_context_files


VALID_BUCKETS = {"timeline", "hypotheses", "handoffs", "faq"}
VALID_HYPOTHESIS_STATUS = {"untested", "testing", "confirmed", "rejected", "blocked"}
DEFAULT_RUN_ID_PREFIX = "manual"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def today_slug() -> str:
    return utc_now().strftime("%Y-%m-%d")


def slugify(value: str, *, fallback: str = "note") -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = value.strip("-")
    return value or fallback


def default_run_id(agent: str) -> str:
    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{slugify(agent, fallback=DEFAULT_RUN_ID_PREFIX)}"


def read_body(args: argparse.Namespace) -> str:
    parts: list[str] = []
    if args.body:
        parts.append(args.body.strip())
    if args.body_file:
        parts.append(Path(args.body_file).read_text(encoding="utf-8").strip())
    if not parts:
        raise SystemExit("Provide --body or --body-file.")
    return "\n\n".join(part for part in parts if part).rstrip() + "\n"


def layout_from_args(args: argparse.Namespace):
    layout = resolve_storage(
        args.program,
        family=args.family,
        lane=args.lane,
        root_override=args.root,
        create=True,
    )
    ensure_layout(layout)
    return layout


def ensure_note_index(layout) -> Path:
    index_path = layout.notes_root / "index.md"
    if not index_path.exists():
        index_path.write_text(
            f"# {layout.program} Notes\n\n"
            f"Program: {layout.program}\n"
            f"Family/Lane: {layout.family}/{layout.lane}\n"
            f"Last updated: {iso_now()}\n\n"
            "## Start Here\n"
            "- Hypotheses: `hypotheses/`\n"
            "- Handoffs: `handoffs/`\n"
            "- Timeline: `timeline/`\n"
            "- FAQ: `faq/`\n"
            "- Working artifacts: `../working/scratch/`\n",
            encoding="utf-8",
        )
    return index_path


def append_index_link(index_path: Path, *, label: str, relative_path: Path) -> None:
    text = index_path.read_text(encoding="utf-8") if index_path.exists() else ""
    line = f"- {label}: `{relative_path.as_posix()}`"
    if line in text:
        return
    if not text.endswith("\n"):
        text += "\n"
    index_path.write_text(text.rstrip() + "\n" + line + "\n", encoding="utf-8")


def note_header(args: argparse.Namespace, *, bucket: str, title: str) -> str:
    lines = [
        f"# {title}",
        "",
        f"Status: {args.status}" if bucket == "hypotheses" else f"Type: {bucket}",
        f"Program: {args.program}",
        f"Family/Lane: {args.family or 'auto'}/{args.lane}",
        f"Agent/Run: {args.agent} / {args.run_id}",
        f"Updated: {iso_now()}",
    ]
    if args.refs:
        lines.extend(["", "## References"])
        lines.extend(f"- {ref}" for ref in args.refs)
    return "\n".join(lines).rstrip() + "\n\n"


def cmd_init(args: argparse.Namespace) -> int:
    layout = layout_from_args(args)
    write_context_files(layout, overwrite_handoff=False)
    ensure_note_index(layout)
    for bucket in VALID_BUCKETS:
        (layout.notes_root / bucket).mkdir(parents=True, exist_ok=True)
    scratch = layout.working_root / "scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    print(json.dumps({"notes_root": str(layout.notes_root), "scratch_root": str(scratch)}, indent=2))
    return 0


def cmd_note(args: argparse.Namespace) -> int:
    if args.bucket not in VALID_BUCKETS:
        raise SystemExit(f"Invalid bucket: {args.bucket}")
    if args.bucket == "hypotheses" and args.status not in VALID_HYPOTHESIS_STATUS:
        raise SystemExit(f"Invalid hypothesis status: {args.status}")
    if not args.run_id:
        args.run_id = default_run_id(args.agent)

    layout = layout_from_args(args)
    index_path = ensure_note_index(layout)
    title = args.title.strip()
    body = read_body(args)

    if args.bucket == "timeline":
        note_path = layout.notes_root / "timeline" / f"{today_slug()}.md"
        note_path.parent.mkdir(parents=True, exist_ok=True)
        entry = (
            f"\n## {iso_now()} - {title}\n\n"
            f"Agent/Run: {args.agent} / {args.run_id}\n\n"
            f"{body}"
        )
        with note_path.open("a", encoding="utf-8") as fh:
            fh.write(entry)
    else:
        note_path = layout.notes_root / args.bucket / f"{slugify(args.slug or title)}.md"
        note_path.parent.mkdir(parents=True, exist_ok=True)
        note_path.write_text(note_header(args, bucket=args.bucket, title=title) + body, encoding="utf-8")

    append_index_link(index_path, label=title, relative_path=note_path.relative_to(layout.notes_root))
    print(str(note_path))
    return 0


def cmd_artifact(args: argparse.Namespace) -> int:
    run_id = args.run_id or default_run_id(args.agent)
    layout = layout_from_args(args)
    ensure_note_index(layout)
    run_root = layout.working_root / "scratch" / run_id
    artifacts_root = run_root / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)

    copied: list[str] = []
    for src_text in args.source:
        src = Path(src_text).expanduser().resolve()
        if not src.exists():
            raise SystemExit(f"Artifact source does not exist: {src}")
        dst = artifacts_root / src.name
        if src.is_dir():
            if dst.exists():
                raise SystemExit(f"Destination already exists: {dst}")
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
        copied.append(str(dst))

    manifest = {
        "program": layout.program,
        "family": layout.family,
        "lane": layout.lane,
        "agent": args.agent,
        "run_id": run_id,
        "created": iso_now(),
        "artifact_note": args.note,
        "artifacts": copied,
        "safety": "Do not paste secrets or raw proxy dumps into notes. Keep sensitive material local and referenced only by sanitized summaries.",
    }
    (run_root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    readme = run_root / "README.md"
    if not readme.exists():
        readme.write_text(
            f"# Scratch Run {run_id}\n\n"
            f"Program: {layout.program}\n"
            f"Family/Lane: {layout.family}/{layout.lane}\n"
            f"Agent: {args.agent}\n"
            f"Created: {manifest['created']}\n\n"
            "## Artifacts\n"
            + "\n".join(f"- `{Path(path).relative_to(run_root).as_posix()}`" for path in copied)
            + "\n\n## Promotion\n"
            "Summarize durable knowledge into `notes/`; do not leave useful learning only in scratch.\n",
            encoding="utf-8",
        )
    print(str(run_root))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("program")
        p.add_argument("--family", default=None, help="Storage family, e.g. web_bounty or binaries.")
        p.add_argument("--lane", default="web", help="Storage lane, e.g. web, api, apk, exe.")
        p.add_argument("--root", default=None, help="Override shared storage root for tests or special lanes.")

    init = sub.add_parser("init", help="Create canonical note directories for a program/lane.")
    add_common(init)
    init.set_defaults(func=cmd_init)

    note = sub.add_parser("note", help="Write a durable note into a canonical bucket.")
    add_common(note)
    note.add_argument("--bucket", required=True, choices=sorted(VALID_BUCKETS))
    note.add_argument("--title", required=True)
    note.add_argument("--slug")
    note.add_argument("--status", default="untested")
    note.add_argument("--agent", default="ghost")
    note.add_argument("--run-id", default=None)
    note.add_argument("--body")
    note.add_argument("--body-file")
    note.add_argument("--refs", action="append", default=[])
    note.set_defaults(func=cmd_note)

    artifact = sub.add_parser("artifact", help="Copy generated artifacts into working/scratch/<run-id>.")
    add_common(artifact)
    artifact.add_argument("--source", action="append", required=True)
    artifact.add_argument("--agent", default="ghost")
    artifact.add_argument("--run-id", default=None)
    artifact.add_argument("--note", default="")
    artifact.set_defaults(func=cmd_artifact)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
