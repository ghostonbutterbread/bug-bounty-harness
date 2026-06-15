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
from urllib.parse import parse_qsl, urlsplit, urlunsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.storage_resolver import ensure_layout, resolve_storage, write_context_files


VALID_BUCKETS = {"timeline", "hypotheses", "handoffs", "faq"}
VALID_HYPOTHESIS_STATUS = {"untested", "testing", "confirmed", "rejected", "blocked"}
DEFAULT_RUN_ID_PREFIX = "manual"
NOTE_INDEX_DIRNAME = "_index"
NOTE_INDEX_JSON = "notes.json"


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


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        return value
    parse_value = value if "://" in value else f"https://{value}"
    parsed = urlsplit(parse_value)
    host = parsed.netloc.lower()
    path = re.sub(r"/+", "/", parsed.path or "/")
    if path != "/":
        path = path.rstrip("/")
    query_pairs = sorted((key, val) for key, val in parse_qsl(parsed.query, keep_blank_values=True))
    query = "&".join(f"{key}={val}" if val else key for key, val in query_pairs)
    normalized = urlunsplit((parsed.scheme.lower() or "https", host, path, query, ""))
    return normalized


def wikilink_for_note(notes_root: Path, target: str | Path, *, label: str | None = None) -> str:
    target_path = Path(target)
    if target_path.is_absolute():
        try:
            target_path = target_path.relative_to(notes_root)
        except ValueError:
            target_text = str(target)
            return f"[[{target_text}|{label}]]" if label else f"[[{target_text}]]"
    stemmed = target_path.as_posix()
    if stemmed.endswith(".md"):
        stemmed = stemmed[:-3]
    return f"[[{stemmed}|{label}]]" if label else f"[[{stemmed}]]"


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
            "- Last active and lookup indexes: `_index/active.md`\n"
            "- URL lookup: `_index/by-url.md`\n"
            "- Report/FID lookup: `_index/by-report.md`\n"
            "- Tag lookup: `_index/by-tag.md`\n"
            "- Hypotheses: `hypotheses/`\n"
            "- Handoffs: `handoffs/`\n"
            "- Timeline: `timeline/`\n"
            "- FAQ: `faq/`\n"
            "- Working artifacts: `../working/scratch/`\n",
            encoding="utf-8",
        )
    return index_path


def index_paths(layout) -> tuple[Path, Path]:
    index_root = layout.notes_root / NOTE_INDEX_DIRNAME
    index_root.mkdir(parents=True, exist_ok=True)
    return index_root, index_root / NOTE_INDEX_JSON


def read_note_index(layout) -> list[dict]:
    _index_root, index_json = index_paths(layout)
    if not index_json.exists():
        return []
    try:
        data = json.loads(index_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    entries = data.get("notes", []) if isinstance(data, dict) else []
    return [entry for entry in entries if isinstance(entry, dict)]


def write_note_index(layout, entries: list[dict]) -> None:
    index_root, index_json = index_paths(layout)
    entries = sorted(entries, key=lambda item: item.get("updated", ""), reverse=True)
    index_json.write_text(
        json.dumps({"updated": iso_now(), "notes": entries}, indent=2) + "\n",
        encoding="utf-8",
    )
    render_lookup_indexes(layout, index_root, entries)


def render_lookup_indexes(layout, index_root: Path, entries: list[dict]) -> None:
    active = ["# Active Notes\n", "Most recently touched notes.\n"]
    for entry in entries[:50]:
        active.append(f"- {entry.get('updated', '')} {wikilink_for_note(layout.notes_root, entry['path'], label=entry.get('title'))} `{entry.get('bucket')}`")
    (index_root / "active.md").write_text("\n".join(active).rstrip() + "\n", encoding="utf-8")

    by_url: dict[str, list[dict]] = {}
    by_report: dict[str, list[dict]] = {}
    by_tag: dict[str, list[dict]] = {}
    for entry in entries:
        for url in entry.get("urls", []):
            by_url.setdefault(url, []).append(entry)
        for report in entry.get("reports", []):
            by_report.setdefault(report, []).append(entry)
        for tag in entry.get("tags", []):
            by_tag.setdefault(tag, []).append(entry)

    def grouped(title: str, groups: dict[str, list[dict]]) -> str:
        lines = [f"# {title}\n"]
        for key in sorted(groups):
            lines.append(f"## {key}")
            for entry in groups[key]:
                lines.append(f"- {wikilink_for_note(layout.notes_root, entry['path'], label=entry.get('title'))} `{entry.get('bucket')}` {entry.get('updated', '')}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    (index_root / "by-url.md").write_text(grouped("Notes By URL", by_url), encoding="utf-8")
    (index_root / "by-report.md").write_text(grouped("Notes By Report", by_report), encoding="utf-8")
    (index_root / "by-tag.md").write_text(grouped("Notes By Tag", by_tag), encoding="utf-8")
    active_json = entries[0] if entries else {}
    (index_root / "active.json").write_text(json.dumps(active_json, indent=2) + "\n", encoding="utf-8")


def upsert_note_entry(layout, entry: dict) -> None:
    entries = read_note_index(layout)
    entries = [old for old in entries if old.get("path") != entry.get("path")]
    entries.insert(0, entry)
    write_note_index(layout, entries)


def note_entry_from_args(layout, args: argparse.Namespace, note_path: Path, *, bucket: str, title: str) -> dict:
    urls = [normalize_url(url) for url in args.url]
    return {
        "path": note_path.relative_to(layout.notes_root).as_posix(),
        "title": title,
        "bucket": bucket,
        "status": args.status if bucket == "hypotheses" else "",
        "updated": iso_now(),
        "agent": args.agent,
        "run_id": args.run_id,
        "urls": urls,
        "tags": sorted({slugify(tag, fallback="tag") for tag in args.tag}),
        "reports": sorted(set(args.report)),
        "hypotheses": sorted(set(args.hypothesis)),
        "links": sorted(set(args.link)),
        "refs": sorted(set(args.refs)),
    }


def append_index_link(index_path: Path, *, label: str, relative_path: Path) -> None:
    text = index_path.read_text(encoding="utf-8") if index_path.exists() else ""
    line = f"- {label}: `{relative_path.as_posix()}`"
    if line in text:
        return
    if not text.endswith("\n"):
        text += "\n"
    index_path.write_text(text.rstrip() + "\n" + line + "\n", encoding="utf-8")


def note_header(layout, args: argparse.Namespace, *, bucket: str, title: str) -> str:
    lines = [
        f"# {title}",
        "",
        f"Status: {args.status}" if bucket == "hypotheses" else f"Type: {bucket}",
        f"Program: {args.program}",
        f"Family/Lane: {args.family or 'auto'}/{args.lane}",
        f"Agent/Run: {args.agent} / {args.run_id}",
        f"Updated: {iso_now()}",
    ]
    if args.tag:
        lines.append(f"Tags: {' '.join('#' + slugify(tag, fallback='tag') for tag in args.tag)}")
    if args.url:
        lines.extend(["", "## Related URLs"])
        lines.extend(f"- {normalize_url(url)}" for url in args.url)
    if args.report:
        lines.extend(["", "## Related Reports"])
        lines.extend(f"- {report}" for report in args.report)
    if args.hypothesis:
        lines.extend(["", "## Related Hypotheses"])
        lines.extend(f"- {hypothesis}" for hypothesis in args.hypothesis)
    if args.link:
        lines.extend(["", "## Related Notes"])
        lines.extend(f"- {wikilink_for_note(layout.notes_root, link)}" for link in args.link)
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
        metadata = []
        if args.url:
            metadata.append("URLs: " + ", ".join(normalize_url(url) for url in args.url))
        if args.report:
            metadata.append("Reports: " + ", ".join(args.report))
        if args.tag:
            metadata.append("Tags: " + " ".join("#" + slugify(tag, fallback="tag") for tag in args.tag))
        if args.link:
            metadata.append("Links: " + ", ".join(wikilink_for_note(layout.notes_root, link) for link in args.link))
        entry = (
            f"\n## {iso_now()} - {title}\n\n"
            f"Agent/Run: {args.agent} / {args.run_id}\n\n"
            + ("\n".join(metadata) + "\n\n" if metadata else "")
            + f"{body}"
        )
        with note_path.open("a", encoding="utf-8") as fh:
            fh.write(entry)
    else:
        note_path = layout.notes_root / args.bucket / f"{slugify(args.slug or title)}.md"
        note_path.parent.mkdir(parents=True, exist_ok=True)
        note_path.write_text(note_header(layout, args, bucket=args.bucket, title=title) + body, encoding="utf-8")

    append_index_link(index_path, label=title, relative_path=note_path.relative_to(layout.notes_root))
    upsert_note_entry(layout, note_entry_from_args(layout, args, note_path, bucket=args.bucket, title=title))
    print(str(note_path))
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    layout = layout_from_args(args)
    ensure_note_index(layout)
    entries = read_note_index(layout)
    if args.url:
        url_key = normalize_url(args.url)
        entries = [entry for entry in entries if url_key in entry.get("urls", [])]
    if args.tag:
        tag_key = slugify(args.tag, fallback="tag")
        entries = [entry for entry in entries if tag_key in entry.get("tags", [])]
    if args.report:
        entries = [entry for entry in entries if args.report in entry.get("reports", [])]
    if args.bucket:
        entries = [entry for entry in entries if args.bucket == entry.get("bucket")]
    if args.text:
        needle = args.text.lower()
        matches = []
        for entry in entries:
            path = layout.notes_root / entry.get("path", "")
            haystack = json.dumps(entry).lower()
            if path.exists():
                haystack += "\n" + path.read_text(encoding="utf-8", errors="ignore").lower()
            if needle in haystack:
                matches.append(entry)
        entries = matches
    entries = entries[: args.limit]
    if args.json:
        print(json.dumps(entries, indent=2))
    else:
        for entry in entries:
            print(f"{entry.get('updated', '')}\t{entry.get('bucket', '')}\t{entry.get('path', '')}\t{entry.get('title', '')}")
    return 0


def cmd_link(args: argparse.Namespace) -> int:
    layout = layout_from_args(args)
    ensure_note_index(layout)
    source = layout.notes_root / args.source
    if not source.exists():
        raise SystemExit(f"Source note does not exist: {source}")
    backlink = (
        "\n## Linked Context\n\n"
        f"- {args.relationship}: {wikilink_for_note(layout.notes_root, args.target)}\n"
    )
    text = source.read_text(encoding="utf-8")
    if backlink.strip() not in text:
        source.write_text(text.rstrip() + "\n" + backlink, encoding="utf-8")
    entries = read_note_index(layout)
    for entry in entries:
        if entry.get("path") == Path(args.source).as_posix():
            entry.setdefault("links", [])
            if args.target not in entry["links"]:
                entry["links"].append(args.target)
            entry["updated"] = iso_now()
            break
    write_note_index(layout, entries)
    print(str(source))
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
    note.add_argument("--url", action="append", default=[], help="Related URL or endpoint; normalized into notes/_index/by-url.md.")
    note.add_argument("--tag", action="append", default=[], help="Lookup tag, stored as an Obsidian tag and notes/_index/by-tag.md entry.")
    note.add_argument("--report", action="append", default=[], help="Related FID or report path.")
    note.add_argument("--hypothesis", action="append", default=[], help="Related hypothesis id/path.")
    note.add_argument("--link", action="append", default=[], help="Related note path for Obsidian wikilinks.")
    note.set_defaults(func=cmd_note)

    search = sub.add_parser("search", help="Find notes through the machine-readable note index.")
    add_common(search)
    search.add_argument("--url")
    search.add_argument("--tag")
    search.add_argument("--report")
    search.add_argument("--bucket", choices=sorted(VALID_BUCKETS))
    search.add_argument("--text")
    search.add_argument("--limit", type=int, default=20)
    search.add_argument("--json", action="store_true")
    search.set_defaults(func=cmd_search)

    link = sub.add_parser("link", help="Append an Obsidian-style link between notes and refresh the index.")
    add_common(link)
    link.add_argument("--source", required=True, help="Source note path relative to notes/.")
    link.add_argument("--target", required=True, help="Target note/report path.")
    link.add_argument("--relationship", default="related")
    link.set_defaults(func=cmd_link)

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
