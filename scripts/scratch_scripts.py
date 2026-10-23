#!/usr/bin/env python3
"""Create, discover, run, and propose/promote Shared program scratch scripts."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

MARKER = "<!-- generated: bbh-scratch-scripts -->"
SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


def slug(value: str) -> str:
    if not SLUG.fullmatch(value) or value in {".", ".."}:
        raise ValueError("run ID and script name must be simple non-path identifiers")
    return value


def selected_lane(profile: Path) -> Path:
    data = json.loads(profile.read_text(encoding="utf-8"))
    root = Path(data["canonical_root"]).resolve()
    if not root.is_dir() or profile.resolve() != root / "context" / "target_profile.json":
        raise ValueError("profile must be the selected lane's context/target_profile.json")
    for key in ("program", "family", "lane"):
        if not data.get(key):
            raise ValueError(f"profile missing {key}")
    return root


def homes(root: Path) -> tuple[Path, Path]:
    index = root / "scripts"
    records = index / "_scratch_records"
    return index, records


def safe_path(root: Path, path: Path) -> Path:
    """Reject redirected children of the selected lane, including dangling links."""
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"symlink in program script path: {current}")
    if not path.resolve().is_relative_to(root):
        raise ValueError("program script path escapes selected lane")
    return path


@contextmanager
def lane_lock(root: Path):
    directory = safe_path(root, homes(root)[0])
    directory.mkdir(parents=True, exist_ok=True)
    lock = safe_path(root, directory / ".scratch-scripts.lock")
    with lock.open("a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def atomic_text(path: Path, text: str) -> None:
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def record_path(root: Path, run_id: str, name: str) -> Path:
    return safe_path(root, homes(root)[1] / f"{slug(run_id).encode().hex()}-{slug(name).encode().hex()}.json")


def script_path(root: Path, run_id: str, name: str) -> Path:
    return safe_path(root, root / "working" / "_runs" / slug(run_id) / "_scratch" / "scripts" / f"{slug(name)}.py")


def load_records(root: Path) -> list[dict]:
    directory = safe_path(root, homes(root)[1])
    return [json.loads(safe_path(root, p).read_text(encoding="utf-8")) for p in sorted(directory.glob("*.json"))]


def get_record(root: Path, run_id: str, name: str) -> dict:
    path = record_path(root, run_id, name)
    if not path.is_file():
        raise ValueError(f"scratch script not registered: {run_id}/{name}")
    return json.loads(path.read_text(encoding="utf-8"))


def use_count(root: Path, record: dict) -> int:
    return sum(1 for _ in safe_path(root, homes(root)[0] / "_scratch_uses" / record["id"]).glob("*.json"))


def write_managed(path: Path, text: str) -> None:
    check_managed(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_text(path, MARKER + "\n" + text)


def check_managed(path: Path) -> None:
    if path.exists() and (not path.is_file() or not path.read_text(encoding="utf-8").startswith(MARKER)):
        raise ValueError(f"refusing to replace unmanaged index: {path}")


def refresh(root: Path) -> None:
    records = load_records(root)
    lines = ["# Scratch script candidates", "", "Unreviewed candidates; inspect before running. Counts are helper-recorded invocations only.", ""]
    for r in records:
        path = script_path(root, r["run_id"], r["name"])
        available = path.is_file() and not path.is_symlink()
        lines.append(f"- `{r['run_id']}/{r['name']}` — {r['description']} ({r['status']}; {use_count(root, r)} uses; {'available' if available else 'missing'}; `{path.relative_to(root)}`)")
    if not records:
        lines.append("No scratch scripts registered.")
    write_managed(safe_path(root, homes(root)[0] / "SCRATCH.md"), "\n".join(lines) + "\n")


def refresh_run(root: Path, run_id: str) -> None:
    records = [r for r in load_records(root) if r["run_id"] == run_id]
    lines = ["# Run scratch scripts", ""]
    lines.extend(f"- `{r['name']}.py` — {r['description']} (unreviewed; use `bbh scripts/scratch_scripts.py` to discover and record use)." for r in records)
    directory = root / "working" / "_runs" / run_id / "_scratch" / "scripts"
    write_managed(safe_path(root, directory / "README.md"), "\n".join(lines) + "\n")


def create(root: Path, run_id: str, name: str, description: str) -> Path:
    if not description.strip() or "\n" in description or "\r" in description:
        raise ValueError("a single-line description is required")
    path = script_path(root, run_id, name)
    record = record_path(root, run_id, name)
    if os.path.lexists(path) or os.path.lexists(record):
        raise ValueError("script or record already exists; edit the original rather than recreating it")
    check_managed(safe_path(root, homes(root)[0] / "SCRATCH.md"))
    check_managed(safe_path(root, path.parent / "README.md"))
    path.parent.mkdir(parents=True, exist_ok=True)
    record.parent.mkdir(parents=True, exist_ok=True)
    created_path = False
    created_record = False
    try:
        with path.open("x", encoding="utf-8") as out:
            created_path = True
            out.write("#!/usr/bin/env python3\n# " + description.strip() + "\n\nraise SystemExit('Implement this scratch script before use')\n")
        entry = {"id": uuid.uuid4().hex, "run_id": run_id, "name": name, "description": description.strip(), "status": "scratch", "created_at": datetime.now(timezone.utc).isoformat()}
        with record.open("x", encoding="utf-8") as out:
            created_record = True
            json.dump(entry, out, sort_keys=True)
            out.write("\n")
        refresh_run(root, run_id)
        refresh(root)
    except Exception:
        if created_record:
            record.unlink(missing_ok=True)
        if created_path:
            path.unlink(missing_ok=True)
        raise
    return path


def describe(root: Path, run_id: str, name: str, description: str) -> None:
    if not description.strip() or "\n" in description or "\r" in description:
        raise ValueError("a single-line description is required")
    record = get_record(root, run_id, name)
    record["description"] = description.strip()
    atomic_text(record_path(root, run_id, name), json.dumps(record, sort_keys=True) + "\n")
    refresh_run(root, run_id)
    refresh(root)


def run(root: Path, run_id: str, name: str, args: list[str]) -> int:
    record = get_record(root, run_id, name)
    path = script_path(root, run_id, name)
    if not path.is_file():
        raise ValueError("registered scratch script is missing or not a regular file in its run")
    command = [sys.executable, str(path), *(args[1:] if args and args[0] == "--" else args)]
    try:
        result = subprocess.run(command, check=False)
        returncode = result.returncode
    except OSError as exc:
        print(f"scratch script launch failed: {exc}", file=sys.stderr)
        returncode = 127
    with lane_lock(root):
        events = safe_path(root, homes(root)[0] / "_scratch_uses" / record["id"])
        events.mkdir(parents=True, exist_ok=True)
        (events / f"{uuid.uuid4().hex}.json").write_text(json.dumps({"at": datetime.now(timezone.utc).isoformat(), "run_id": run_id, "returncode": returncode}) + "\n", encoding="utf-8")
        refresh(root)
    return returncode


def promote(root: Path, run_id: str, name: str, destination: str, review_ref: str | None, verification: str | None) -> str:
    record = get_record(root, run_id, name)
    path = script_path(root, run_id, name)
    if not path.is_file() or path.is_symlink():
        raise ValueError("registered scratch script is unavailable")
    if destination == "bbh":
        proposal = safe_path(root, path.parent / f"{name}-promotion.md")
        if os.path.lexists(proposal):
            raise ValueError("BBH proposal already exists")
        with proposal.open("x", encoding="utf-8") as out:
            out.write(f"# BBH script proposal\n\nSource: `{path.relative_to(root)}`\nPurpose: {record['description']}\n\nCheck existing owner and choose a class module, skill script, or standalone category through SCRIPT_POLICY.md. Add fixture, review, and integrate on a feature branch; this proposal does not publish code.\n")
        return f"BBH proposal: {proposal}"
    if not review_ref or not verification or any(x in value for value in (review_ref, verification) for x in ("\n", "\r")):
        raise ValueError("program promotion requires --review-ref and --verification")
    target = safe_path(root, homes(root)[0] / path.name)
    if os.path.lexists(target):
        raise ValueError("maintained program script already exists")
    index = safe_path(root, homes(root)[0] / "README.md")
    if index.exists() and not index.is_file():
        raise ValueError(f"program script index is not a file: {index}")
    check_managed(safe_path(root, homes(root)[0] / "SCRATCH.md"))
    source_bytes = path.read_bytes()
    digest = hashlib.sha256(source_bytes).hexdigest()
    entry = (
        f"\n## `{name}.py`\n\n"
        f"- **Purpose:** {record['description']}\n"
        f"- **Inputs:** See script help/source; review required before supplying target data.\n"
        f"- **Outputs:** See script help/source; caller selects output location.\n"
        f"- **Mutates:** Program-local script; inspect source and invocation before use.\n"
        f"- **Invocation:** `python3 <resolved-program-lane>/scripts/{name}.py --help`\n"
        f"- **Verification:** {verification} (operator-supplied)\n"
        f"- **Owner/scope:** Selected program lane only; review reference: {review_ref} (operator-supplied).\n"
        f"- **Last verified:** {datetime.now(timezone.utc).date()} (operator-supplied receipt).\n"
        f"- **Coverage:** Unknown until reviewed against actual inputs; not exhaustive.\n"
        f"- **sha256:** `{digest}`\n"
    )
    current = index.read_text(encoding="utf-8") if index.exists() else "# Maintained program scripts\n"
    with target.open("xb") as out:
        out.write(source_bytes)
    try:
        atomic_text(index, current.rstrip() + "\n" + entry)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    record.update(status="promoted", review_ref=review_ref, verification=verification, sha256=digest)
    atomic_text(record_path(root, run_id, name), json.dumps(record, sort_keys=True) + "\n")
    refresh(root)
    return f"Promoted to {target}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path, help="Selected program lane context/target_profile.json")
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create", help="Create a run scratch script and index it")
    create_parser.add_argument("--run-id", required=True)
    create_parser.add_argument("--name", required=True)
    create_parser.add_argument("--description", required=True)
    describe_parser = commands.add_parser("describe", help="Update a registered script description and indexes")
    describe_parser.add_argument("--run-id", required=True)
    describe_parser.add_argument("--name", required=True)
    describe_parser.add_argument("--description", required=True)
    commands.add_parser("list", help="List indexed scratch scripts and recorded uses")
    run_parser = commands.add_parser("run", help="Run a registered script and record this invocation")
    run_parser.add_argument("--run-id", required=True)
    run_parser.add_argument("--name", required=True)
    run_parser.add_argument("args", nargs=argparse.REMAINDER)
    promote_parser = commands.add_parser("promote", help="Promote to program index or prepare BBH proposal")
    promote_parser.add_argument("--run-id", required=True)
    promote_parser.add_argument("--name", required=True)
    promote_parser.add_argument("--to", choices=("program", "bbh"), required=True)
    promote_parser.add_argument("--review-ref")
    promote_parser.add_argument("--verification")
    args = parser.parse_args(argv)
    try:
        root = selected_lane(args.profile)
        if args.command == "run":
            return run(root, slug(args.run_id), slug(args.name), args.args)
        with lane_lock(root):
            if args.command == "create":
                print(create(root, slug(args.run_id), slug(args.name), args.description))
            elif args.command == "describe":
                describe(root, slug(args.run_id), slug(args.name), args.description)
                print("Description and indexes updated")
            elif args.command == "list":
                refresh(root)
                print(safe_path(root, homes(root)[0] / "SCRATCH.md").read_text(encoding="utf-8"), end="")
            else:
                print(promote(root, slug(args.run_id), slug(args.name), args.to, args.review_ref, args.verification))
        return 0
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        print(f"scratch-scripts: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
