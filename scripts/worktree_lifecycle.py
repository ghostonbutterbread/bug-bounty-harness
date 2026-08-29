#!/usr/bin/env python3
"""Create, audit, and safely retire BBH feature worktrees.

Git remains authoritative for worktree attachment, dirtiness, containment, patch
identity, and commit age.  A branch-local docs/integrations dossier is the only
human handoff record.
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOSSIER_DIR = "docs/integrations"
MARKER = "lifecycle: bbh-worktree/v1"


def run(*args: str, cwd: Path = ROOT, check: bool = True) -> str:
    completed = subprocess.run([*args], cwd=cwd, text=True, capture_output=True)
    if check and completed.returncode:
        raise RuntimeError(completed.stderr.strip() or " ".join(args))
    return completed.stdout.strip()


def worktrees() -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for block in run("git", "worktree", "list", "--porcelain").split("\n\n"):
        record = dict(line.split(" ", 1) if " " in line else (line, "") for line in block.splitlines() if line)
        if "worktree" not in record:
            continue
        path = Path(record["worktree"])
        branch = run("git", "branch", "--show-current", cwd=path, check=False)
        records.append({"path": str(path), "branch": branch, "head": record.get("HEAD", "")})
    return records


def frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}
    return {
        key.strip(): value.strip()
        for line in text[4:end].splitlines()
        if ":" in line
        for key, value in [line.split(":", 1)]
    }


def dossier(branch: str) -> tuple[str, dict[str, str]] | None:
    paths = run("git", "ls-tree", "-r", "--name-only", branch, "--", DOSSIER_DIR, check=False).splitlines()
    found: list[tuple[str, dict[str, str]]] = []
    for path in paths:
        text = run("git", "show", f"{branch}:{path}", check=False)
        meta = {key.strip(): value.strip() for key, value in frontmatter(text).items()}
        if meta.get("lifecycle") == "bbh-worktree/v1":
            found.append((path, meta))
    return found[0] if len(found) == 1 else None


def has_unique(target: str, branch: str) -> bool:
    return any(line.startswith("+") for line in run("git", "cherry", target, branch, check=False).splitlines())


def is_ancestor(ancestor: str, descendant: str) -> bool:
    return subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant], cwd=ROOT, capture_output=True
    ).returncode == 0


def classify(record: dict[str, str], target: str, max_age_days: int) -> tuple[str, str]:
    branch, path = record["branch"], Path(record["path"])
    if not branch or branch in {target, "main", "master"}:
        return "lane", "integration or stable lane"
    dirty = bool(run("git", "status", "--porcelain", cwd=path, check=False))
    item = dossier(branch)
    if not item:
        return "dirty" if dirty else "missing-dossier", "legacy or untracked lifecycle"
    _, meta = item
    if meta.get("branch") != branch or meta.get("target", target) != target:
        return "dirty" if dirty else "missing-dossier", "dossier branch/target mismatch"
    if dirty:
        return "dirty", "never auto-remove"
    if is_ancestor(branch, target):
        return "merged-cleanup", "contained in target"
    if not has_unique(target, branch):
        return "patch-equivalent-cleanup", "no unique patch relative to target"
    stamp = int(run("git", "log", "-1", "--format=%ct", branch))
    age = (dt.datetime.now(dt.timezone.utc).timestamp() - stamp) / 86400
    if age > max_age_days:
        return "stale-unmerged", f"{age:.1f} days since checkpoint"
    return "active", "unique work with current dossier"


def cmd_audit(args: argparse.Namespace) -> int:
    failures = False
    for record in worktrees():
        if args.branch and record["branch"] != args.branch:
            continue
        state, detail = classify(record, args.target, args.max_age_days)
        print(f"{state}\t{record['branch'] or '(detached)'}\t{record['path']}\t{detail}")
        failures |= state in {"missing-dossier", "stale-unmerged"}
    return 1 if args.strict and failures else 0


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def cmd_open(args: argparse.Namespace) -> int:
    if run("git", "status", "--porcelain"):
        raise RuntimeError("integration checkout must be clean")
    run("git", "fetch", "origin", args.target)
    base = run("git", "rev-parse", f"origin/{args.target}")
    if run("git", "show-ref", "--verify", f"refs/heads/{args.branch}", check=False):
        raise RuntimeError(f"branch already exists: {args.branch}")
    path = Path(args.path).expanduser().resolve()
    run("git", "worktree", "add", "-b", args.branch, str(path), base)
    dossier_path = path / DOSSIER_DIR / f"{slug(args.task)}.md"
    dossier_path.parent.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    dossier_path.write_text(f"---\nlifecycle: bbh-worktree/v1\ntask: {args.task}\nbranch: {args.branch}\nworktree: {path}\nbase: {base}\ntarget: {args.target}\nstatus: active\nopened_at: {now}\ncheckpoint: initial-dossier\n---\n\n# {args.task}\n\nRecord implementation, tests, blockers, and the exact resume point here.\n")
    run("git", "add", str(dossier_path.relative_to(path)), cwd=path)
    run("git", "commit", "-m", f"docs: checkpoint {args.task}", cwd=path)
    print(path)
    return 0


def cmd_retire(args: argparse.Namespace) -> int:
    matches = [item for item in worktrees() if item["branch"] == args.branch]
    if len(matches) != 1:
        raise RuntimeError("branch must have exactly one attached worktree")
    record = matches[0]
    state, detail = classify(record, args.target, args.max_age_days)
    if state not in {"merged-cleanup", "patch-equivalent-cleanup"}:
        raise RuntimeError(f"refusing retirement: {state} ({detail})")
    run("git", "worktree", "remove", record["path"])
    run("git", "branch", "-d", args.branch)
    print(f"retired {args.branch}: {state}")
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--target", default="beta")
    common.add_argument("--max-age-days", type=int, default=7)
    audit = sub.add_parser("audit", parents=[common]); audit.add_argument("--strict", action="store_true"); audit.add_argument("--branch"); audit.set_defaults(func=cmd_audit)
    open_p = sub.add_parser("open", parents=[common]); open_p.add_argument("--task", required=True); open_p.add_argument("--branch", required=True); open_p.add_argument("--path", required=True); open_p.set_defaults(func=cmd_open)
    retire = sub.add_parser("retire", parents=[common]); retire.add_argument("branch"); retire.set_defaults(func=cmd_retire)
    return p


def main() -> int:
    try:
        args = parser().parse_args()
        return args.func(args)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
