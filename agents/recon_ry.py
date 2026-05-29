"""Wrapper and ingest helper for Ryushe's recon-ry tool."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

_AGENT_DIR = Path(__file__).resolve().parent
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

from bounty_core_bootstrap import ensure_bounty_core_importable

ensure_bounty_core_importable("bounty_core.recon")

from bounty_core.recon import start_run, write_manifest

from scope_validator import OutOfScopeError, ScopeValidator
from scope_seed_files import clean_scope_value, recon_seed_lines


DEFAULT_REMOTE = "ryushe@hoster"
DEFAULT_SSH_KEY = Path.home() / ".ssh" / "hoster"
TOP_LEVEL_ARTIFACTS = (
    "alive.txt",
    "url.txt",
    "urls.txt",
    "wild.txt",
    "params_raw.txt",
    "params.txt",
    "jsfiles.txt",
    "secrets.txt",
    "dorks.txt",
    "rate_limit.conf",
)
DIR_ARTIFACTS = ("dirs_status", "history", "eyewitness")


def safe_slug(value: str, *, default: str = "target") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip()).strip("._-")
    return cleaned or default


def line_count(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        return sum(1 for line in handle if line.strip())


def copy_if_present(source: Path, destination: Path, copied: list[Path]) -> None:
    if not source.exists():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(source, destination, symlinks=False)
    else:
        shutil.copy2(source, destination)
    copied.append(destination)


def copy_recon_outputs(source_dir: Path, raw_dir: Path, parsed_dir: Path) -> tuple[list[Path], list[Path]]:
    raw_files: list[Path] = []
    parsed_files: list[Path] = []

    for name in TOP_LEVEL_ARTIFACTS:
        copy_if_present(source_dir / name, raw_dir / name, raw_files)
        copy_if_present(source_dir / name, parsed_dir / name, parsed_files)

    for name in DIR_ARTIFACTS:
        copy_if_present(source_dir / name, raw_dir / name, raw_files)

    return raw_files, parsed_files


def build_counts(parsed_dir: Path) -> dict[str, int]:
    counts = {
        "raw_records": 0,
        "parsed_records": 0,
        "promotion_candidates": 0,
        "promoted_findings": 0,
        "alive_urls": line_count(parsed_dir / "alive.txt"),
        "seed_urls": line_count(parsed_dir / "urls.txt"),
        "params": line_count(parsed_dir / "params.txt"),
        "raw_params": line_count(parsed_dir / "params_raw.txt"),
        "js_files": line_count(parsed_dir / "jsfiles.txt"),
        "secrets": line_count(parsed_dir / "secrets.txt"),
        "dorks": line_count(parsed_dir / "dorks.txt"),
    }
    counts["parsed_records"] = sum(
        counts[key]
        for key in ("alive_urls", "seed_urls", "params", "raw_params", "js_files", "secrets", "dorks")
    )
    counts["raw_records"] = counts["parsed_records"]
    return counts


def is_remote_source(source: str) -> bool:
    return ":" in source and not source.startswith("/") and not source.startswith("./")


def fetch_remote_source(source: str, destination: Path, ssh_key: Path | None = None) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    ssh_key_args = ["-i", str(ssh_key)] if ssh_key else []
    if shutil.which("rsync"):
        ssh = "ssh " + " ".join(ssh_key_args) if ssh_key_args else "ssh"
        subprocess.run(["rsync", "-a", "-e", ssh, source.rstrip("/") + "/", str(destination) + "/"], check=True)
        return
    subprocess.run(["scp", "-r", *ssh_key_args, source.rstrip("/"), str(destination)], check=True)


def ingest(args: argparse.Namespace) -> Path:
    source = str(args.source)
    source_label = source
    temp_remote_dir: Path | None = None

    if is_remote_source(source):
        temp_remote_dir = Path(args.work_dir).expanduser() / f"recon_ry_fetch_{safe_slug(args.program)}"
        if temp_remote_dir.exists():
            shutil.rmtree(temp_remote_dir)
        fetch_remote_source(source, temp_remote_dir, Path(args.ssh_key).expanduser() if args.ssh_key else None)
        source_dir = temp_remote_dir
    else:
        source_dir = Path(source).expanduser().resolve(strict=True)

    if not source_dir.is_dir():
        raise NotADirectoryError(f"source is not a directory: {source_dir}")

    target = args.target or Path(source.rstrip("/")).name or args.program
    run = start_run(
        tool="recon-ry",
        target=safe_slug(target),
        program=args.program,
        family=args.family,
        lane=args.lane,
        root_override=args.root,
    )
    run.command_path.write_text(
        f"ingest source={source_label}\n",
        encoding="utf-8",
    )
    run.stdout_path.write_text("", encoding="utf-8")
    run.stderr_path.write_text("", encoding="utf-8")
    (run.raw_dir / "source_path.txt").write_text(source_label + "\n", encoding="utf-8")

    raw_files, parsed_files = copy_recon_outputs(source_dir, run.raw_dir, run.parsed_dir)
    manifest = {
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "exit_code": 0,
        "source": source_label,
        "mode": "ingest",
        "raw_files": [str(path) for path in raw_files],
        "parsed_files": [str(path) for path in parsed_files],
        "counts": build_counts(run.parsed_dir),
        "promoted_finding_ids": [],
        "promotion_policy": "No automatic ledger promotion. Recon artifacts are stored for later review.",
    }
    manifest_path = write_manifest(run, manifest)

    if temp_remote_dir and not args.keep_fetched:
        shutil.rmtree(temp_remote_dir, ignore_errors=True)
    return manifest_path


def ssh_command(remote: str, ssh_key: Path | None, command: str) -> list[str]:
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if ssh_key:
        cmd.extend(["-i", str(ssh_key)])
    cmd.extend([remote, command])
    return cmd


def validate_start_scope(program: str, url: str, *, allow_unscoped: bool = False) -> None:
    validator = ScopeValidator(program=program, strict=True)
    if validator.is_empty():
        if allow_unscoped:
            return
        raise SystemExit(
            f"No saved scope is loaded for {program!r}. Run /pullscope first or pass "
            "--allow-unscoped only after Ryushe explicitly approves this target."
        )
    try:
        validator.validate_or_fail(url)
    except OutOfScopeError as exc:
        raise SystemExit(str(exc)) from exc


def build_remote_seed_files(program: str, seed_url: str, *, allow_unscoped: bool = False) -> dict[str, str]:
    """Build recon-ry project seed files from saved scope plus the requested seed URL."""
    domains: list[str] = []
    urls: list[str] = [seed_url]
    try:
        validator = ScopeValidator(program=program, strict=True)
    except Exception:
        validator = None
    if validator and not validator.is_empty():
        for entry in getattr(validator, "_entries", []):
            raw = clean_scope_value(getattr(entry, "raw", ""))
            if not raw:
                continue
            if getattr(entry, "entry_type", "") == "url_pattern" or raw.startswith(("http://", "https://")):
                urls.append(raw)
            else:
                domains.append(raw)
    elif not allow_unscoped:
        validate_start_scope(program, seed_url, allow_unscoped=allow_unscoped)

    url_lines, wild_lines = recon_seed_lines(domains, urls)
    return {
        "urls.txt": "\n".join(url_lines) + ("\n" if url_lines else ""),
        "url.txt": "\n".join(url_lines) + ("\n" if url_lines else ""),
        "wild.txt": "\n".join(wild_lines) + ("\n" if wild_lines else ""),
    }


def rate_limit_conf_body(rate_limit_rps: float, timeout: int) -> str:
    rate = max(float(rate_limit_rps), 0.1)
    timeout = max(int(timeout), 0)
    lines = [
        "# rate_limit.conf - generated by Ghost recon-ry wrapper",
        f"# Values are requests per second. Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')}",
        f"timeout={timeout}",
        "",
        f"default={rate:g}",
        "",
    ]
    for tool in [
        "subfinder",
        "assetfinder",
        "amass",
        "katana",
        "hakrawler",
        "waybackurls",
        "gau",
        "httpx",
        "nuclei",
        "ffuf",
    ]:
        lines.append(f"{tool}={rate:g}")
    return "\n".join(lines) + "\n"


def start_remote(args: argparse.Namespace) -> None:
    validate_start_scope(args.program, args.url, allow_unscoped=args.allow_unscoped)
    project_dir = args.remote_project or f"/home/ryushe/bounties/{safe_slug(args.program)}"
    profile_flag = f"--{args.profile}" if args.profile in {"full", "subs", "fast", "urls", "params", "dork", "dir"} else f"--profile {args.profile}"
    url_part = f" --url {shell_quote(args.url)}" if args.url else ""
    verbose = " -vv" if args.very_verbose else " -v"
    rate_conf = rate_limit_conf_body(args.rate_limit_rps, args.timeout)
    seed_files = build_remote_seed_files(args.program, args.url, allow_unscoped=args.allow_unscoped)
    seed_file_cmds = ""
    for filename, body in seed_files.items():
        marker = f"RECONRY_{filename.upper().replace('.', '_')}"
        seed_file_cmds += (
            f"cat > {shell_quote(project_dir + '/' + filename)} <<'{marker}'\n"
            f"{body}"
            f"{marker}\n"
        )
    remote_cmd = (
        "set -eu; "
        "mkdir -p \"$HOME/bounties\" \"$HOME/recon-ry-logs\"; "
        f"mkdir -p {shell_quote(project_dir)}; "
        f"{seed_file_cmds}"
        f"cat > {shell_quote(project_dir + '/rate_limit.conf')} <<'RECONRY_RATE_LIMIT'\n"
        f"{rate_conf}"
        "RECONRY_RATE_LIMIT\n"
        f"log=\"$HOME/recon-ry-logs/{safe_slug(args.program)}-$(date -u +%Y%m%dT%H%M%SZ).log\"; "
        f"nohup \"$HOME/bin/recon-ry\" recon {profile_flag} --project {shell_quote(project_dir)}{url_part}{verbose} "
        "> \"$log\" 2>&1 & "
        "printf 'pid=%s\\nlog=%s\\nproject=%s\\n' \"$!\" \"$log\" "
        f"{shell_quote(project_dir)}"
    )
    if args.dry_run:
        print(remote_cmd)
        return
    subprocess.run(ssh_command(args.remote, Path(args.ssh_key).expanduser() if args.ssh_key else None, remote_cmd), check=True)


def status_remote(args: argparse.Namespace) -> None:
    remote_cmd = (
        "set -eu; "
        "printf 'processes:\\n'; "
        "pgrep -af 'main.sh recon|recon-ry recon' | grep -v 'pgrep -af' || true; "
        "printf '\\nrecent logs:\\n'; "
        "ls -1t \"$HOME/recon-ry-logs\" 2>/dev/null | sed -n '1,10p' || true"
    )
    subprocess.run(ssh_command(args.remote, Path(args.ssh_key).expanduser() if args.ssh_key else None, remote_cmd), check=True)


def shell_quote(value: str) -> str:
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run or ingest recon-ry artifacts.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    start_parser = subparsers.add_parser("start", help="Start recon-ry on Hoster and return immediately.")
    start_parser.add_argument("program")
    start_parser.add_argument("--url", required=True, help="Scoped seed URL or domain.")
    start_parser.add_argument("--profile", default="full")
    start_parser.add_argument("--remote-project")
    start_parser.add_argument("--remote", default=DEFAULT_REMOTE)
    start_parser.add_argument("--ssh-key", default=str(DEFAULT_SSH_KEY))
    start_parser.add_argument("--rate-limit-rps", type=float, default=2.0, help="Project-local recon-ry rate limit written before start.")
    start_parser.add_argument("--timeout", type=int, default=300, help="Per-tool timeout written to rate_limit.conf.")
    start_parser.add_argument("--allow-unscoped", action="store_true", help="Bypass saved-scope fail-closed check after explicit approval.")
    start_parser.add_argument("--very-verbose", action="store_true")
    start_parser.add_argument("--dry-run", action="store_true")
    start_parser.set_defaults(func=start_remote)

    ingest_parser = subparsers.add_parser("ingest", help="Import a completed recon-ry project directory.")
    ingest_parser.add_argument("program")
    ingest_parser.add_argument("--source", required=True, help="Local dir or remote spec like ryushe@hoster:/home/ryushe/bounties/acme")
    ingest_parser.add_argument("--target", help="Target slug for canonical recon path.")
    ingest_parser.add_argument("--family", default="web_bounty")
    ingest_parser.add_argument("--lane", default="web")
    ingest_parser.add_argument("--root")
    ingest_parser.add_argument("--ssh-key", default=str(DEFAULT_SSH_KEY))
    ingest_parser.add_argument("--work-dir", default="/tmp")
    ingest_parser.add_argument("--keep-fetched", action="store_true")
    ingest_parser.set_defaults(func=lambda args: print(ingest(args)))

    status_parser = subparsers.add_parser("status", help="Show remote recon-ry processes/logs.")
    status_parser.add_argument("--remote", default=DEFAULT_REMOTE)
    status_parser.add_argument("--ssh-key", default=str(DEFAULT_SSH_KEY))
    status_parser.set_defaults(func=status_remote)

    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
