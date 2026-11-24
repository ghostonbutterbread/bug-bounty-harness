#!/usr/bin/env python3
"""Record one deliberate Attempt through BBH's canonical writer.

Run it through the selected checkout so the runtime interpreter and Bounty Core
are the ones that checkout pins::

    bbh scripts/append_attempt.py --program <program> --lane <lane> \\
        --run-id <run-id> --timestamp-now <<'JSON'
    {"tool": "...", "target": "...", "outcome": "...", "stop_reason": "..."}
    JSON

Redaction, attempt-ID assignment, and locked appends stay in
``agents.attempts.append_attempt``. This adapter selects the stream, reads one
JSON object, and rejects shell-input mistakes (non-string required fields, a
conflicting ``run_id``, path-like names) before anything is written.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from agents.attempts import (
        REQUIRED_ATTEMPT_FIELDS,
        append_attempt,
        resolve_attempts_path,
        utc_timestamp,
    )
    from agents.storage_resolver import DEFAULT_LANES, infer_family_from_lane, resolve_storage
except ImportError as exc:  # agents.attempts carries the actionable guidance.
    raise SystemExit(f"append_attempt: {exc}") from None

PROG = "bbh scripts/append_attempt.py"
# Run IDs become a path component and are echoed in the receipt: keep them to a
# charset the writer's redaction never rewrites, so stored row, path and output agree.
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
NO_INPUT = "no attempt JSON; pass --json or a quoted heredoc (<<'JSON' ... JSON)"


class UsageError(Exception):
    """A caller-correctable problem; reported without a traceback."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Append one Attempt (a JSON object) through agents.attempts.append_attempt. "
            "The object must carry nonempty string timestamp, tool, target, outcome and "
            "stop_reason; add Core fields such as vuln_class, payload, payload_family, "
            "input_location, variable_changed and comparison_to when known."
        ),
        epilog=(
            "Destination: --program/--lane/--run-id resolve the run-owned stream "
            "<lane>/attempts/_runs/<run-id>/attempts.jsonl in an existing program lane; "
            "--path appends to an exact stream handed over by a packet. Prints the stored "
            "attempt_id, run_id and absolute path as JSON."
        ),
    )
    destination = parser.add_argument_group("destination")
    destination.add_argument("--program", help="program slug of an initialized program")
    destination.add_argument("--lane", help="selected lane, for example web or api")
    destination.add_argument(
        "--run-id", help="current run ID: letters, digits, '.', '_', '-' (reuse it for the whole run)"
    )
    destination.add_argument("--family", help="storage family; inferred for default lanes (web/api/apk/exe/mac)")
    destination.add_argument("--root", help="explicit shared base (defaults to the resolver's ~/Shared)")
    destination.add_argument("--path", help="exact attempts.jsonl stream instead of program/lane/run")
    attempt = parser.add_argument_group("attempt")
    attempt.add_argument("--json", dest="attempt_json", help="attempt JSON object; read from stdin when omitted")
    attempt.add_argument(
        "--timestamp-now",
        action="store_true",
        help="set timestamp to the current UTC time; rejected if the JSON already has one",
    )
    attempt.add_argument("--agent-id", help="optional ai_reviewed_by agent attribution")
    attempt.add_argument("--model-id", help="optional ai_reviewed_by model attribution")
    return parser


def _absent(value: object) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _check_run_id(value: str, source: str) -> str:
    if not RUN_ID.fullmatch(value):
        raise UsageError(
            f"{source} must use only letters, digits, '.', '_' or '-' and start with a letter or digit; "
            "never put secrets in a run ID"
        )
    return value


def check_destination(args: argparse.Namespace) -> str | None:
    """Validate destination options before any storage access; return the stream's run ID.

    In --path mode this also normalizes ``args.path`` to an absolute path.
    """
    resolver_options = {
        "--program": args.program,
        "--lane": args.lane,
        "--run-id": args.run_id,
        "--family": args.family,
        "--root": args.root,
    }
    if args.path is not None:
        conflicting = [flag for flag, value in resolver_options.items() if value is not None]
        if conflicting:
            raise UsageError(f"--path cannot be combined with {', '.join(conflicting)}")
        if not args.path.strip():
            raise UsageError("--path must name an attempts.jsonl file")
        args.path = os.path.abspath(Path(args.path).expanduser())
        path = Path(args.path)
        if path.name == "attempts.jsonl" and path.parent.parent.name == "_runs":
            return _check_run_id(path.parent.name, "the --path run directory")
        return None
    missing = [flag for flag in ("--program", "--lane", "--run-id") if resolver_options[flag] is None]
    if missing:
        raise UsageError(f"missing {', '.join(missing)} (or pass --path with an exact attempts.jsonl stream)")
    for flag in ("--program", "--lane"):
        value = resolver_options[flag].strip()
        if value in {"", ".", ".."} or "/" in value or "\\" in value:
            raise UsageError(f"{flag} must be a plain name, not empty, '.', '..' or a path")
    return _check_run_id(args.run_id, "--run-id")


def read_attempt(args: argparse.Namespace) -> dict:
    if args.attempt_json is not None:
        text = args.attempt_json
    elif sys.stdin is None or sys.stdin.isatty():
        raise UsageError(NO_INPUT)
    else:
        text = sys.stdin.read()
    if not text.strip():
        raise UsageError(NO_INPUT)
    try:
        attempt = json.loads(text)
    except json.JSONDecodeError as exc:
        raise UsageError(f"attempt is not valid JSON: {exc}") from None
    if not isinstance(attempt, dict):
        raise UsageError("attempt must be one JSON object, not a list or scalar")
    return attempt


def check_attempt(attempt: dict, args: argparse.Namespace, stream_run_id: str | None) -> None:
    if args.timestamp_now:
        if not _absent(attempt.get("timestamp")):
            raise UsageError("--timestamp-now conflicts with the attempt's own timestamp; supply only one")
        attempt["timestamp"] = utc_timestamp()
    invalid = [
        field for field in REQUIRED_ATTEMPT_FIELDS
        if not (isinstance(attempt.get(field), str) and attempt[field].strip())
    ]
    if invalid:
        raise UsageError(f"attempt missing required fields: {', '.join(invalid)}")
    if _absent(attempt.get("run_id")):
        attempt.pop("run_id", None)  # the writer fills it from the run stream
    elif stream_run_id is not None and attempt["run_id"] != stream_run_id:
        raise UsageError(
            f"attempt run_id does not match the destination run {stream_run_id!r}; "
            "omit run_id from the JSON or make them equal"
        )


def resolve_destination(args: argparse.Namespace) -> Path:
    if args.path is not None:
        return Path(args.path)
    family = args.family or infer_family_from_lane(args.lane)
    layout = resolve_storage(args.program, family=family, lane=args.lane, root_override=args.root)
    if not layout.lane_root.is_dir():
        # Writing here would otherwise create a whole program tree for a typo.
        if layout.lane in DEFAULT_LANES.get(layout.family, set()):
            remedy = (
                f"initialize it with bbh scripts/program_init.py {layout.program} --lane {layout.lane} "
                "(plus --platform or --skip-scope)"
            )
        else:
            remedy = (
                "custom lanes are created by the tool that owns them, not by this command; "
                "use the lane or exact --path from your packet"
            )
        raise UsageError(
            f"program lane not found: {layout.lane_root}; check --program/--lane/--family/--root or {remedy}"
        )
    # create=False: write only under attempts/; never rescaffold the lane or
    # rewrite its context/target_profile.json.
    return resolve_attempts_path(
        args.program, run_id=args.run_id, family=family, lane=args.lane, root_override=args.root, create=False
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        stream_run_id = check_destination(args)
        attempt = read_attempt(args)
        check_attempt(attempt, args, stream_run_id)
        path = resolve_destination(args)
        stored = append_attempt(path, attempt, agent_id=args.agent_id, model_id=args.model_id)
    except (UsageError, ValueError) as exc:
        message = str(exc)
        print(f"append_attempt: {message}", file=sys.stderr)
        if message.startswith("attempt missing required fields"):
            print(
                f"append_attempt: required nonempty string fields: {', '.join(REQUIRED_ATTEMPT_FIELDS)}; "
                "use --timestamp-now for the current UTC timestamp",
                file=sys.stderr,
            )
        return 2
    except OSError as exc:
        print(f"append_attempt: could not write the attempt: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"attempt_id": stored["attempt_id"], "run_id": stored.get("run_id"), "path": str(path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
