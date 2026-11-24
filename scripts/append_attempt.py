#!/usr/bin/env python3
"""Record one deliberate Attempt through BBH's canonical writer.

Run it through the selected checkout so the runtime interpreter and Bounty Core
are the ones that checkout pins::

    bbh scripts/append_attempt.py --program <program> --lane <lane> \\
        --run-id <run-id> --timestamp-now <<'JSON'
    {"tool": "...", "target": "...", "outcome": "...", "stop_reason": "..."}
    JSON

Validation, redaction, attempt-ID assignment, and locked appends stay in
``agents.attempts.append_attempt``; this adapter only selects the stream and
reads one JSON object.
"""

from __future__ import annotations

import argparse
import json
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
    from agents.storage_resolver import infer_family_from_lane, resolve_storage
except ImportError as exc:  # agents.attempts carries the actionable guidance.
    raise SystemExit(f"append_attempt: {exc}") from None

PROG = "bbh scripts/append_attempt.py"


class UsageError(Exception):
    """A caller-correctable problem; reported without a traceback."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Append one Attempt (a JSON object) through agents.attempts.append_attempt. "
            "The object must carry nonempty timestamp, tool, target, outcome and stop_reason; "
            "add Core fields such as run_id, vuln_class, payload, payload_family, "
            "input_location, variable_changed and comparison_to when known."
        ),
        epilog=(
            "Destination: --program/--lane/--run-id resolve the run-owned stream "
            "<lane>/attempts/_runs/<run-id>/attempts.jsonl in an existing program lane; "
            "--path appends to an exact stream handed over by a packet. Prints the stored "
            "attempt_id, run_id and path as JSON."
        ),
    )
    destination = parser.add_argument_group("destination")
    destination.add_argument("--program", help="program slug of an initialized program")
    destination.add_argument("--lane", help="selected lane, for example web or api")
    destination.add_argument("--run-id", help="current run ID (path-safe; reuse it for the whole run)")
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


def read_attempt(args: argparse.Namespace) -> dict:
    if args.attempt_json is not None:
        text = args.attempt_json
    elif sys.stdin.isatty():
        raise UsageError("provide the attempt as one JSON object with --json or on stdin")
    else:
        text = sys.stdin.read()
    try:
        attempt = json.loads(text)
    except json.JSONDecodeError as exc:
        raise UsageError(f"attempt is not valid JSON: {exc}") from None
    if not isinstance(attempt, dict):
        raise UsageError("attempt must be one JSON object, not a list or scalar")
    if args.timestamp_now:
        if str(attempt.get("timestamp", "")).strip():
            raise UsageError("--timestamp-now conflicts with the attempt's own timestamp; supply only one")
        attempt["timestamp"] = utc_timestamp()
    return attempt


def resolve_destination(args: argparse.Namespace) -> Path:
    resolver_options = {
        "--program": args.program,
        "--lane": args.lane,
        "--run-id": args.run_id,
        "--family": args.family,
        "--root": args.root,
    }
    if args.path:
        conflicting = [flag for flag, value in resolver_options.items() if value]
        if conflicting:
            raise UsageError(f"--path cannot be combined with {', '.join(conflicting)}")
        return Path(args.path).expanduser()
    missing = [flag for flag in ("--program", "--lane", "--run-id") if not resolver_options[flag]]
    if missing:
        raise UsageError(f"missing {', '.join(missing)} (or pass --path with an exact attempts.jsonl stream)")
    family = args.family or infer_family_from_lane(args.lane)
    layout = resolve_storage(args.program, family=family, lane=args.lane, root_override=args.root)
    if not layout.lane_root.is_dir():
        # The writer would otherwise create a whole program tree for a typo.
        raise UsageError(
            f"program lane not found: {layout.lane_root}; check --program/--lane/--family/--root "
            "or initialize it with bbh scripts/program_init.py"
        )
    return resolve_attempts_path(
        args.program, run_id=args.run_id, family=family, lane=args.lane, root_override=args.root
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        attempt = read_attempt(args)
        path = resolve_destination(args)
        stored = append_attempt(path, attempt, agent_id=args.agent_id, model_id=args.model_id)
    except (UsageError, ValueError) as exc:
        message = str(exc)
        print(f"append_attempt: {message}", file=sys.stderr)
        if message.startswith("attempt missing required fields"):
            print(
                f"append_attempt: required nonempty fields: {', '.join(REQUIRED_ATTEMPT_FIELDS)}; "
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
