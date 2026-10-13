#!/usr/bin/env python3
"""Register an existing Bunny report against its exact finding FID.

Registration updates navigation, not readiness or external submission state.
The standalone reporting skill creates and reviews the file; this command never
writes report content or runs a target-facing action.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from bounty_core.ledger import record_final_finding_report


def register(
    program: str, fid: str, report: Path, *, lane: str,
    family: str | None = None, storage_root: Path | None = None,
) -> dict:
    finding = record_final_finding_report(
        program, fid, report, family=family, lane=lane,
        root_override=storage_root,
    )
    if finding is None:
        raise ValueError(f"no finding found for {program}/{lane}/{fid}")
    return {"fid": finding["fid"], "report_path": finding["report_path"],
            "evidence_path": finding.get("evidence_path"), "ready": False,
            "submitted": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program")
    parser.add_argument("fid", help="exact existing ledger FID")
    parser.add_argument("--lane", required=True, choices=("web", "api", "apk", "exe", "mac"))
    parser.add_argument("--family", choices=("web_bounty", "binaries"))
    parser.add_argument("--report", type=Path, required=True, help="existing FID-named Bunny report")
    parser.add_argument("--storage-root", type=Path, help="explicit test/local storage root")
    args = parser.parse_args(argv)
    try:
        result = register(
            args.program, args.fid, args.report, lane=args.lane,
            family=args.family, storage_root=args.storage_root,
        )
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
