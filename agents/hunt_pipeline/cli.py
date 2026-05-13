from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if _PROJECT_ROOT.as_posix() not in (Path(item).as_posix() for item in sys.path if item):
    sys.path.insert(0, _PROJECT_ROOT.as_posix())

from agents.hunt_pipeline.dry_run import build_dry_run_plan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Dry-run hunt pipeline planner.")
    parser.add_argument("program")
    parser.add_argument("target_path")
    parser.add_argument("--target-kind", default="auto")
    parser.add_argument("--ruleset", default="auto")
    parser.add_argument("--from-appmap-run", dest="appmap_run")
    parser.add_argument("--output-dir", default="hunt_pipeline_out")
    parser.add_argument("--run-id", default="pipeline-dry-run")
    parser.add_argument("--max-hypotheses", type=int)
    parser.add_argument("--dry-run", action="store_true", default=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    artifact, plan_path = build_dry_run_plan(
        program=args.program,
        target_path=args.target_path,
        target_kind=args.target_kind,
        ruleset_id=args.ruleset,
        appmap_run=args.appmap_run,
        output_dir=args.output_dir,
        run_id=args.run_id,
        max_hypotheses=args.max_hypotheses,
    )
    print(json.dumps({"pipeline_plan": str(Path(plan_path)), "hypotheses": len(artifact.hypotheses)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
