#!/usr/bin/env python3
"""Retired compatibility entry point for the obsolete SUBMISSION.md writer."""

import sys

MESSAGE = "SUBMISSION.md generation is retired. After populated FID EVIDENCE.md, load the standalone bunny-report-and-triage skill directly and register its reviewed final report with agents/finding_report.py; historical files are preserved."


def prepare_submission(*args, **kwargs):
    raise ValueError(MESSAGE)


def main(argv=None):
    print(MESSAGE, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
