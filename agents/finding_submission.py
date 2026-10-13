#!/usr/bin/env python3
"""Retired compatibility entry point for the obsolete SUBMISSION.md writer."""

import sys

MESSAGE = "SUBMISSION.md generation is retired. Use the standalone Bunny FID report via security-reporting and register it with agents/finding_report.py; historical files are preserved."


def prepare_submission(*args, **kwargs):
    raise ValueError(MESSAGE)


def main(argv=None):
    print(MESSAGE, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
