#!/usr/bin/env python3
"""Forward safety incident commands to the pinned Bounty Core provider."""

from bounty_core.safety_incidents import main


if __name__ == "__main__":
    raise SystemExit(main())
