#!/bin/bash
cd ~/projects/bug_bounty_harness
exec python3 -c "
import sys
sys.path.insert(0, '.')
from agents.zero_day_team import orchestrate_zero_day_team
import sys
sys.argv[0] = 'zero_day_team'
sys.exit(orchestrate_zero_day_team())
" "$@"
