#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "${REPO_DIR}"
exec python3 -c "
import sys
sys.path.insert(0, '.')
from agents.zero_day_team import orchestrate_zero_day_team
sys.argv[0] = 'zero_day_team'
sys.exit(orchestrate_zero_day_team())
" "$@"
