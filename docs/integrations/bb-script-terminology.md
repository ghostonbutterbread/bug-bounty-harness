# BBH script trigger terminology — integration handoff

- Status: review-ready; target `beta`.
- Branch: `docs/bb-script-terminology`; worktree: `/home/ryushe/worktrees/bbh-script-terminology`.
- Base: `c030c0a9b12f4dcff6d14e066ea05dd0a3f50821`; implementation checkpoint: `1df4fc56d41aabb41de73690c880d6e48e5b1f02` (followed by registry and test correction).

Ryu corrected the trigger from a “hunting script” to a **bug-bounty script**. Update the `/bb-script-rules` description/body, BBH entry route, registry, and their test. The trigger applies when a BBH agent uses a bug-bounty script to investigate a target; it does not make routine CI/maintenance scripts subject to target-analysis guidance. The relevant BBH skill need not be a vulnerability-class skill. The output remains non-exhaustive and technology-stack inquiry still accompanies longer scripts. JS/XSS pointers and Script Manager's separate creation/maintenance responsibility remain unchanged. This is an agent load instruction, not a deterministic runner hook.

Checks: `python3 -m pytest -q tests/test_script_policy.py skills/xss/scripts/test_xss_canary_mapper.py` → 40 passed at initial checkpoint; `git diff --check` clean. Initial independent review blocked stale registry terminology, corrected in the next checkpoint; narrow re-review pending. After review, reconcile any newer beta; merge with this temporary dossier retired, rerun focused checks, publish beta, fast-forward clean Hoster checkout, verify local/Hoster projections and new-session boundary. No stable promotion or script implementation change.
