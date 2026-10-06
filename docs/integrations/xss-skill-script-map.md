# XSS skill script map integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `docs/xss-skill-script-map`
- **Base commit:** `a9d625d39f247a9b708401056938533613419bae`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-05
- **Owning feature branch/ref:** `docs/xss-skill-script-map`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** `SCRIPT_POLICY.md`, `scripts/README.md`, `skills/xss/scripts/README.md`, `skills/xss/SKILL.md`, Discord script-reuse thread.

## Intent

Make existing XSS helpers discoverable without inventing a second catalog or presenting old script names as proof of currency. Preserve XSS routing, script ownership, and non-exhaustive interpretation.

## Implemented contract

Append a concise Scripts map to the XSS skill. Link the maintained skill-owned README and describe the canary mapper's use. Point static sink census to the current JS analyzer and `/js`; do not claim a script proves a source-to-sink path. Other skill-owned script homes already name their helpers in their owning skills, and only XSS has a local vulnerability-class script directory in this repository.

## Evidence and review

- Tests and commands: `python3 -m pytest skills/xss/scripts/test_xss_canary_mapper.py -q` (15 passed); `python3 -m pytest tests/test_script_policy.py -q` (25 passed); `git diff --check` (pass); checked `--help` for canary mapper and JS analyzer from beta dispatcher. The clean feature worktree lacks `.venv`, so its `./scripts/bbh` command fails with the documented environment prerequisite; Python tests execute without that venv.
- Independent review: pending.
- Replay/cohort/fixture evidence: not applicable; metadata-only skill change.
- Merge/ancestry evidence: base equals fetched `origin/beta` at branch creation; re-fetch before integration.

## Blockers and deferred work

No blocker to documentation review. A checkout-local dispatcher smoke requires `./setup.sh --install-python-deps` in this feature worktree; it was not necessary for the unchanged scripts or focused Python tests. Rerun the dispatcher here if a reviewer needs proof of worktree-local executable dependencies; do not claim it was run successfully here.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/xss-skill-script-map`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** Commit skill and dossier, request independent diff review, then integrate to beta if accepted.
- **Working-tree state at handoff:** intentionally uncommitted until first checkpoint.

## Decision gates

- **Integration gate:** focused checks plus independent review; merge only into current clean beta.
- **Activation / cohort gate:** verify linked Hermes XSS skill resolves to the integrated canonical source; remote Hoster publication is separate.
- **Promotion gate:** main requires explicit direction.

## Decision record

- 2026-10-05 — Audited existing map conventions and added a bottom-of-skill pointer for XSS; awaiting review.
