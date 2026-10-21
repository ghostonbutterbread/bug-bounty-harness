# XSS consumer reach blind-lane correction

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `fix/xss-consumer-reach-blind`
- **Base:** `3adaf9ed880dda96c42e66c4380f3a3f7688b45a` (`origin/beta`)
- **Target:** `beta`
- **Last updated:** 2026-10-21
- **Recovery checkpoint / implementation commit:** pending
- **Inspiration:** post-integration comparison with canonical `blind-xss`.

## Intent and contract

The new reachability policy row must not categorically exclude staff-facing artifacts: `blind-xss` allows permitted inert correlated staff-facing canaries and prohibits them when program rules do. Scope and human-visible effects remain bounded. Patch only the row and regression assertions; no target probing.

## Evidence and review

- Focused tests: pending.
- Independent review: prior review missed this adjacent-lane conflict; correction review pending.
- Full-suite known blockers: root `test_catalog.py` missing `bac_checks`; unrelated stack-to-program script-index failure; broad tests timed out. Do not claim suite green.

## Blockers and deferred work

No correction-specific blocker. Rerun focused tests, review against blind lane, integrate, verify runtime projection. Full-suite blockers as above.

## Interruption / resume handoff

- **Branch:** `fix/xss-consumer-reach-blind`
- **Checkpoint:** pending
- **Next:** focused tests, review, commit, merge into current beta and retire dossier.
- **Working tree:** uncommitted until checks.

## Decision gates

- **Integration:** focused tests and adjacent lane compatibility.
- **Activation:** beta push plus local resolved reference load.
- **Promotion:** main unchanged.

## Decision record

- 2026-10-21 — identified contradiction with `blind-xss` staff-facing inert canary carve-out; correction drafted.
