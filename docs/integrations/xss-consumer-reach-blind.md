# XSS consumer reach blind-lane correction

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `fix/xss-consumer-reach-blind`
- **Base:** `3adaf9ed880dda96c42e66c4380f3a3f7688b45a` (`origin/beta`)
- **Target:** `beta`
- **Last updated:** 2026-10-21
- **Recovery checkpoint / implementation commit:** `2f8f7e8103e05c044ef87cd3d2cf4ea2c37b0d46`
- **Inspiration:** post-integration comparison with canonical `blind-xss`.

## Intent and contract

The new reachability policy row must not categorically exclude staff-facing artifacts: `blind-xss` allows permitted inert correlated staff-facing canaries and prohibits them when program rules do. Scope and human-visible effects remain bounded. Patch only the row and regression assertions; no target probing.

## Evidence and review

- Focused tests: 12 passed (`test_xss_consumer_reach.py`, `test_xss_mechanism_ideation.py`, `test_xss_defense_chain_policy.py`, `test_xss_skill_clarity.py`); `git diff --check` clean.
- Independent read-only correction review approved after checking `blind-xss`, `stored-xss`, and program-rule ownership; reviewer ran 10 adjacent focused tests and `git diff --check`.
- Full-suite known blockers: root `test_catalog.py` missing `bac_checks`; unrelated stack-to-program script-index failure; broad tests timed out. Do not claim suite green.

## Blockers and deferred work

No correction-specific blocker. Rerun focused tests, review against blind lane, integrate, verify runtime projection. Full-suite blockers as above.

## Interruption / resume handoff

- **Branch:** `fix/xss-consumer-reach-blind`
- **Checkpoint:** `2f8f7e8103e05c044ef87cd3d2cf4ea2c37b0d46`
- **Next:** merge into current beta, retire dossier, rerun focused tests, push and verify projection.
- **Working tree:** clean after this decision update is committed.

## Decision gates

- **Integration:** focused tests and adjacent lane compatibility.
- **Activation:** beta push plus local resolved reference load.
- **Promotion:** main unchanged.

## Decision record

- 2026-10-21 — identified contradiction with `blind-xss` staff-facing inert canary carve-out; correction drafted.
- 2026-10-21 — independent correction review accepted with no blocking findings; integrate to beta.
