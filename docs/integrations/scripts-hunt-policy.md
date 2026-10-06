# Script-assisted hunting integration dossier

- **Status:** review-ready
- **Owner:** Hermes Agent
- **Branch:** `docs/scripts-hunt-policy`
- **Base commit:** `58706890ddb4cb4e882bbe781a4a9157a806dc5b`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-06
- **Owning feature branch/ref:** `docs/scripts-hunt-policy`
- **Latest immutable recovery checkpoint:** `c06b7fca5c65ad9476c1b52049d92ad59910748a`
- **Feature implementation commit(s):** `2061f033aa8e6a46182d99e042a1128fdb2f7751`, `c06b7fca5c65ad9476c1b52049d92ad59910748a`
- **Inspiration:** Ryu's request for one BBH `/scripts` policy loaded when vulnerability hunters run scripts, rather than duplicated specialist-only wording or Script Manager obligations.

## Intent and contract

`skills/scripts/SKILL.md` owns bounded interpretation of script output and concurrent application-specific, vulnerability-class inquiry during longer runs. A short run gets its coverage review afterward. The BBH entry routes relevant hunt scripts to it; XSS and JS retain only class-specific examples and skill-local command discovery. `SCRIPT_POLICY.md` remains for creation/maintenance; no script executable or inventory implementation changes. Live policy and class proof gates stay authoritative. This is not a universal rule for tests, migrations, or all operations.

## Evidence and review

- Tests and commands: `python3 -m pytest -q tests/test_script_policy.py skills/xss/scripts/test_xss_canary_mapper.py` (40 passed after JS authority fix); `git diff --check` clean. `python3 -m pytest -q tests` returned 183 passed, 1 skipped, 3 pre-existing failures in `test_hoster_script_authority.py`, `test_runtime_dependencies.py`, and `test_skill_command_lane_safety.py` (the latter names an unchanged dossier at base). Root-level `python3 -m pytest -q` additionally fails collecting `test_catalog.py` due to unavailable `bac_checks` import.
- Independent review: initial duplicate-JS-doctrine finding was fixed in `c06b7fc`; narrow re-review approved feature tip `bbb5860` with no blocker. Reviewer reran 40 focused tests and `git diff --check`.
- Merge/ancestry evidence: fetched `origin/beta` at `5870689`, unchanged from feature base; no competing delta.

## Blockers and deferred work

- No known implementation blocker. Baseline suite failures above are not caused by this diff; rerun those tests when their owners reconcile the stale assertion, dependency pin, old dossier, and root-level import path. Hoster new-skill projection requires a clean beta runtime checkout, profile dry-run, apply, and active-link read-back; if remote credentials fail, preserve published source and report activation blocked rather than transferring via an unapproved fallback.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/scripts-hunt-policy`
- **Latest immutable recovery checkpoint:** `c06b7fca5c65ad9476c1b52049d92ad59910748a`
- **Feature implementation commit(s):** `2061f033aa8e6a46182d99e042a1128fdb2f7751`, `c06b7fca5c65ad9476c1b52049d92ad59910748a`
- **Exact resume point:** merge the approved feature into `beta`, remove this temporary dossier from the integration tree, publish, and activate linked skill.
- **Working-tree state at handoff:** clean after dossier checkpoint commit.

## Decision gates

- **Integration gate:** focused tests and independent review of one canonical owner and specialist routes.
- **Activation gate:** published beta revision, clean Hoster source update, focused profile sync and active-link content check.
- **Promotion gate:** main requires explicit Ryu direction; out of scope.

## Decision record

- 2026-10-06 — implementation checkpoint `2061f033`; focused tests passed; wider baseline failures recorded. Reviewer blocked duplicate JS output doctrine; follow-up `c06b7fc` narrowed JS guidance to mechanics and moved interpretation exclusively to `/scripts`. Focused tests: 40 passed; re-review requested.
- 2026-10-06 — independent re-review approved `bbb5860` after the JS fix; accepted for `beta` integration with baseline suite failures documented separately.
