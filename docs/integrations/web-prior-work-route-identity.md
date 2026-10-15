# Web prior-work route identity integration dossier

- **Status:** review-ready
- **Owner:** Hermes delegated implementation
- **Branch / owning ref:** `fix/web-prior-work-route-identity`
- **Worktree:** `/home/ryushe/worktrees/bbh-web-prior-work-route-identity`
- **Base commit:** `4823e2b9a27e04db4569f03e1075182e76a16b47`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** none yet
- **Implementation commits:** none yet

## Intent and contract

A web finding with a technology label in `file` but a sufficiently asserted single affected route should answer a targeted URL/class prior-work question without reading reports or exposing finding proof. New web/API manual ingest uses a declared URL or an unambiguous affected route for its canonical `file` identity. Ambiguous legacy prose produces an `identity_incomplete` warning, not an optimistic novelty claim. Source-file identities, unrelated hosts/routes, other classes, and binary lanes remain separate. Existing ledger data is read-only; no historical rewrite or broad migration. This only addresses **our own ledger's internal finding identity**; platform/company duplicate reports by other researchers are outside the tool's visibility and remain possible.

## Evidence and review

- Relevant isolated suites: `PYTHONPATH="$PWD" python3 -m pytest -q agents/test_me_ledger.py agents/test_manual_hunter.py agents/test_ledger_v2.py agents/test_report_checker.py tests/test_ledger_skill_visibility.py -k 'not test_cli_packet_lifecycle_keeps_stable_path_and_submission_view and not test_update_team_finding_patches_reviewer_identity_changes_by_fid'` → 93 passed, 2 deselected, 26 subtests passed.
- Both excluded tests also fail on unchanged `beta` with the same interpreter and source-first import path; packet `poc/` directory and `D01/EVIDENCE.md` path expectations diverge from installed Bounty Core. External `bounty_core` resolves `/home/ryushe/projects/bounty-core`.
- Current code's real-ledger **read-only** smoke: Immutable D21 actual URL returns `known_prior_work=true`, `confirmed=true`, `submitted=true`, `duplicate=true`; unrelated `/unrelated` route returns false. Historical ledger not edited.
- Independent read-only reviews returned BLOCK on overly broad legacy URL inference and negation; the builder added focused regressions and a fifth fresh reviewer returned **PASS** on the corrected tree (93 passed, 2 unchanged-beta failures deselected, 26 subtests; `git diff --check` clean). Reviewer did not read or change the real ledger.

## Blockers and deferred work

- **Known baseline failures:** The two packet layout expectations above fail on unchanged beta. They are explicitly deselected only in the passing relevant-suite receipt, not claimed fixed.
- **Kanban:** The Hermes `delegate_task` child context receives `kanban: delegate_task child contexts cannot mutate Kanban tasks or boards`. Parent must create/claim and close the project card; no local workaround attempted.
- **Activation:** No runtime checkout/main change authorized. No actual ledger mutation.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/web-prior-work-route-identity`
- **Latest immutable recovery checkpoint:** none yet; material change must be committed before pause.
- **Exact resume point:** Commit reviewed implementation; record immutable SHA in a follow-up dossier-only commit; fetch current beta, preflight/merge if clean, run post-merge suite.
- **Working-tree state:** implementation, tests, and dossier uncommitted.

## Decision gates

- **Integration:** Independent reviewer accepted corrected tree and relevant isolated suite passed with two reproduced baseline exclusions. Beta merge and post-merge verification pending.
- **Activation / promotion:** Not authorized.

## Decision record

- 2026-10-15 — Created bounded fixture-based repair from current beta; no target-specific code branch.
- 2026-10-15 — Reviewer acceptance after narrow fix/re-review loop; unchanged-beta packet failures remain excluded, not repaired.
