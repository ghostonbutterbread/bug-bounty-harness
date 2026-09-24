# Program-scoped authenticated browser clone pool

- **Status:** feasibility and contract validation; no auth-cloning implementation yet
- **Owner:** Hermes integration
- **Branch / worktree:** `feat/browser-auth-clone-pool` / `/home/ryushe/projects/bug_bounty_harness/browser-legacy-auto-migration`
- **Base / target:** fetched `origin/beta` `4998839964166054e6193939e4e9335be2137d40` → `beta`
- **Inspiration:** owner correction in the concurrent-Blue browser thread. The earlier auto-slot migration creates separate, initially unauthenticated profiles; that does not meet this goal.

## Contract to establish

Agents request a color/account within an exact `(program, auth domain, account alias)` pool. When policy and admission permit concurrent sessions, each receives a distinct Chrome instance and profile directory populated with a verified copy of that pool's authenticated state. No cross-program or cross-domain Blue state flows. The provisioner exposes an explicit program-scoped concurrency setting (`single` versus `multiple`) that agents may update with evidence as they learn the program's session rules. A confirmed single-session program remains restricted to one effective browser; ordinary logout alone does not prove that policy. The existing `set-browser-policy` command is narrower (program/account/auth domain); reconcile precedence and preserve existing per-account restrictions rather than silently overriding them with a program-wide multiple setting. The live owner and its profile are never copied as raw changing files, stopped, or revoked by another agent's request. A verified auth update from one clone can be promoted to the pool and propagated to other clones at a safe boundary, with per-clone auth verification and no raw secrets in CLI output, logs, Git, or notes. Existing active clones cannot have their on-disk files overwritten. Failed/unknown clone verification must queue or require login rather than declare an authenticated Blue ready.

## Open implementation boundary

Determine whether browser-native transfer covers the account's actual auth stores (cookies, origin storage, token lifecycle) without stealing the source agent's control or leaking session data; a quiescent full-profile snapshot may be needed for unsupported stores. A live filesystem copy is not an acceptable generic shortcut. Decide and test the supported contract before editing runtime selection. Keep the old isolated-empty auto-slot behavior from being represented as authenticated-clone success.

## Acceptance and release gates

- Deterministic tests: program-level `single`/`multiple` policy command/readback, evidence and precedence against existing per-account/domain rules, cross-program isolation, same-color pool, verified auth generation and stale recipient, restricted mode, concurrent requester race, source/recipient failure rollback, no raw auth in receipts, owner termination and cleanup, and profile directory uniqueness.
- Disposable browser fixture: first and second Chrome have separate physical profiles and the same controlled authenticated canary; update one, promote, and verify the other's next safe refresh. Prove source browser remains live and unchanged. A cookie-only demonstration is not evidence for apps that require other storage.
- Independent review and integrated beta tests before merge. Hoster data/owner preflight and destination fixture before activation; do not operate on live Blue until quiescence and the historical malformed manager cohort are safely classified.

## Evidence / handoff

Program-policy slice implemented locally on this feature branch: separate program-keyed SQLite table, categorical source/evidence (no free text), set/show CLI readback, and shared admission predicate used by provisioner selection, canonical acquire and transfer. Program `single` dominates exact `multiple`; exact `single` dominates program `multiple`; absent/unknown program mode preserves legacy exact behavior. Writes do not touch active leases or browsers and logout reports remain passive. Focused disposable tests cover cross-program same-alias isolation, precedence, legacy/unknown DB, active lease stability, invalid metadata and logout. Receipt: `python -m pytest -q agents/test_browser_program_policy.py agents/test_browser_resources.py agents/test_browser_legacy_auto.py` → 125 passed. `git diff --check` clean. No Hoster or account mutation.

Authenticated clone feasibility remains blocked: determine whether browser-native transfer covers actual auth stores without stealing source control or leaking session data; a quiescent snapshot may be required for unsupported stores. Deferred checks are the acceptance tests above for same-color verified auth generation, stale recipient, races, rollback, source termination and physical browser profiles, plus a disposable two-Chrome canary covering cookies **and** required origin storage. Trigger these only after a concrete safe transfer contract and fixture exist; do not promote this policy checkpoint as clone-ready. Next action: reconcile feasibility evidence, then build/test only the supported clone path on this branch. Target remains `beta`; no merge/push or Hoster activation in this checkpoint.
