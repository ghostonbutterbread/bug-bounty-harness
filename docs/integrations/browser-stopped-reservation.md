# Fixture stopped-profile reservation checkpoint

- **Status:** blocked / inert gate only
- **Owner:** Hermes bugfix subagent
- **Branch / owning ref:** `feat/browser-stopped-reservation`
- **Base commit:** `2d80b03af499a033a0b9a46c87b7e3a4eb61236c` (fetched `origin/beta`)
- **Intended integration target:** `beta` (no merge or push authorized)
- **Last updated:** 2026-09-25
- **Latest immutable recovery checkpoint:** this commit (resolve with `git rev-parse HEAD`)
- **Feature implementation commit(s):** this checkpoint
- **Inspiration:** stopped-profile feasibility is separate work; no feasibility-branch code used or edited.

## Intent and implemented contract

A fixture-only, *inert* manager reservation persists in the canonical SQLite store. It binds exact fixture pool (`fixture`, `fixture.invalid`, `anon`), source lease, manager identity, owner, recorded control generation/root/unit/CDP and physical directory inode. Creation reads manager and canonical rows, checks stopped/terminal identity and historical physical aliases, then serializes against canonical acquisition with `BEGIN IMMEDIATE`. Manager `start`, `retire`, `release`, and `sweep_rows` and direct canonical `acquire`, `transfer_managed_lease`, and `release` reject an active fence. The reservation is not time-expired; unknown copy/uncertain phases stay fenced. Cancellation is limited to an untouched `reserved` phase with reverified stopped identity. No CLI or copy/snapshot activation is provided. No real browser profile was read.

## Evidence and review

- `python3 -m pytest agents/test_browser_stopped_reservation.py agents/test_browser_profile_lease.py agents/test_browser_manager_transfer_gate.py agents/test_browser_provisioner.py -q` — **80 passed** in isolated worktree.
- Fixture tests cover symlink identity, alias nonterminal rejection, stale generation, persisted fence, direct canonical transfer/release/acquire, policy flip, concurrent canonical gate reads, uncertain phase, and cancellation. Browser stop/CDP/unit probes are mocked for disposable SQLite fixtures.
- Independent review: not performed. No integration/release claim.

## Blockers and deferred work

- **Missing evidence:** manager-authoritative offline snapshot proof reader and session-only negative canary. **Fixture/trigger:** add a snapshot consumer only after separate feasibility branch supplies validated session-only evidence; run a crash-during-copy restart/claim/cleanup race with actual disposable browser and filesystem alias changes. **Why blocking:** the gate alone does not make copying safe.
- **Missing consumer:** state transitions into `copying`/`uncertain`, verified completion/resume, and release after a successful copy. These are intentionally absent; no production clone activation or real account testing permitted. A manually uncertain row remains fenced until a future reviewed recovery protocol exists.
- **Missing integration review:** independently examine all manager lifecycle entry points, physical alias race/TOCTOU behavior, and canonical policy mutation. Retry tests under a disposable browser after the above consumer exists. Do not merge into `beta` on the basis of this fixture-only checkpoint.

## Interruption / resume handoff

- **Branch:** `feat/browser-stopped-reservation`
- **Checkpoint:** this commit; retrieve exact SHA with `git rev-parse HEAD`
- **Exact resume point:** independently review the inert fence, then implement a manager+canonical-derived snapshot reader and verified phase/recovery contract only if feasibility evidence supports it.
- **Working-tree state at handoff:** clean after checkpoint.

## Decision gates

- **Integration:** blocked pending independent review and full lifecycle/consumer verification.
- **Activation:** prohibited; fixture only.
- **Promotion:** prohibited.

## Decision record

- 2026-09-25 — fixture-only inert reservation checkpoint; full clone safety explicitly not claimed.
