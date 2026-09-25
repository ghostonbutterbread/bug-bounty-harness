# Fixture stopped-profile reservation checkpoint

- **Status:** blocked / inert gate only
- **Owner:** Hermes bugfix subagent
- **Branch / owning ref:** `feat/browser-stopped-reservation`
- **Base commit:** `2d80b03af499a033a0b9a46c87b7e3a4eb61236c` (fetched `origin/beta`)
- **Intended integration target:** `beta` (no merge or push authorized)
- **Last updated:** 2026-09-25
- **Latest immutable recovery checkpoint:** `0e943c0` (initial inert fixture checkpoint); the repair commit is the owning branch tip after this dossier is committed.
- **Feature implementation commit(s):** `0e943c0` plus the subsequent reservation repair commit.
- **Inspiration:** stopped-profile feasibility is separate work; no feasibility-branch code used or edited.

## Intent and implemented contract

A fixture-only, *inert* manager reservation persists in the canonical SQLite store. It binds exact fixture pool (`fixture`, `fixture.invalid`, `anon`), source lease, manager identity, owner, recorded control generation/root/unit/invocation/CDP and physical directory inode. Creation reads manager and canonical rows, checks stopped/terminal identity and historical physical aliases, then serializes against canonical acquisition with `BEGIN IMMEDIATE`. A retry is idempotent only for an identical `reserved` row; it cannot downgrade `copying` or `uncertain`. Cancellation requires an untouched `reserved` row, independently re-reading manager, canonical, launch receipt, stopped probes, and physical identity against every recorded field; missing evidence leaves the fence. Manager `start`, `retire`, `release`, and `sweep_rows` and direct canonical `acquire`, `transfer_managed_lease`, and `release` reject an active fence. The reservation is not time-expired; copy/uncertain phases stay fenced. No CLI or copy/snapshot activation is provided. No real browser profile was read.

## Evidence and review

- Initial independent review of `0e943c0` **BLOCKED**: copying→retry rewrote phase to reserved and allowed cancellation; cancellation compared only generation/inode/manager ID, not root/CDP/unit/invocation/owner/canonical identity.
- RED receipt before repair: `python3 -m pytest agents/test_browser_stopped_reservation.py -q` — 16 failed, 10 passed, 1 subtest passed (includes initial fixture harness cascades after first unexpected release; invalid `applying` variation removed because schema excludes it).
- GREEN receipt: `python3 -m pytest agents/test_browser_stopped_reservation.py agents/test_browser_profile_lease.py agents/test_browser_manager_transfer_gate.py agents/test_browser_provisioner.py -q` — **84 passed, 24 subtests passed** (63.19s); `git diff --check` clean. Fixture tests cover copying/uncertain retry→cancel, manager/canonical/recorded identity drift, missing proof, altered fence fields, symlink alias and inode replacement, and existing canonical/manager admission gates. Browser stop/CDP/unit probes are mocked for disposable SQLite fixtures. No post-repair independent review or integration/release claim.

## Blockers and deferred work

- **Missing evidence:** manager-authoritative offline snapshot proof reader and session-only negative canary. **Fixture/trigger:** add a snapshot consumer only after separate feasibility branch supplies validated session-only evidence; run a crash-during-copy restart/claim/cleanup race with actual disposable browser and filesystem alias changes. **Why blocking:** the gate alone does not make copying safe.
- **Missing consumer:** state transitions into `copying`/`uncertain`, verified completion/resume, and release after a successful copy. These are intentionally absent; no production clone activation or real account testing permitted. A manually uncertain row remains fenced until a future reviewed recovery protocol exists.
- **Deferred filesystem TOCTOU:** `browser_profile_lease.py:185-201` physical-profile resolution and sweep around `:2852` / `:2939-2942` may race symlink/directory replacement across check and consumer access. The inert reservation has no snapshot/copy consumer, so this is not a present copy bypass; an actual consumer must pin/open the profile identity and verify at use, then exercise alias-swap races. Do not activate or merge into `beta` on the basis of fixture-only tests.
- **Missing integration review:** independently examine all manager lifecycle entry points, physical alias race/TOCTOU behavior, and canonical policy mutation. Retry tests under a disposable browser after the above consumer exists.

## Interruption / resume handoff

- **Branch:** `feat/browser-stopped-reservation`
- **Checkpoint:** `0e943c0` initial; inspect branch tip for this repair commit and verify its diff/tests before any integration.
- **Exact resume point:** obtain independent review of this repaired inert fence, then implement a manager+canonical-derived snapshot reader and verified phase/recovery contract only if feasibility evidence supports it.
- **Working-tree state at handoff:** clean after checkpoint.

## Decision gates

- **Integration:** blocked pending independent review and full lifecycle/consumer verification.
- **Activation:** prohibited; fixture only.
- **Promotion:** prohibited.

## Decision record

- 2026-09-25 — fixture-only inert reservation checkpoint; full clone safety explicitly not claimed.
