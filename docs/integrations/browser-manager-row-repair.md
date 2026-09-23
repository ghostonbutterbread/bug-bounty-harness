# Historical browser manager-row repair

- **Status:** local implementation; no live run, review, merge, push or activation
- **Owner/ref:** Hermes subagent, `fix/browser-manager-row-repair`
- **Worktree:** `/home/ryushe/projects/bug_bounty_harness/browser-manager-row-repair`
- **Base:** `8316e12` (`fix/browser-provisioner-insert`); ancestor beta `8e82041`; target `beta` only after INSERT fix integration
- **Intent:** reconstruct old physical-order shifted manager rows without touching live ownership, profiles or canonical leases.

## Contract and evidence

Read-only default for any program; apply restricted to explicit Blue, hash of fresh plan, terminal-owner attestation and private backup directory. Exact lease ID joins canonical fields (program/account/domain/agent/run/purpose/profile/unit). Manager launcher receipt must corroborate browser identity, program, account, run, agent, purpose and profile; canonical lease attests domain. Missing/conflicting evidence quarantines the row. Apply refuses the entire Blue cohort on ambiguity, active canonical lease, runtime uncertainty or changed plan. Manager node lock plus attached-DB `BEGIN IMMEDIATE` locks both SQLite writers; both DBs are backed up before mutation. Only manager semantic fields update. Receipt output contains counts, reason categories, hashed lease IDs and plan hash, not paths or private launcher fields.

Focused tests: `python -m pytest -q agents/test_browser_manager_row_repair.py agents/test_browser_provisioner.py` — **23 passed**. Historical 243-row fixture contains 22 Blue shifts and 221 other shifts. Tests cover active canonical lease, active unit, missing/conflicting receipt, idempotency, rollback, canonical state race and conditional manager-row race. Test-injected runtime probe represents a quiescent owner; it is **not** Hoster liveness evidence. `git diff --check` clean.

## Activation boundary and blocker

No Hoster access or mutation in this branch. The owner-visible Blue runtime must be independently verified terminal and launchers/watchers quiesced before any apply; a released lease alone does not prove process death. Actual apply checks inactive unit and watcher, terminal task owner and browser root, absent profile lock, unreachable loopback CDP, and refuses unavailable checks. SQLite locks cannot prevent an external systemd unit from starting after a probe: operational service quiescence is required for rollout. Missing task-owner metadata fails closed. Current known live Blue lease must be excluded; because apply is whole-cohort Blue, do not apply until it is terminal/released and independently verified. A Hoster read-only plan and manually examined quarantines are deferred until authorized rollout. Never copy/remove profiles or update canonical leases.

## Handoff

Owning branch `fix/browser-manager-row-repair`, base `8316e12`, target `beta` after parent fix; current tip is the recovery checkpoint after commit. Next: independent review and test rerun, then parent decides integration and separate Hoster read-only plan/owner quiescence gate. Feature branch remains isolated. No migration-feature worktree touched.
