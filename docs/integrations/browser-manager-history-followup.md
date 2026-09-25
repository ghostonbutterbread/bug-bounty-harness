# Browser manager terminal-history follow-up integration dossier

- **Status:** reviewed; live DB apply gated
- **Owner:** Hermes bugfix
- **Branch:** `fix/browser-manager-history-cleanup`
- **Base commit:** `3e5d2eb1b46c9989dee99c5dbc7c84e95bd092f6`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-24
- **Owning feature branch/ref:** `fix/browser-manager-history-cleanup`
- **Latest immutable recovery checkpoint:** `8d064763bde2183312af04452b141aff42441dc2`
- **Feature implementation commit(s):** `715f07c7ccf58ffaf1c8d037c4e019c355cc353c` (already beta), `a7e0fa75e5eb4977e37fcef6d1b7631289fefc4d`, `13373bb16d3846a7c5374e6ef7db9faa38ffb326`
- **Inspiration / canonical references:** Hoster read-only probe after first reviewed rollout.

## Intent

Unblock exact-cohort historical repair without relaxing quiescence: old unloaded user units print `inactive` but `systemctl is-active` exits 4, and ordinary idle-stopped legacy rows have `auth_domain='legacy-global'` while canonical lease has NULL. Keep active owner, mismatched service unit, missing fields, and ambiguous identities quarantined.

## Implemented contract

Use `systemctl --user show` and require ActiveState=inactive, LoadState loaded/not-found, MainPID=0, empty ControlGroup for both browser and owner units. Permit canonical NULL domain only for manager legacy-global while all other identity fields match. All existing plan-hash, DB lock, backup, process/CDP checks remain.

## Evidence and review

- Hoster read-only: 236 shifted (176 released/60 expired), 10 ordinary idle-stopped (8 expired/2 released). Cryptobox/Zooplus historical units returned `(exit 4, inactive)`; 9 of 10 idle rows have manager legacy-global/canonical NULL with matching service unit; one soundcloud service-unit conflict remains quarantined. Two active Neon browsers untouched.
- Tests: `python3 -m pytest agents/test_browser_manager_row_repair.py -q` → 21 passed; two matching legacy selection tests passed. The combined suite timed out near the end during local I/O stall; 70 tests passed before the follow-up.
- Independent review: first pass found a missing NULL-domain active-owner fence; regression added and narrow re-review approved, no blocker. Live apply not reviewed without per-cohort proof.

## Blockers and deferred work

- **Missing evidence:** final review, integrated tests, Hoster per-cohort runtime plans and independently verified owner inactivity before any apply.
- **Command / environment:** project `.venv/bin/python` read-only `--probe-runtime` plan; exact cohort `--apply` only after private backup and live owner check.
- **Trigger:** reviewed/published beta active on Hoster. Keep rows with active/unknown service or profile ownership quarantined.
- **Why:** expired canonical leases alone cannot prove termination.
- **Next:** review, integrate, deploy, per-cohort plan/apply, read back exact counts.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/browser-manager-history-cleanup`
- **Latest immutable recovery checkpoint:** `8d064763bde2183312af04452b141aff42441dc2`
- **Feature implementation commit(s):** `715f07c7ccf58ffaf1c8d037c4e019c355cc353c`, `a7e0fa75e5eb4977e37fcef6d1b7631289fefc4d`, `13373bb16d3846a7c5374e6ef7db9faa38ffb326`
- **Exact resume point:** merge reviewed follow-up into beta, activate Hoster, and perform per-cohort plan/verification.
- **Working-tree state at handoff:** clean after dossier-only decision commit.

## Decision gates

- **Integration:** narrow independent review and focused tests.
- **Activation/cohort:** exact runtime plan, quiescent owner, private two-DB backups and readback.
- **Stable promotion:** separate direction.

## Decision record

- 2026-09-24 — first reviewed repair published beta; read-only Hoster probe revealed two historical compatibility gaps, no DB writes.
- 2026-09-24 — re-review approved after NULL-domain active-owner regression; live DB remains untouched pending cohort evidence.
