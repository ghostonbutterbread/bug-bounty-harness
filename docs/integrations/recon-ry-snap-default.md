# Recon-Ry snap default integration dossier

- **Status:** review-ready
- **Owner:** Hermes bugfix
- **Branch / owning ref:** `fix/recon-ry-snap-default`
- **Base commit:** `69aa9992526acb1ccfb93314022a4c7ea205afce` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-16
- **Latest immutable recovery checkpoint:** none yet; initial commit pending
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Ryushe request; Recon-Ry `config/profiles.yaml` snap preset; BBH `AGENTS.md` ownership boundary.

## Intent

Make ordinary BBH Recon-Ry broad launches choose reduced `snap`, not `full`, without changing Recon-Ry upstream profiles, exact-host queue, or active-scope safety boundaries.

## Implemented contract

`agents/recon_ry.py start` defaults to `snap` and sends `--profile snap` to Hoster. Explicit `--profile full` still works. Snap follows the same wildcard/root and scope-file guards as full. Recon-Ry, recon skill, and playbook show the new default and distinguish `/recon --mode full` from Recon-Ry's `full` profile. Snap remains active broad collection and does not authorize restricted origins/paths. No live target or Hoster job was launched.

## Evidence and review

- `python3 -m pytest -q tests/test_recon_ry_snap_default.py tests/test_skill_triage_routes.py tests/test_recon_ry_scope_files.py` → 19 passed.
- Recon-Ry local `config/profiles.yaml` includes snap (subdomain, URL, alive, IP, fingerprint, params, secret, ranking); `main.sh` accepts `--profile`.
- Independent review: pending.
- Merge/ancestry: feature based on fetched `origin/beta` tip above; no integration yet.

## Blockers and deferred work

- No current blocker. Hoster runtime activation/read-back is separate from beta publication; verify installed Recon-Ry snap preset and BBH projection before calling it active there.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/recon-ry-snap-default`
- **Latest immutable recovery checkpoint:** pending initial commit
- **Exact resume point:** commit, independent review, reconcile/integrate to beta, verify consumer activation.
- **Working-tree state at handoff:** task-owned edits pending commit.

## Decision gates

- **Integration gate:** independent review and focused tests on integrated beta tree.
- **Activation gate:** verify real consumer skill and wrapper resolve to beta; no live recon launch needed.
- **Promotion gate:** stable/main remains unchanged unless separately approved.

## Decision record

- 2026-10-16 — implemented default change and mirrored full-profile safety guards; focused offline checks green; pending independent review.
