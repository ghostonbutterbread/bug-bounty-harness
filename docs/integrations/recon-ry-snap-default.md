# Recon-Ry snap default integration dossier

- **Status:** review-ready
- **Owner:** Hermes bugfix
- **Branch / owning ref:** `fix/recon-ry-snap-default`
- **Base commit:** `69aa9992526acb1ccfb93314022a4c7ea205afce` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-16
- **Latest immutable recovery checkpoint:** `6c67e12f50eaa07da77788688acce218fda481b0`
- **Feature implementation commit(s):** `6c67e12f50eaa07da77788688acce218fda481b0`
- **Inspiration / canonical references:** Ryushe request; Recon-Ry `config/profiles.yaml` snap preset; BBH `AGENTS.md` ownership boundary.

## Intent

Make ordinary BBH Recon-Ry broad launches choose reduced `snap`, not `full`, without changing Recon-Ry upstream profiles, exact-host queue, or active-scope safety boundaries.

## Implemented contract

`agents/recon_ry.py start` defaults to `snap` and sends `--profile snap` to Hoster. Explicit `--profile full` still works. Snap follows the same wildcard/root and scope-file guards as full. Recon-Ry, recon skill, and playbook show the new default and distinguish `/recon --mode full` from Recon-Ry's `full` profile. Snap remains active broad collection and does not authorize restricted origins/paths. No live target or Hoster job was launched.

## Evidence and review

- `python3 -m pytest -q tests/test_recon_ry_snap_default.py tests/test_skill_triage_routes.py tests/test_recon_ry_scope_files.py tests/test_full_recon.py tests/test_recon_docs.py` → 27 passed after review follow-up.
- Recon-Ry local `config/profiles.yaml` includes snap (subdomain, URL, alive, IP, fingerprint, params, secret, ranking); `main.sh` accepts `--profile`.
- Independent review: approved behavior and guards; requested registry/playbook alignment and current dossier receipt, now addressed. Focused reviewer checks: 19 passed. Excluded-wildcard regression covered in follow-up.
- Merge/ancestry: feature based on fetched `origin/beta` tip above; no integration yet.

## Blockers and deferred work

- No current blocker. Hoster runtime activation/read-back is separate from beta publication; verify installed Recon-Ry snap preset and BBH projection before calling it active there.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/recon-ry-snap-default`
- **Latest immutable recovery checkpoint:** `6c67e12f50eaa07da77788688acce218fda481b0`
- **Feature implementation commit(s):** `6c67e12f50eaa07da77788688acce218fda481b0`
- **Exact resume point:** reconcile/integrate to beta, verify consumer activation.
- **Working-tree state at handoff:** clean after follow-up commit.

## Decision gates

- **Integration gate:** independent review and focused tests on integrated beta tree.
- **Activation gate:** verify real consumer skill and wrapper resolve to beta; no live recon launch needed.
- **Promotion gate:** stable/main remains unchanged unless separately approved.

## Decision record

- 2026-10-16 — independent review accepted code behavior; requested registry/playbook/dossier alignment. Follow-up addressed those items and tested excluded-wildcard rejection (27 focused tests green). Integration approved; Hoster activation remains separate.
