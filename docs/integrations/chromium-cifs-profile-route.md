# Chromium network-profile routing integration dossier

- **Status:** corrective review (target-navigation gate addressed; final review pending)
- **Owner:** Hermes bugfix
- **Branch:** `fix/chromium-cifs-profile-route`
- **Base commit:** `ab22f670666bad995bcdcc0439ee48212d44ded9`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-13
- **Owning feature branch/ref:** `fix/chromium-cifs-profile-route`
- **Latest immutable recovery checkpoint:** `f59e754` (target-navigation gate; dossier handoff follows)
- **Feature implementation commit(s):** `3d02bc2`, `f59e754`
- **Inspiration / canonical references:** chromium-test browser provisioner, local/Hoster filesystem comparison, browser-runtime-operations.

## Intent

Prevent agents on the Hermes control host from placing live Chrome profiles on its CIFS `/mnt/bounty` mount, while leaving Hoster's local ext4 profile flow and GPU auto-selection intact. Do not copy or relabel named profiles, globally redirect artifacts, or bypass the provisioner.

## Implemented contract

The canonical Chromium Test skill checks the browser node's profile filesystem. On a network mount it prefers a local-filesystem browser node; for fresh task-owned disposable profiles it offers a per-request artifact-root override on a host-local filesystem. Named persistent profiles are routed to their exact local-profile host, normally Hoster. Existing provisioner, MITM CA, lease and exact cleanup gates remain. This is guidance, not an automatic code-level mount guard.

## Evidence and review

- Red policy test: `uv run --with pytest --with aiohttp --with httpx --with websocket-client --with pyyaml pytest -q agents/test_chromium_test_launcher.py -k routes_network_mount_profiles_without_gpu_workaround` failed before guidance addition.
- Green: full focused launcher suite 50 passed; `git diff --check` clean.
- Real local disposable proof preceding edit: `/mnt/bounty` CIFS runs failed; same provisioner with a local ext4 profile succeeded headless direct, headless task-MITM (trusted CA), and headed auto (`--use-angle=gl`). All exact leases released, task proxy finished, stopped test profiles removed.
- Independent review: first review blocked an absent-root `findmnt` call; correction and executed regression passed. Second review confirmed that correction but blocked target navigation before the final profile check and stale dossier fields. The guidance now starts at `about:blank` when final path is unverified, including named profiles, and requires checked local filesystem/CA before target navigation. Dossier reconciled to commit `3d02bc2`. Third review pending.
- Merge/ancestry: feature based on fetched `origin/beta` at base above; pending.

## Blockers and deferred work

- **Missing evidence:** fresh Hermes consumer load after beta integration and sync.
- **Trigger:** approved/reviewed beta merge and focused skill projection refresh.
- **Why:** feature text is not active merely because it exists in a worktree.
- **Next:** review, commit, integrate; verify live projection and fresh resolution.
- **Separate D01 work:** Hoster's ext4-backed provisioner did spawn a disposable `about:blank` browser with CDP HTTP 200 through a bounded user-systemd request; its exact lease was released and stopped task profile removed. A second Hoster task-MITM request failed before launch with `proxy-unavailable: no task MITM port available`. The exact `ai1` profile reports an expired manager-owned lease with no browser row; ordinary release returns `not-owner-or-missing`. Do not bypass either guard. The final PoC remains uninstalled/unverified; revisit after the scoped proxy pool and exact lease are reconciled through supported mechanisms.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/chromium-cifs-profile-route`
- **Latest immutable recovery checkpoint:** `f59e754` (target-navigation gate; dossier handoff follows)
- **Feature implementation commit(s):** `3d02bc2`, `f59e754`
- **Exact resume point:** third independent review of target-navigation gate, then beta integration if approved.
- **Working-tree state at handoff:** clean after this dossier-only handoff commit; reviewer must inspect branch tip as well as checkpoint.

## Decision gates

- **Integration gate:** independent review, focused tests, clean diff, beta reconciliation.
- **Activation gate:** focused runtime projection and fresh Hermes skill load.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-10-13 — scoped skill guidance added after local ext4 A/B and Hoster mount inspection.
