# Tailscale Mullvad exits integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `docs/tailscale-mullvad-exit-nodes`
- **Base commit:** `adcaedc0d2ee5cb6f96522a60d0e30ed9e143543`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-08
- **Owning feature branch/ref:** `docs/tailscale-mullvad-exit-nodes`
- **Latest immutable recovery checkpoint:** `e0ebdac6954b4d239e9423e0e4da992883eeee38`
- **Feature implementation commit(s):** `6894c9ba46ee8c4ba50a3764cf9c9caed2fbc7b7`, `e0ebdac6954b4d239e9423e0e4da992883eeee38`
- **Inspiration / canonical references:** Ryushe's Discord thread 1557863033424977999; Tailscale Mullvad exit-node and CLI documentation; Mullvad connection-check API.

## Intent

Replace the standalone Mullvad relay-rotation instructions with Tailscale's Mullvad add-on, preserving West Coast routing, public egress verification, and existing scoped-testing guardrails. This does not change host VPN state or other scripts.

## Implemented contract

The skill and playbook use `tailscale exit-node list --filter=USA` to discover live West Coast hosts, `tailscale set --exit-node=<host>` to select/rotate, `tailscale get exit-node` and public IP/Mullvad checks to verify. One-time standalone VPN migration is distinct from subsequent rotations and requires operator recovery access where disconnecting may interrupt control or expose ISP egress. No automatic unverified fallback.

## Evidence and review

- Tests and commands: read-only local CLI checks with `tailscale set --help`, `tailscale exit-node list --filter=USA`, `tailscale get exit-node`, `mullvad status`, `mullvad lockdown-mode get`, `mullvad auto-connect get`, `curl -4fsS --max-time 10 https://ip.me`, and `curl -4fsS --max-time 10 https://am.i.mullvad.net/json`; `git diff --check` passed. Manual static inspection confirmed the new selector, hostname match, startup policy and rollback; no durable automated assertion suite was added.
- Independent review: first review requested egress proof, auto-connect, and dossier corrections. Re-review confirmed behavior but asked to remove an untraceable numerical test claim. Narrow final re-review approved `8842cee` after that correction, found clean worktree and `git diff --check` pass.
- Replay/cohort/fixture evidence: live routing switch deliberately not exercised; existing standalone Mullvad tunnel remains connected.
- Merge/ancestry evidence: fetched `origin/beta` at `adcaedc0`; reviewed feature tip `8842cee` is based on that commit; beta integration pending.

## Blockers and deferred work

- **Missing test or evidence:** live one-time handoff and subsequent Tailscale exit rotation.
- **Command / fixture / environment needed:** operator access to host and planned pause of target traffic; inspect/agree on `mullvad auto-connect get`, then `mullvad disconnect`, `tailscale set --exit-node=<listed-host>`, check standalone status, public IPv4, and matching Mullvad exit hostname.
- **Trigger to run it:** Ryushe schedules a migration window with recovery access.
- **Why it blocks integration, activation, or promotion:** does not block documentation integration; blocks claiming that the live host is using a Tailscale-managed exit.
- **Next completion step / successor reference:** perform planned switch and verify egress on each intended host.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/tailscale-mullvad-exit-nodes`
- **Latest immutable recovery checkpoint:** `e0ebdac6954b4d239e9423e0e4da992883eeee38`
- **Feature implementation commit(s):** `6894c9ba46ee8c4ba50a3764cf9c9caed2fbc7b7`, `e0ebdac6954b4d239e9423e0e4da992883eeee38`
- **Exact resume point:** obtain independent re-review, merge to beta, verify live projection; do not switch VPN without recovery path.
- **Working-tree state at handoff:** clean after dossier-only commit; live VPN unchanged.

## Decision gates

- **Integration gate:** passed static/document checks and independent review; merge approved for `beta`.
- **Activation / cohort gate:** beta skill projection verified separately; live VPN handoff deferred.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-10-08 — Created feature branch at fetched beta; committed the skill, playbook, and this dossier as `6894c9b`. Independent review requested three corrections; applied in `e0ebdac` and committed dossier in `0885502`.
- 2026-10-08 — Removed an untraceable numerical test claim in `8842cee`; independent narrow re-review approved the reviewed tip. Merge into `beta` with dossier removed from integration, then verify runtime projection; live VPN migration remains deferred.
