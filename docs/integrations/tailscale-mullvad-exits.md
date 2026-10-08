# Tailscale Mullvad exits integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `docs/tailscale-mullvad-exit-nodes`
- **Base commit:** `adcaedc0d2ee5cb6f96522a60d0e30ed9e143543`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-08
- **Owning feature branch/ref:** `docs/tailscale-mullvad-exit-nodes`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Ryushe's Discord thread 1557863033424977999; Tailscale Mullvad exit-node and CLI documentation; Mullvad connection-check API.

## Intent

Replace the standalone Mullvad relay-rotation instructions with Tailscale's Mullvad add-on, preserving West Coast routing, public egress verification, and existing scoped-testing guardrails. This does not change host VPN state or other scripts.

## Implemented contract

The skill and playbook use `tailscale exit-node list --filter=USA` to discover live West Coast hosts, `tailscale set --exit-node=<host>` to select/rotate, `tailscale get exit-node` and public IP/Mullvad checks to verify. One-time standalone VPN migration is distinct from subsequent rotations and requires operator recovery access where disconnecting may interrupt control or expose ISP egress. No automatic unverified fallback.

## Evidence and review

- Tests and commands: local `tailscale set --help`, `tailscale exit-node list --filter=USA`, `tailscale get exit-node`, `mullvad status`, `mullvad lockdown-mode get`, `curl -4 https://ip.me`, and Mullvad JSON check read-only; static assertions for both documents passed (7/7) and `git diff --check` passed. Independent diff review pending.
- Independent review: pending.
- Replay/cohort/fixture evidence: live routing switch deliberately not exercised; existing standalone Mullvad tunnel remains connected.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- **Missing test or evidence:** live one-time handoff and subsequent Tailscale exit rotation.
- **Command / fixture / environment needed:** operator access to host and planned pause of target traffic; `mullvad disconnect`, `tailscale set --exit-node=<listed-host>`, public IPv4/Mullvad check.
- **Trigger to run it:** Ryushe schedules a migration window with recovery access.
- **Why it blocks integration, activation, or promotion:** does not block documentation integration; blocks claiming that the live host is using a Tailscale-managed exit.
- **Next completion step / successor reference:** perform planned switch and verify egress on each intended host.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/tailscale-mullvad-exit-nodes`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** run static checks, independent review, merge to beta, verify live projection; do not switch VPN without recovery path.
- **Working-tree state at handoff:** intentionally uncommitted until first verification.

## Decision gates

- **Integration gate:** static checks and independent review.
- **Activation / cohort gate:** beta skill projection verified separately; live VPN handoff deferred.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-10-08 — Created feature branch at fetched beta and updated the skill/playbook only.
