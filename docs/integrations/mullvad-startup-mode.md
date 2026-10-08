# Mullvad startup-mode integration dossier

- **Status:** feature
- **Owner:** Hermes / BBH Kanban `t_fca6dd78`
- **Branch:** `docs/mullvad-startup-mode`
- **Base commit:** `4e005929127d05785e704847bc80486cbd0c6297`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-08
- **Owning feature branch/ref:** `docs/mullvad-startup-mode`
- **Latest immutable recovery checkpoint:** `687eaccad3688983d171dd99131f266ec167a6f1`
- **Feature implementation commit(s):** `92b422c2d2f661d2a949d05c2c04a36914bec551`, `687eaccad3688983d171dd99131f266ec167a6f1`
- **Canonical references:** `skills/mullvad/SKILL.md`, `prompts/mullvad-playbook.md`; official Tailscale `tailscaled` and CLI docs and Mullvad CLI auto-connect documentation.

## Intent

Address the boot-time split-owner ambiguity: selecting a Tailscale Mullvad exit is insufficient if the Tailscale daemon does not start after boot or the standalone Mullvad auto-connect reclaims traffic. In standalone mode, the daemon auto-connect must instead be on. The GUI preference is independently managed. Do not change the approved West Coast restriction, auth/lockdown/privacy controls, or live host routes in this docs change.

## Implemented contract

- Tailscale mode: enabled/active installed startup owner; authenticated client; one specific listed West Coast Mullvad exit preference, validated on actual internet egress; Mullvad daemon and GUI auto-connect off, standalone disconnected.
- Standalone mode: Tailscale exit cleared/verified; Mullvad daemon auto-connect on; actual connected West Coast relay and internet egress verified. Tailnet peer connectivity may remain.
- Post-boot verification before scoped traffic. A service-enabled flag or saved exit preference is not proof that the relay is reachable, nor a kill switch for boot-time traffic.
- Handoff still requires control/recovery. Ryu authorized an immediate live attempt despite Hoster workload activity; both routes remain on standalone Mullvad after rollback. No host system service was changed.

## Evidence and review

- Tests and commands: `git diff --check`; focused 15 skill/playbook startup assertions; local CLI `tailscale set --help`, `mullvad auto-connect --help`; read-only systemd checks on Ghost and Hoster (both tailscaled enabled/active; standalone Mullvad still connected, daemon auto-connect on; no Tailscale exit selected).
- Independent review: changes requested at `45b81fa39b3b255ca51207340fbc6a28fd195d7d` (fallback auto-connect conflict and stale dossier tense); narrow re-review of `687eaccad3688983d171dd99131f266ec167a6f1` confirmed the behavior fix and requested only this dossier checkpoint correction. Final dossier-only re-review pending.
- Live reboot/exit-node evidence: deferred; do not reboot active hosts just for proof.
- Merge/ancestry evidence: implementation commit and base checked before review; this branch-local dossier is planned for exclusion from the beta merge.

## Blockers and deferred work

- **Missing test or evidence:** neither host has a Tailscale exit selected or post-boot egress proof. Ghost's non-root `tailscale set` was denied; on Hoster `mullvad disconnect` hung while the daemon logged `Resetting DNS`. Both hosts were restored to standalone Mullvad with daemon auto-connect on. Hoster direct-IP HTTPS still traversed Mullvad, but hostname DNS lookup failed after the attempt. Mullvad GUI Auto-connect is not verified on either host.
- **Command / fixture / environment needed:** operator permission for Ghost's Tailscale CLI, Hoster Mullvad daemon/DNS repair, per-host GUI check, live exit selection with control/recovery, `tailscale get exit-node`, `mullvad status`, public IP/Mullvad JSON, then post-boot checks at a scheduled restart.
- **Trigger to run it:** owner resolves Ghost privilege and Hoster daemon/DNS blockers; then safe per-host handoff and later normal reboot/restart.
- **Why it blocks activation, not docs integration:** live routing may interrupt active sessions or leak ISP traffic; docs can be reviewed/merged without changing routes.
- **Next completion step / successor reference:** after docs review/integration, carry forward existing Kanban `t_fca6dd78` for the live host handoff.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/mullvad-startup-mode`
- **Latest immutable recovery checkpoint:** `687eaccad3688983d171dd99131f266ec167a6f1`
- **Feature implementation commit(s):** `92b422c2d2f661d2a949d05c2c04a36914bec551`, `687eaccad3688983d171dd99131f266ec167a6f1`
- **Exact resume point:** validate the exact diff against adjacent owner guidance; independent review; beta merge excluding this dossier; verify projections on both hosts.
- **Working-tree state at handoff:** implementation commits `92b422c` and `687eacc` are committed; the branch-local dossier was first committed at `45b81fa` and corrected in the current dossier-only checkpoint. No skill/playbook edits remain uncommitted.

## Decision gates

- **Integration gate:** focused checks and independent review; merge to beta only after approval, retire this dossier on merge.
- **Activation / cohort gate:** operator-safe GUI and workload preflight, per-host service/exit/egress evidence; no automatic reboot or Hoster switch merely from docs integration.
- **Promotion gate:** no main promotion requested.

## Decision record

- 2026-10-08 — Ryu requested Tailscale startup and mode-specific Mullvad auto-connect rule; authored canonical skill/playbook branch from beta. A later live handoff attempt was rolled back; both hosts remain on standalone Mullvad pending privilege and daemon/DNS repair.
