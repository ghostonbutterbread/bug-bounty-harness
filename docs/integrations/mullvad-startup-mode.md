# Mullvad startup-mode integration dossier

- **Status:** feature
- **Owner:** Hermes / BBH Kanban `t_fca6dd78`
- **Branch:** `docs/mullvad-startup-mode`
- **Base commit:** `4e005929127d05785e704847bc80486cbd0c6297`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-08
- **Owning feature branch/ref:** `docs/mullvad-startup-mode`
- **Latest immutable recovery checkpoint:** `92b422c2d2f661d2a949d05c2c04a36914bec551`
- **Feature implementation commit(s):** `92b422c2d2f661d2a949d05c2c04a36914bec551`
- **Canonical references:** `skills/mullvad/SKILL.md`, `prompts/mullvad-playbook.md`; official Tailscale `tailscaled` and CLI docs and Mullvad CLI auto-connect documentation.

## Intent

Address the boot-time split-owner ambiguity: selecting a Tailscale Mullvad exit is insufficient if the Tailscale daemon does not start after boot or the standalone Mullvad auto-connect reclaims traffic. In standalone mode, the daemon auto-connect must instead be on. The GUI preference is independently managed. Do not change the approved West Coast restriction, auth/lockdown/privacy controls, or live host routes in this docs change.

## Implemented contract

- Tailscale mode: enabled/active installed startup owner; authenticated client; one specific listed West Coast Mullvad exit preference, validated on actual internet egress; Mullvad daemon and GUI auto-connect off, standalone disconnected.
- Standalone mode: Tailscale exit cleared/verified; Mullvad daemon auto-connect on; actual connected West Coast relay and internet egress verified. Tailnet peer connectivity may remain.
- Post-boot verification before scoped traffic. A service-enabled flag or saved exit preference is not proof that the relay is reachable, nor a kill switch for boot-time traffic.
- Handoff still requires control/recovery and Hoster workload disposition. No live VPN switches or system service changes performed for this branch.

## Evidence and review

- Tests and commands: `git diff --check`; focused 15 skill/playbook startup assertions; local CLI `tailscale set --help`, `mullvad auto-connect --help`; read-only systemd checks on Ghost and Hoster (both tailscaled enabled/active; standalone Mullvad still connected, daemon auto-connect on; no Tailscale exit selected).
- Independent review: pending.
- Live reboot/exit-node evidence: deferred; do not reboot active hosts just for proof.
- Merge/ancestry evidence: implementation commit and base checked before review; dossier not included in beta merge.

## Blockers and deferred work

- **Missing test or evidence:** neither host has a Tailscale exit selected or post-boot egress proof. Mullvad GUI Auto-connect is not verified on either host. Hoster has active browser/MITM/agent work.
- **Command / fixture / environment needed:** per-host GUI check, live exit selection with control/recovery, `tailscale get exit-node`, `mullvad status`, `curl -4 https://ip.me` and Mullvad JSON, then post-boot checks at a scheduled restart.
- **Trigger to run it:** operator-dispositioned Hoster workload window and safe per-host handoff; later normal reboot/restart.
- **Why it blocks activation, not docs integration:** live routing may interrupt active sessions or leak ISP traffic; docs can be reviewed/merged without changing routes.
- **Next completion step / successor reference:** after docs review/integration, carry forward existing Kanban `t_fca6dd78` for the live host handoff.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/mullvad-startup-mode`
- **Latest immutable recovery checkpoint:** `92b422c2d2f661d2a949d05c2c04a36914bec551`
- **Feature implementation commit(s):** `92b422c2d2f661d2a949d05c2c04a36914bec551`
- **Exact resume point:** validate the exact diff against adjacent owner guidance; independent review; beta merge excluding this dossier; verify projections on both hosts.
- **Working-tree state at handoff:** the implementation is committed; dossier will be committed separately.

## Decision gates

- **Integration gate:** focused checks and independent review; merge to beta only after approval, retire this dossier on merge.
- **Activation / cohort gate:** operator-safe GUI and workload preflight, per-host service/exit/egress evidence; no automatic reboot or Hoster switch merely from docs integration.
- **Promotion gate:** no main promotion requested.

## Decision record

- 2026-10-08 — Ryu requested Tailscale startup and mode-specific Mullvad auto-connect rule; authored canonical skill/playbook branch from beta. Live routes deliberately unchanged.
