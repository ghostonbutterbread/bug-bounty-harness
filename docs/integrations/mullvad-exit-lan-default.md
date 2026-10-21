# Tailscale exit LAN default integration dossier

- **Status:** review-ready
- **Owner:** Hermes bugfix
- **Branch:** `docs/mullvad-exit-lan-default`
- **Base commit:** `d7f3fda`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-21
- **Owning feature branch/ref:** `docs/mullvad-exit-lan-default`
- **Latest immutable recovery checkpoint:** `28959ee`
- **Feature implementation commit(s):** `28959ee`
- **Inspiration / canonical references:** Ryu's request; Tailscale exit-node setup documentation; Tailscale issue 9413 on networkd route loss.

## Intent

Default to LAN access whenever a Tailscale exit node is selected unless Ryu explicitly opts a host out. Keep exit-node, DNS, and remote-control safety requirements intact. Do not conflate saved LAN preference with the actual route.

## Implemented contract

The Mullvad skill and playbook set the LAN preference before first exit selection, with a copyable default-true command allowing an explicit false exception. Rotation and boot checks verify effective LAN return route and independent LAN SSH, and diagnose missing table-52 throw routes. No network-service restart or route write on Hoster is part of this branch.

## Evidence and review

- Tests and commands: `git diff --check`; assertions for LAN default, host exception, table-52 route diagnosis; review the copyable commands.
- Independent review: `deleg_8e2bf18d` found first-handoff/default exception inconsistencies and missing table-52 diagnosis; corrected and final diff inspected. Focused contract check passed.
- Replay/cohort/fixture evidence: Hoster saved pref `true`, `tailscale set --exit-node-allow-lan-access=true` returned 0, `ip -4 route get 10.0.0.11` still selected `tailscale0 table 52`.
- Merge/ancestry evidence: Feature begins at fetched `origin/beta` `d7f3fda`.

## Blockers and deferred work

- **Missing test or evidence:** Hoster restored LAN SSH after networkd restart or reboot.
- **Command / fixture / environment needed:** Privileged out-of-band session; inspect `ip -4 route show table 52`, `ip -4 route get 10.0.0.11`; independent LAN SSH; diagnose networkd foreign-route management before choosing durable repair.
- **Trigger to run it:** Operator provides an independent recovery path and privileged access, or performs the controlled host repair locally.
- **Why it blocks integration, activation, or promotion:** Does not block documentation integration; blocks claiming Hoster LAN repair.
- **Next completion step / successor reference:** Kanban `t_83b8ad2d` tracks runtime repair separately.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/mullvad-exit-lan-default`
- **Latest immutable recovery checkpoint:** `28959ee`
- **Feature implementation commit(s):** `28959ee`
- **Exact resume point:** Merge reviewed feature into beta, remove dossier from integration tree, verify runtime projection.
- **Working-tree state at handoff:** clean after dossier decision commit.

## Decision gates

- **Integration gate:** Accepted: review findings addressed; focused check passed and final diff inspected.
- **Activation / cohort gate:** Confirm published beta and selected runtime projection; existing agents may retain old skill text.
- **Promotion gate:** No stable promotion requested.

## Decision record

- 2026-10-21 — Accepted for beta after independent review corrections; Hoster route repair intentionally separate.
