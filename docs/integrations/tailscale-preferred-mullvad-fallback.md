# Tailscale-preferred Mullvad fallback integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `docs/tailscale-preferred-mullvad-fallback`
- **Base commit:** `da20bb7cfc37728d01467410a8827188b5044f71`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-08
- **Owning feature branch/ref:** `docs/tailscale-preferred-mullvad-fallback`
- **Latest immutable recovery checkpoint:** `3d504547aa06fce3f643f43bfdb2763bab0a8d5f`
- **Feature implementation commit(s):** `eea5ae2bf95b7d6e610c28e276fdb1078c0ea735`, `3d504547aa06fce3f643f43bfdb2763bab0a8d5f`
- **Inspiration / canonical references:** Ryushe Discord request 1557872090361765991; Tailscale official Mullvad exit and exit-node docs; live Tailscale/Mullvad CLI help and host preflights.

## Intent

Prefer a Tailscale-selected West Coast Mullvad exit per host; keep standalone Mullvad CLI as a verified fallback when Tailscale is unavailable or unauthorized. Explain the traffic flow with a compact diagram. Avoid a gap in verification and do not silently disrupt active workloads.

## Implemented contract

The skill and playbook distinguish tailnet connectivity from internet exit routing, select one manager per host, document planned CLI-to-Tailscale handoff and rollback, and permit standalone CLI West Coast relay selection when a Tailscale Mullvad exit is unavailable. Public IP and Mullvad JSON verification apply to both paths; Tailscale path additionally requires the standalone tunnel disconnected and matching exit hostname.

## Evidence and review

- Tests and commands: local and Hoster read-only `tailscale status`, `tailscale get exit-node`, `tailscale exit-node list --filter=USA`, `mullvad status -v`, `mullvad auto-connect get`, `mullvad lockdown-mode get`, plus official docs and local `mullvad relay set location --help`. Ad-hoc source checks for manager selection, fallback, verification, diagram and rollback passed; review-fix source checks and `git diff --check` passed. No durable automated suite added.
- Independent review: initial review requested GUI Auto-connect handling/approval, fail-closed inaccessible-Tailscale fallback, verbose connected relay proof, dossier consistency, and removal of an incorrect MagicDNS prerequisite. Corrections in `3d50454`; narrow re-review approved clean tip `562866f` with no remaining blockers.
- Live host state: both hosts currently standalone Mullvad connected; Tailscale online but no exit selected. Hoster shows active browser/agent/proxy processes despite initial assumption of no active agents. A request for operator decisions on auto-connect and Hoster disruption received no response; no live VPN change authorized at this time.
- Merge/ancestry evidence: `origin/beta` last fetched at `da20bb7`; merge pending.

## Blockers and deferred work

- **Missing test or evidence:** live manager migration and public egress verification on Ghost and Hoster.
- **Command / fixture / environment needed:** controlled `mullvad disconnect` then `tailscale set --exit-node=<listed-host>`; check standalone disconnected, selected node, IPv4/IPv6 and Mullvad JSON, with rollback.
- **Trigger to run it:** Ryushe explicitly decides the daemon/GUI Auto-connect changes and selects a Hoster workload-disruption window; verify remote control/recovery per host.
- **Why it blocks integration, activation, or promotion:** does not block the reviewed skill integration or Hoster skill projection; blocks claiming either host uses a Tailscale Mullvad exit.
- **Next completion step / successor reference:** merge/publish skill and verify local/Hoster projections; leave VPN migration as a separate operator-approved action.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/tailscale-preferred-mullvad-fallback`
- **Latest immutable recovery checkpoint:** `3d504547aa06fce3f643f43bfdb2763bab0a8d5f`
- **Feature implementation commit(s):** `eea5ae2bf95b7d6e610c28e276fdb1078c0ea735`, `3d504547aa06fce3f643f43bfdb2763bab0a8d5f`
- **Exact resume point:** narrow independent re-review of `3d50454` and dossier, then merge and runtime projection; per-host migration only after operator decision and safe workload/control-plane window.
- **Working-tree state at handoff:** clean after this dossier commit; implementation commits reachable.

## Decision gates

- **Integration gate:** independent review approved `562866f`; merge to `beta` with temporary dossier retired.
- **Activation / cohort gate:** verify runtime skill projection on both hosts separately; live VPN migration is deferred for owner decision and safe Hoster window.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-10-08 — Began from fetched beta; Hoster workload assumption contradicted by active browser and task MITM services, so no Hoster route switch until assessed.
- 2026-10-08 — Committed skill/playbook/dossier in `eea5ae2`; independent review requested four safety and accuracy corrections. Corrected in `3d50454`, updated dossier in `562866f`; narrow review approved.
- 2026-10-08 — No response to operator decision request on auto-connect or Hoster disruption. Integrate reviewed guidance, but do not claim live routing switched; record the per-host migration as blocked.
