# Mullvad validated-routing documentation integration dossier

- **Status:** re-review required after first independent review blocker; not integrated or activated
- **Owner:** Hermes / Kanban t_38097d65
- **Branch:** `docs/mullvad-validated-routing`
- **Base commit:** `866523ceea889bf2560c22af6c09b88692baebd2` (`origin/beta` at creation)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-08
- **Owning feature branch/ref:** `docs/mullvad-validated-routing`
- **Latest immutable recovery checkpoint:** `f1f23f6778acfdca15861280589e65067edc672c`
- **Feature implementation commit(s):** `f489b728bcc2a6a5186c2233cc713b3195eaf97f`, `f1f23f6778acfdca15861280589e65067edc672c`
- **Inspiration / canonical references:** Kanban parent t_aaff5b3b, attachment `routing-model-validation.md`; existing beta Mullvad docs; Tailscale exit-node, Mullvad exit-node and CLI official docs.

## Intent

Close the gap between beta's existing Tailscale-first/standalone-fallback prose and the read-only host validation: preflight privilege, routes, DNS, remote control and workload checks, manual fallback boundary, and unresolved operational decisions. No live network changes or automatic failover implementation.

## Implemented contract

`skills/mullvad/SKILL.md` points to the fuller `prompts/mullvad-playbook.md` gate. The playbook records a remote preflight, command-based post-switch route/DNS checks, explicit rollback and snapshot-specific Ghost/Hoster blockers. Tailscale is still preferred only with an authorized, listed WA/OR/CA Mullvad exit; standalone Mullvad remains a deliberately switched fallback with no Tailscale exit selected. Startup/auto-connect and region restrictions in beta are unchanged. The guide does not claim fail-closed startup, automatic fallback, DNS leak prevention, or that either host has been migrated.

## Evidence and review

- Tests and commands: `python3 ../check_mullvad_docs.py` passed 14 focused contract assertions; `git diff --check` and staged diff check passed; `git diff --stat` inspected for the two docs and dossier. The test script is scratch-only and not part of the feature commit.
- Independent review: first read-only review found that pre-switch LAN SSH could be mistaken for a recovery path surviving exit selection. The playbook/skill now require an out-of-band console or control/rollback proven with the selected exit, and explicitly stop on LAN SSH as sole pre-switch control. Re-review of the corrected tip is pending.
- Replay/cohort/fixture evidence: parent read-only report; no privileged network tests in this docs task.
- Merge/ancestry evidence: feature based on current fetched `origin/beta` above; integration not performed.

## Blockers and deferred work

- **Missing test or evidence:** actual preferred exit, DNS/IPv6, remote access, per-workload and failover/reboot checks on Ghost/Hoster. **Command / environment:** playbook preflight and post-switch commands with independent local control; operators on each host. **Trigger:** Ghost privilege grant; Hoster DNS/daemon repair, workload-safe window and tested console/LAN rollback. **Why:** beta documentation is not production migration evidence. **Next:** migration cards t_f2049d6a and t_59ecffbc.
- **Decisions requiring review:** whether LAN access is enabled with possible LAN DNS exposure; whether to design automatic fallback or OS-enforced fail-closed behavior (requires separate failure-injection verification). Preserve lockdown and current manager until explicit decision.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/mullvad-validated-routing`
- **Latest immutable recovery checkpoint:** `f1f23f6778acfdca15861280589e65067edc672c`
- **Feature implementation commit(s):** `f489b728bcc2a6a5186c2233cc713b3195eaf97f`, `f1f23f6778acfdca15861280589e65067edc672c`; the tip after this dossier-only handoff commit is later.
- **Exact resume point:** independently review the committed diff against `origin/beta`; integrate into a clean current beta only after acceptance and remove this dossier from integration target.
- **Working-tree state at handoff:** clean after the dossier-only checkpoint commit.

## Decision gates

- **Integration gate:** diff and focused checks pass; independent review of exact feature tip; clean current beta merge, removing dossier from target.
- **Activation / cohort gate:** network state change is out of scope; operators must satisfy each host's preflight and verify actual paths.
- **Promotion gate:** no main promotion requested.

## Decision record

- 2026-10-08 — Created docs refinement from reviewed beta; first independent review identified LAN-only control gap; revised preflight to require independent recovery and post-selection verification in correction `f1f23f6778acfdca15861280589e65067edc672c`. No production change.
