# Mullvad validated-routing documentation integration dossier

- **Status:** final discrepancy/DNS-reset correction pending independent re-review; not integrated or activated by this task
- **Owner:** Hermes / Kanban t_38097d65
- **Branch:** `docs/mullvad-validated-routing`
- **Base commit:** `866523ceea889bf2560c22af6c09b88692baebd2` (`origin/beta` at creation)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-08
- **Owning feature branch/ref:** `docs/mullvad-validated-routing`
- **Latest immutable recovery checkpoint:** `bd14e713b4178fe4b8af34a7e99f13db7245f124`
- **Feature implementation commit(s):** `f489b728bcc2a6a5186c2233cc713b3195eaf97f`, `f1f23f6778acfdca15861280589e65067edc672c`, `cc7903a014e027a90725bdaacd5a593e016fe678`, `bd14e713b4178fe4b8af34a7e99f13db7245f124`
- **Inspiration / canonical references:** Kanban parent t_aaff5b3b, attachment `routing-model-validation.md`; existing beta Mullvad docs; Tailscale exit-node, Mullvad exit-node and CLI official docs.

## Intent

Close the gap between beta's existing Tailscale-first/standalone-fallback prose and the read-only host validation: preflight privilege, routes, DNS, remote control and workload checks, manual fallback boundary, and unresolved operational decisions. No live network changes or automatic failover implementation.

## Implemented contract

`skills/mullvad/SKILL.md` points to the fuller `prompts/mullvad-playbook.md` gate. The playbook records a remote preflight, post-switch route/DNS checks, rollback that reconciles saved/effective exit state, and dated Ghost/Hoster observations. It warns not to timeout/kill a slow Mullvad disconnect during DNS reset, requires operator-coordinated recovery with DNS/egress verification, and selects an exact live-listed West Coast exit instead of a fixed Seattle relay. Standalone remains a deliberate verified fallback with no Tailscale exit selected. Neither fail-closed startup, automatic fallback, DNS leak prevention nor completed host migration is claimed.

## Evidence and review

- Tests and commands: `python3 ../check_mullvad_docs.py` passed 20 focused contract assertions on `bd14e713b4178fe4b8af34a7e99f13db7245f124`; `git diff --check` and staged diff check passed. The test script is scratch-only and not part of the feature commit.
- Independent review: the early review found LAN-only control insufficient; the revised gate requires independent recovery. A later read-only review found rollback trusted only `tailscale get exit-node` despite Hoster's saved-versus-effective discrepancy and flagged stale dossier claims. `bd14e713b4178fe4b8af34a7e99f13db7245f124` adds the saved/effective/status/route gate and corrects the DNS-reset and dynamic exit guidance; it needs exact-head re-review. This dossier updates the stale Hoster claim.
- Replay/cohort/fixture evidence: parent read-only report; no privileged network tests in this docs task.
- Merge/ancestry evidence: feature based on current fetched `origin/beta` above; integration not performed.

## Blockers and deferred work

- **Missing test or evidence:** controlled preferred exit, DNS/IPv6, remote access, per-workload and failover/reboot checks on both hosts. **Command / environment:** playbook preflight and post-switch checks from independent local control. **Trigger:** recheck Ghost privilege; recheck Hoster's later reported Tailscale Seattle egress and repaired DNS, reconcile Mullvad daemon auto-connect still on, obtain a workload-safe window and tested rollback. **Why:** a read-only Hoster check is not a completed migration/failover test. **Next:** migration cards t_f2049d6a and t_59ecffbc.
- **Decisions requiring review:** whether LAN access is enabled with possible LAN DNS exposure; whether to design automatic fallback or OS-enforced fail-closed behavior (requires separate failure-injection verification). Preserve lockdown and current manager until explicit decision.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/mullvad-validated-routing`
- **Latest immutable recovery checkpoint:** `bd14e713b4178fe4b8af34a7e99f13db7245f124`
- **Feature implementation commit(s):** `f489b728bcc2a6a5186c2233cc713b3195eaf97f`, `f1f23f6778acfdca15861280589e65067edc672c`, `cc7903a014e027a90725bdaacd5a593e016fe678`, `bd14e713b4178fe4b8af34a7e99f13db7245f124`; the tip after this dossier-only handoff commit is later.
- **Exact resume point:** independently re-review the corrected rollback/DNS-reset wording at `bd14e713b4178fe4b8af34a7e99f13db7245f124` against fetched `origin/beta`; integrate into a clean current beta only after acceptance and remove this dossier from integration target.
- **Working-tree state at handoff:** clean after the dossier-only checkpoint commit.

## Decision gates

- **Integration gate:** diff and focused checks pass; independent review of exact feature tip; clean current beta merge, removing dossier from target.
- **Activation / cohort gate:** network state change is out of scope; operators must satisfy each host's preflight and verify actual paths.
- **Promotion gate:** no main promotion requested.

## Decision record

- 2026-10-08 — Created docs refinement from reviewed beta; first independent review identified LAN-only control gap; revised preflight to require independent recovery and post-selection verification in correction `f1f23f6778acfdca15861280589e65067edc672c`. No production change.
