# SSRF reference packs integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `docs/ssrf-reference-packs`
- **Base commit:** `a023632`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-13
- **Owning feature branch/ref:** `docs/ssrf-reference-packs`
- **Latest immutable recovery checkpoint:** `5239edaf5398e0e9983175b01f34df0e7e8691ec`
- **Feature implementation commit(s):** `5239edaf5398e0e9983175b01f34df0e7e8691ec`
- **Inspiration / canonical references:** OWASP SSRF Prevention Cheat Sheet and SSRF Bible; Orange Tsai's URL-parser research; PortSwigger SSRF guidance; cloud-provider and Kubernetes documentation.

## Intent

Replace thin SSRF reference packs with a compact, source-linked catalogue of
observed-boundary technique families. Preserve strict scope, controlled-callback,
minimal-proof, and no-secret/no-state-change constraints.

## Implemented contract

The existing three packs cover: (1) synchronous/blind/async and secondary
fetchers, (2) address representation, URL parser, DNS TOCTOU/rebinding, and
redirect boundaries, and (3) cloud/container/internal destination classes,
metadata controls, alternate schemes, and request-shape escalation boundaries.
The primary skill and short idea-seed file point agents to the matching pack.
No live target traffic, ready-to-send protocol frames, secret retrieval, or
broad scanning procedure is added.

## Evidence and review

- Tests and commands: reference-path validator for five required files; `git diff --check`; independent local Markdown-link audit.
- Independent review: **approved**; no blockers. Reviewer verified changed paths, navigation, cited-source reachability, and safety boundaries.
- Replay/cohort/fixture evidence: not applicable; documentation-only change.
- Merge/ancestry evidence: branch created from fetched `origin/beta` at `a023632`.

## Blockers and deferred work

None. The reviewer noted and this commit corrects stale dossier handoff metadata.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/ssrf-reference-packs`
- **Latest immutable recovery checkpoint:** `24221724253f813ff1e54fb45cef10d61e639937` (dossier-only checkpoint; implementation is `5239edaf5398e0e9983175b01f34df0e7e8691ec`)
- **Feature implementation commit(s):** `5239edaf5398e0e9983175b01f34df0e7e8691ec`
- **Exact resume point:** merge the approved feature into a clean, current local `beta` worktree; remove this branch-local dossier during integration.
- **Working-tree state at handoff:** clean; independent review approved the implementation with one corrected handoff-metadata note.

## Decision gates

- **Integration gate:** clean diff/path checks plus independent safety/content review.
- **Activation / cohort gate:** no runtime activation; skill synchronization remains a separate decision.
- **Promotion gate:** no main promotion requested.

## Decision record

- 2026-09-13 — created isolated feature branch and expanded SSRF reference packs.
- 2026-09-13 — independent review approved; corrected dossier metadata and ready for beta integration.