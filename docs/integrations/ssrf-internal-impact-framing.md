# SSRF internal-impact framing integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `fix/ssrf-internal-impact-framing`
- **Base commit:** `ed1b102bc1446bf7f42b56ca5f38d34bb65ee8eb`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-02
- **Owning feature branch/ref:** `fix/ssrf-internal-impact-framing`
- **Latest immutable recovery checkpoint:** `ac006212d2aaf6192aff5717d3ec11e774537118`
- **Feature implementation commit(s):** `ac006212d2aaf6192aff5717d3ec11e774537118`
- **Inspiration / canonical references:** PortSwigger SSRF and Blind SSRF; OWASP SSRF WSTG and Prevention Cheat Sheet; Ryushe's SSRF evidence/impact correction in Discord.

## Intent

Public callback is fetch evidence, not internal reachability or impact. Make evidence-driven internal investigation—including sensitive disclosure—normal SSRF follow-up. Avoid blanket read-only, non-sensitive, or owned-fixture prerequisites while preserving concrete program and harm gates.

## Implemented contract

The SSRF entry and metadata pack distinguish DNS/HTTP fetch, internal reachability, visibility, privileged access, and impact. Mechanism-specific filter pressure continues toward internal pages/APIs/metadata. Sensitive exposure can be minimally proved without broad collection or credential use. The separate AI Policies live-testing boundary is updated in its own repository to align.

## Evidence and review

- Tests and commands: BBH `git diff --check` and focused policy smoke passed; AI Policies `python3 scripts/policy_lint.py` and `git diff --check` passed after alignment edits.
- Independent review: initial pass found three conflicts (targeted disclosure approval, credential-use gate, callback attribution). Re-review confirmed those resolved and found a pre-existing minimal credential-validation exception in `live-testing-policy/references/operating-details.md`; aligned the ask-first text with `information-disclosure-policy` and fixed a typo. Final policy comparison: general router delegates to live controller; live boundaries and rate reference permit targeted minimal exposure while gating broad scans/collection and credential use beyond validity check; injection and SSRF specialist agree.
- Replay/cohort/fixture evidence: documentation-only, no live target requests.
- Merge/ancestry evidence: branch from fetched `origin/beta` at `ed1b102`; recheck before merge.

## Blockers and deferred work

- None known; runtime projection needs verification after beta integration.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/ssrf-internal-impact-framing`
- **Latest immutable recovery checkpoint:** `ac006212d2aaf6192aff5717d3ec11e774537118`
- **Feature implementation commit(s):** `ac006212d2aaf6192aff5717d3ec11e774537118`
- **Exact resume point:** merge reviewed feature into current `beta`, remove this dossier on integration, verify policy and runtime projection.
- **Working-tree state at handoff:** clean after dossier-only checkpoint commit.

## Decision gates

- **Integration gate:** independent review and policy alignment; focused checks green.
- **Activation / cohort gate:** AI Policies beta policy commit `923bcf1a2304b3e36c5ffb35b9fd2eef67e40395` and BBH beta sync/runtime skill load; do not claim active on Hoster from local commits.
- **Promotion gate:** stable only on explicit user direction.

## Decision record

- 2026-10-02 — independent review corrected three conflicts; re-review found and resolved the credential-validity exception. Accepted for beta integration after green lint and smoke.
