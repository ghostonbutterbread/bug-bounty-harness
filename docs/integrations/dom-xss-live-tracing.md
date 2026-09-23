# DOM-XSS live tracing integration dossier

- **Status:** review-ready
- **Owner:** Hermes (bugfix profile)
- **Branch:** `docs/dom-xss-live-tracing`
- **Base commit:** `72da9b9f36ce3cbb751cf08be1524b2cc08cb7f4`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-22
- **Owning feature branch/ref:** `docs/dom-xss-live-tracing`
- **Latest immutable recovery checkpoint:** `626f03181892f93b317580bca8823a0ea18d3030`
- **Feature implementation commit(s):** `626f03181892f93b317580bca8823a0ea18d3030`
- **Inspiration / canonical references:** Intigriti, “Hunting for DOM-based XSS vulnerabilities: A complete guide” (https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-dom-based-xss-vulnerabilities); canonical `skills/dom-xss/SKILL.md`, `skills/xss/SKILL.md`.

## Intent

Make live source-to-sink tracing discoverable when static review cannot explain a controlled value's path. Keep context-matched probes and browser execution proof as the finding boundary. No live target interaction or new tooling requirement.

## Implemented contract

A conditional DOM-lane guide names inert canaries, DevTools breakpoints/call stacks, optional sink tracers, asynchronous retriggering, transformation inspection, and negative-evidence limits. Existing XSS router and attempts contracts remain unchanged.

## Evidence and review

- Tests and commands: `git diff --check`; focused skill frontmatter/link/section checks passed.
- Independent review: no blockers; one minor caveat about raw/browser comparisons was resolved by making the comparison conditional. Reviewed neighboring XSS guidance.
- Replay/cohort/fixture evidence: not applicable; instruction-only change.
- Merge/ancestry evidence: branch from fetched `origin/beta` at base commit above.

## Blockers and deferred work

- No known blockers. Runtime adoption by future agents is not claimed from this document-only change.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/dom-xss-live-tracing`
- **Latest immutable recovery checkpoint:** `626f03181892f93b317580bca8823a0ea18d3030`
- **Feature implementation commit(s):** `626f03181892f93b317580bca8823a0ea18d3030`
- **Exact resume point:** integrate the reviewed feature into beta, then verify the active skill projection.
- **Working-tree state at handoff:** clean after the dossier update commit.

## Decision gates

- **Integration gate:** independent review and focused document checks pass; remove this temporary dossier from beta.
- **Activation / cohort gate:** runtime symlink resolves to integrated beta content and skill load shows new section.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-09-22 — created feature branch and added focused guidance.
- 2026-09-22 — accepted independent review; resolved its conditional raw/browser comparison caveat. No remaining blockers; integrate into beta, with no stable promotion.
