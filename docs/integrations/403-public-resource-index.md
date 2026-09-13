# Public 403 resource index integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `bug-bounty-harness/t_8554c39a-integrate-curated-public-403-resources`
- **Base commit:** `8228c320386f5dfa53c2281263ec710d1b22e494`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-13
- **Owning feature branch/ref:** `bug-bounty-harness/t_8554c39a-integrate-curated-public-403-resources`
- **Latest immutable recovery checkpoint:** `7bd2f4547e2727518f2f2ee511a5feadacb9b594`
- **Feature implementation commit(s):** `7bd2f4547e2727518f2f2ee511a5feadacb9b594`
- **Inspiration / canonical references:** public 403-bypass methodology, tooling, and supporting corpora discovered through `safe-fetch`; dead BApp-store listing excluded after independent revalidation

## Intent

Give the bounded BBH `403` workflow a curated, refreshable public-resource index without replacing its existing scope, ownership, rate, routing, or evidence gates.

## Implemented contract

A new `skills/403/references/public-resources.md` groups primary methodology,
reviewable candidate generators, and supporting corpora. It requires agents to
start from an existing local lane pack, choose only a distinct candidate family,
inspect third-party tooling before any approved live use, and treat response
differences only as leads. The `403` skill loads it only when an existing lane
pack is insufficient or a vetted additional family is needed.

## Evidence and review

- Research retrieval: public candidate sources were retrieved through `safe-fetch` on 2026-09-13; the dead PortSwigger BApp-store listing was removed during independent review, leaving only its verified public source repository.
- Validation planned: Markdown/reference-link and routing assertions; `git diff --check`; independent review.
- Live-target interaction: none.
- Merge/ancestry evidence: pending.

## Decision Record

- 2026-09-13 — independent review rejected the first staged revision because the PortSwigger BApp-store URL had become dead and the dossier lacked required recovery/decision details. The dead link was removed; the public source repository remains.
- 2026-09-13 — corrected implementation committed as `7bd2f4547e2727518f2f2ee511a5feadacb9b594`.
- 2026-09-13 — fresh review confirmed the dead-link and safety fixes, but found a stale `pending first commit` handoff line. Commit `8cd83b5b184bd5a5e321924ab85044cc10a9c953` corrected that record.
- 2026-09-13 — final review approved candidate `56bea734f94ba487116c1124151c94a188a98340`: all nine indexed URLs resolved through `safe-fetch`; safety gates, routing, and no-auto-execution language were accepted. Next: clean beta integration check and merge.

## Blockers and deferred work

- **Missing test or evidence:** beta integration validation.
- **Command / fixture / environment needed:** clean beta merge check and post-merge reference validation.
- **Trigger to run it:** immediately before and after merge.
- **Why it blocks integration:** the approved feature must be merged into a current clean beta worktree and revalidated there.
- **Next completion step / successor reference:** merge the approved feature into clean beta, remove this branch-local dossier from beta, then verify the resulting reference files.

## Interruption / resume handoff

- **Owning feature branch/ref:** `bug-bounty-harness/t_8554c39a-integrate-curated-public-403-resources`
- **Latest immutable recovery checkpoint:** `7bd2f4547e2727518f2f2ee511a5feadacb9b594` (implementation). `85aef236794f8e3af9fbb9d41158a49ea15ba135` is a prior dossier-only review checkpoint, not a claim about the current branch tip.
- **Exact resume point:** obtain a fresh independent review of the corrected dossier checkpoint after this update, then perform a clean beta merge check.
- **Working-tree state at handoff:** implementation and first dossier checkpoint committed; this update corrects the remaining recovery-record contradiction.

## Decision gates

- **Integration gate:** link/routing validation, `git diff --check`, independent review, and clean beta merge check.
- **Activation gate:** normal beta skill projection must resolve the merged `403` reference; no live-tool activation is implied.
- **Promotion gate:** no `main` promotion implied.
