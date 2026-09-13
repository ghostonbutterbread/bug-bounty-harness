# Public 403 resource index integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `bug-bounty-harness/t_8554c39a-integrate-curated-public-403-resources`
- **Base commit:** `8228c320386f5dfa53c2281263ec710d1b22e494`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-13
- **Owning feature branch/ref:** `bug-bounty-harness/t_8554c39a-integrate-curated-public-403-resources`
- **Latest immutable recovery checkpoint:** pending first commit
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

- 2026-09-13 — independent review rejected the first staged revision because the PortSwigger BApp-store URL had become dead and the dossier lacked required recovery/decision details. The dead link was removed; the public source repository remains. A fresh review is required before integration.

## Blockers and deferred work

- **Missing test or evidence:** independent review and beta integration validation.
- **Command / fixture / environment needed:** repository documentation checks and a clean beta merge check.
- **Trigger to run it:** before merge.
- **Why it blocks integration:** policy-adjacent skill reference changes require a fresh review and exact routing validation.
- **Next completion step / successor reference:** validate the feature diff, obtain independent reviewer verdict, then merge only if clean.

## Interruption / resume handoff

- **Owning feature branch/ref:** `bug-bounty-harness/t_8554c39a-integrate-curated-public-403-resources`
- **Latest immutable recovery checkpoint:** pending first commit.
- **Exact resume point:** run focused reference checks and independent review against the changed `403` files.
- **Working-tree state at handoff:** uncommitted implementation and dossier.

## Decision gates

- **Integration gate:** link/routing validation, `git diff --check`, independent review, and clean beta merge check.
- **Activation gate:** normal beta skill projection must resolve the merged `403` reference; no live-tool activation is implied.
- **Promotion gate:** no `main` promotion implied.
