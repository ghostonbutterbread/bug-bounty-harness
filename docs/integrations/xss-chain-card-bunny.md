# XSS chain-card Bunny integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `feat/xss-chain-cards-harness`
- **Base commit:** `ca76506b830880c691316e8912a83ec50e4d313f`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-23
- **Owning feature branch/ref:** `feat/xss-chain-cards-harness`
- **Latest immutable recovery checkpoint:** `2622a9647b9322483b4dd929006094f604bd7a08`
- **Feature implementation commit(s):** `2622a9647b9322483b4dd929006094f604bd7a08`
- **Inspiration / canonical references:** read-only XSS run audit; `bunny-collaborative`, `xss`, `leads`.

## Intent

Preserve parameter and sink catalogs while ensuring a selected XSS path receives an evidence-linked chain-card decision, not false closure or a fresh breadth assignment after timeout. No live target action or finding is authorized by a card.

## Implemented contract

The existing campaign record carries mapped/connected/defended path cards with writer, field/route, consumer, observed defense, evidence, owner and next discriminator. Public facts stay with Leads/MapStore; exact tests stay with Attempts. Successive worker segments retain ownership and recheck safety admission.

## Evidence and review

- Tests and commands: pending focused static review and independent reviewer.
- Independent review: pending.
- Replay/cohort/fixture evidence: no target traffic; a live campaign uptake check is deferred until beta projection is activated separately.
- Merge/ancestry evidence: feature starts at fetched `origin/beta` `ca76506`.

## Blockers and deferred work

- **Missing test or evidence:** fresh Hoster worker loads the beta-projected skill and produces a real card/continuation receipt.
- **Command / fixture / environment needed:** authorized isolated Bunny campaign with a mapped XSS catalog and normal browser/account lease.
- **Trigger to run it:** separately approved beta activation/cohort run.
- **Why it blocks integration, activation, or promotion:** does not block local integration; blocks any claim of deployed behavioral improvement.
- **Next completion step / successor reference:** verify after beta integration and explicit activation.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/xss-chain-cards-harness`
- **Latest immutable recovery checkpoint:** `2622a9647b9322483b4dd929006094f604bd7a08`
- **Feature implementation commit(s):** `2622a9647b9322483b4dd929006094f604bd7a08`
- **Exact resume point:** review skill diff, commit, independent review, integrate into beta with sibling branches.
- **Working-tree state at handoff:** intentionally uncommitted until review.

## Decision gates

- **Integration gate:** focused review of wording and no conflicting evidence store; independent review.
- **Activation / cohort gate:** verify selected runtime and fresh consumer.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-10-23 — created from audited catalog-to-continuation gap.
