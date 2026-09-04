# Advanced recon baseline integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `docs/advanced-recon-baseline`
- **Base commit:** `a4fe70ce8fa929c79c504cc5018ca70e3bb68ce4`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-03
- **Owning feature branch/ref:** `docs/advanced-recon-baseline`
- **Latest immutable recovery checkpoint:** `226875eb5801579420912d3ae92b0850e11927aa`
- **Feature implementation commit(s):** `226875eb5801579420912d3ae92b0850e11927aa`
- **Inspiration / canonical references:** Ryushe’s advanced, wildcard-aware recon workflow; existing `/recon`, `/recon-ry`, and Recon Bus contracts.

## Intent

Implement a clear two-horizon reconnaissance contract: a rigorous initial surface baseline that maximizes authorized DNS/IP/service/URL/JS/dork-derived coverage, followed by continuous evidence enrichment while browsing or testing. Recon-Ry remains the single broad GAU/Wayback/archive producer. Documentation and public-code reading are deferred until a concrete observed surface creates a named mapping or behavior-comparison question.

## Implemented contract

- `/recon` now distinguishes a thorough initial, scope-checked surface baseline
  from continuous enrichment through live-map, JS, Recon Bus, URL Ingest, and
  MapStore.
- Recon-Ry is explicitly the single broad GAU/Wayback/archive producer; the
  parent does not launch overlapping archive collectors.
- Full baselines may select up to three independent, scope-gated lanes for
  DNS/IP/certificate correlation, attributable service/vhost inventory, and
  provider-compliant target-specific dorking.
- IP/ASN/co-hosting/historical-DNS/search correlation remains evidence only;
  unattributed records are quarantined until attribution and saved-scope
  validation.
- Documentation and public-code reading are deferred until a concrete observed
  endpoint, technology, integration, or behavior raises a named question.

No collector stages, profile flags, runner behavior, or scheduler activation
changes are included in this branch.

## Evidence and review

- Tests and commands:
  - `git diff --check` — passed.
  - Contract-marker validation over the three updated skills/reference plus this
    dossier — passed; it also confirmed no unsupported `/recon --mode deep`
    invocation remains.
- Independent review: requested changes were resolved: removed unsupported
  `deep` mode syntax, made Phase 3 consume completed Recon-Ry archive output,
  required saved-scope hostname/CIDR eligibility before service/vhost traffic,
  and removed default auth from the full-recon command example.
- Replay/cohort/fixture evidence: not applicable; guidance-only change.
- Merge/ancestry evidence: branch starts from `origin/beta` at
  `a4fe70ce8fa929c79c504cc5018ca70e3bb68ce4`.

## Blockers and deferred work

- **Missing test or evidence:** Runtime validation of any new Recon-Ry collector/stage behavior.
- **Command / fixture / environment needed:** A separate reviewed change in `~/tools/recon-ry/`, followed by a scoped dry-run or approved execution.
- **Trigger to run it:** When an implementation proposal specifies a new collector or a profile/stage change.
- **Why it blocks integration, activation, or promotion:** This branch deliberately changes only guidance and must not claim collector implementation.
- **Next completion step / successor reference:** Review the guidance diff, then implement collector tooling separately if approved.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/advanced-recon-baseline`
- **Latest immutable recovery checkpoint:** `226875eb5801579420912d3ae92b0850e11927aa`
- **Feature implementation commit(s):** `226875eb5801579420912d3ae92b0850e11927aa`
- **Exact resume point:** Merge the reviewed branch into a clean current `beta`; remove this temporary dossier in the same integration operation or immediate cleanup commit.
- **Working-tree state at handoff:** clean after committing this dossier-only handoff.

## Decision gates

- **Integration gate:** Clean docs-only diff, valid Markdown/references, and independent review with resolved findings.
- **Activation / cohort gate:** None; the branch does not enable a collector or scheduler.
- **Promotion gate:** Merge to `beta` only after the integration gate; runtime Recon-Ry stage changes remain separate.

## Decision record

- 2026-09-03 — created; implementing documentation-only advanced recon baseline contract.
- 2026-09-03 — reviewed; requested corrections applied and implementation committed as `226875eb5801579420912d3ae92b0850e11927aa`.
