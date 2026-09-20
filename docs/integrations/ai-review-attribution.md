# AI review attribution — BBH integration dossier

- **Feature branch:** `feat/ai-review-attribution`
- **Base / target:** `aa275fde49802c393c5789d6e3387da82c6f1c2a` (`origin/beta`) → `beta`
- **Worktree:** `/home/ryushe/worktrees/bbh-ai-review-attribution`
- **Provider:** Bounty Core beta `7b08495f65a50f733fc18213c38cc3ae8e91bdf5`

## Intent

Expose a small optional `ai_reviewed_by` tag throughout the durable BBH records
that represent AI interpretation. This answers “which models have looked here?”
without rewriting raw evidence or guessing old model identity.

## Implemented contract

- MapStore observations, lifecycle updates, and application behaviors accept
  `--model-id` with the existing agent identity and surface the structured tag
  in both their index data and human header.
- Attempts accept `agent_id` / `model_id` through `append_attempt` and persist
  the tag in the canonical event.
- Hypothesis Ledger, Error Store, Blocker Store, Public Artifact Store, Bounty
  Notes, and scratch manifests accept optional model attribution through their
  BBH writer paths.
- `requirements.txt` pins the reviewed immutable provider merge revision.
- `docs/ai-review-attribution.md` states coverage, legacy behavior, the raw
  evidence boundary, and the bounded second-model review rule.

## Evidence

- Provider beta merge/publish receipts: `65cfe628a69c920637e4c50cb52374869f5d623c`
  (initial attribution support) and `7b08495f65a50f733fc18213c38cc3ae8e91bdf5`
  (empty hypothesis reviewer omission); provider beta suite passed `147` tests.
- Expanded BBH focused tests passed `109` tests through a checkout-local virtual
  environment after installing `requirements.txt`; distribution metadata and
  `direct_url.json` resolved the exact provider commit above.
- `python -m compileall -q agents` and `git diff --check` passed after the review
  corrections.
- Direct CLI checks wrote temporary MapStore, Hypothesis, Error, and Bounty
  Notes artifacts, each with the expected reviewer tag.

## Boundaries

The tag is optional and neither an evidence-validity claim nor authorization.
Existing data stays unmodified when the source model is unknown. Raw captures,
generated indexes, and mechanical transport artifacts are not retroactively
attributed.

## Review corrections

Independent review found that repeated MapStore and Bounty Notes writes could
replace prior attribution, model-less Bounty Notes artifacts wrote empty tags,
and timeline entries did not render their reviewer. The branch now merges prior
reviewers on replacement writes, omits empty optional fields, and renders a
reviewer line in every attributed timeline event. A final release review also
found that model-less Hypothesis Ledger payloads exposed an empty optional field;
Bounty Core beta `7b08495f65a50f733fc18213c38cc3ae8e91bdf5` corrects that
provider contract and BBH pins it. Focused regressions cover every corrected
path. The final reviewer also found scratch manifests replaced earlier reviewer
tags when a run received another attributed artifact; that manifest now merges
prior reviewers before replacement and is regression-tested. Fresh independent review
approved the correction after installed-provider tests and legacy/model-less
smokes. The branch is ready for a clean current-beta integration merge.

## Next action

Run the expanded focused BBH tests from the checkout-local installed environment,
then obtain a fresh independent review of the corrected branch before beta
integration.
