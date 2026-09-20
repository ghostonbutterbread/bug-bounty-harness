# AI review attribution — BBH integration dossier

- **Feature branch:** `feat/ai-review-attribution`
- **Base / target:** `aa275fde49802c393c5789d6e3387da82c6f1c2a` (`origin/beta`) → `beta`
- **Worktree:** `/home/ryushe/worktrees/bbh-ai-review-attribution`
- **Provider:** Bounty Core beta `65cfe628a69c920637e4c50cb52374869f5d623c`

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

- Provider beta merge/publish receipt: `65cfe628a69c920637e4c50cb52374869f5d623c`;
  provider beta suite passed `147` tests.
- BBH focused source tests passed `101` tests through a checkout-local virtual
  environment after installing `requirements.txt`; distribution metadata and
  `direct_url.json` resolved the exact provider commit above.
- Direct CLI checks wrote temporary MapStore, Hypothesis, Error, and Bounty
  Notes artifacts, each with the expected reviewer tag.

## Boundaries

The tag is optional and neither an evidence-validity claim nor authorization.
Existing data stays unmodified when the source model is unknown. Raw captures,
generated indexes, and mechanical transport artifacts are not retroactively
attributed.

## Next action

Install the pinned provider into a checkout-local test environment, prove the
installed distribution resolves to the exact provider revision, run the BBH
focused suite through that installed environment, then request independent BBH
review before beta integration.
