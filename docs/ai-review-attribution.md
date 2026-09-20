# AI Review Attribution

## Purpose

Durable records that represent an AI's interpretation may carry the optional
`ai_reviewed_by` field. It is a compact list of:

```json
{"agent_id": "surface-mapper", "model_id": "openai/gpt-5.6"}
```

It tells a later agent which model/agent combinations have already produced or
updated the interpretation, so a different model can deliberately re-check the
same MapStore surface or evidence without treating prior output as universal.

## Contract

- Both identifiers are required for a tag. Do not invent an `unknown` model.
- Writers merge duplicate tags; absence of `--model-id` preserves legacy
  behavior and creates no tag.
- The field is metadata only: it never proves an observation correct and never
  changes scope, ownership, or testing authorization.
- Do not add the tag to immutable raw capture merely because a model later read
  it. Attach it to the derived observation/attempt/decision that model created.

## Second-model review

When a targeted record or surface has reviewer tags and the current
`agent_id`/`model_id` pair is absent, treat that as an invitation—not an
obligation—to take an independent look. A different model may re-parse the
linked evidence or revisit the same surface when it has a concrete bounded
question, a plausible alternate interpretation, or useful untested adjacent
behavior.

Do not re-run an identical attempt or start broad churn solely because a tag is
missing. Keep the normal scope, rate, status, and duplicate-avoidance rules; use
prior observations as constraints rather than truth. Add the current reviewer
tag only after a material review produces or updates a derived record.

## Coverage

- **MapStore observations and application behaviors:** `--agent` plus
  `--model-id`; lifecycle updates retain every supplied reviewer tag.
- **Attempts:** `append_attempt(..., agent_id=..., model_id=...)`, or equivalent
  `agent_id` and `model_id` in the event payload.
- **Hypothesis Ledger:** `--agent-id`, `--run-id`, and optional `--model-id` on
  creation.
- **Bounty Notes and scratch manifests:** `--agent` and optional `--model-id`.
- **Core append-only Error, Blocker, and Public Artifact events:** their BBH
  `record` commands accept optional `--model-id` alongside `--producer`.

Raw evidence, generated indexes, and mechanical transport artifacts remain
unchanged. Existing records are intentionally not backfilled: historical model
identity is unknown and must not be guessed.
