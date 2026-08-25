# Leads skill lifecycle dossier

- **Status:** implementation complete; awaiting review
- **Owner:** BBH
- **Branch:** `feat/leads-skill-lifecycle`
- **Base:** `726b32060da09f9a45a033dbb6c7ab2a57d49cc4`
- **Target:** `beta`

## Contract

Adds the BBH-native `/leads` skill for class-neutral, cross-run evidence-backed
lead synthesis. `/manual` remains the current-run manual queue. MapStore stays
the public lead projection; Hypothesis Ledger stays private-first continuation;
Attempts retain exact probes.

The skill documents retrieval through MapStore's existing `old-leads` intent,
lead card fields, ranking for push/blocked/needs-you/weakness views, and required
lifecycle reconciliation. It explicitly prohibits exposing live agents' private
hypotheses and treats persistent challenges as a handoff condition rather than
an evasion campaign.

## Evidence

- RED: `uv run --with pytest python -m pytest agents/test_leads_skill.py -q` —
  failed because `skills/leads/SKILL.md` did not exist.
- GREEN: `uv run --with pytest python -m pytest agents/test_leads_skill.py agents/test_manual_places_to_hunt_skill.py -q` — 4 passed.

## Activation

No runtime deployment or schema migration. The skill is registered in
`SKILL_REGISTRY.md` and referenced by `agents/index.md`; normal BBH skill sync
publishes it after review/integration.

## Deferred

A dedicated formatter/CLI for `/leads` is intentionally deferred. Current
MapStore already supports `old-leads` plus class/tag/status filtering; this skill
sets the contract before adding a separate renderer or store.
