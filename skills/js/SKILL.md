---
name: js
description: Use when collecting or hunting JavaScript for application behavior and security leads.
---

# JavaScript Router

Use `/js` to choose between acquiring JavaScript evidence and interpreting it. An
unqualified request such as "hunt the JavaScript", "dig into the JS", or "look
at the JS for vulnerabilities" means **run the adaptive `/js-hunt` workflow**;
the operator need not name a vulnerability class. Trace a strong lead or
available local artifact immediately; a missing inventory is not a gate.
For a broader hunt without suitable material, use `/js-pull` for scoped
collection when permitted. Explicitly offline work uses available artifacts
with no network collection; report missing material as a gap. Explicit
collection-only requests stop after `/js-pull` has produced a usable corpus.

## Intent Routes

- **Pull / collect / inventory** -> load `/js-pull`. Keep the existing
  `bbh agents/js_analyzer.py inventory` acquisition, hashing, source-map, chunk,
  provenance, and packet workflow. Collection is not a vulnerability review.
- **Standalone JS hunt** -> load `/js-hunt`. Its default broad behavior map,
  evidence-selected deep trace, acquisition and synthesis produce supported
  leads and specialist handoffs, not just extracted strings.
- **JS in an existing investigation** -> read this skill's
  [`references/analysis-lens.md`](references/analysis-lens.md) for the current
  feature, artifact or question. Do not start a broad campaign or fanout merely
  because JavaScript is relevant; acquire missing relevant code via `/js-pull`
  when needed and permitted.
- **Focused hunt** -> load `/js-hunt` with `--focus endpoints`, `--focus params`,
  `--focus secrets`, `--focus application-logic`, or `--focus dataflows` (or the
  equivalent natural-language request). Focus biases review, not scope or proof
  standards. Keep peripheral vision for strong adjacent evidence.
- **Generate wordlists** -> first review the JS-derived routes/fields through
  `/js-hunt` when they have not been interpreted, then load `/create-wordlists`;
  execution remains with `/use-wordlists` or `/fuzz`.

Legacy `analyze` maps to hunt; `deep` and `offline-fanout` are effort/execution
choices **within** hunt, not rival pipelines. Legacy `generate` maps to the
reviewed candidate handoff above. The paths `prompts/js-playbook.md` and
`skills/js/references/offline-fanout.md` are relative to the **BBH repository
root**, not this skill directory; the former details existing mechanics, and
the latter governs native
subagent execution when packet volume warrants it. Do not invoke the legacy
`bbh agents/js_offline_campaign.py` unless explicitly requested.

## Tool Map

- **BBH JS inventory** (`bbh agents/js_analyzer.py inventory`): acquire, hash,
  deduplicate, extract cheap signals, and create bounded review packets; owned
  by `/js-pull`.
- **JSLuice** (upstream CLI): AST-derived URL/request-shape or secret leads from
  selected local artifacts. Load `/jsluice` for commands and offline handling;
  parser matches do not prove endpoints or vulnerabilities.
- **Native subagents**: optional bounded packet reviews under `/js-hunt`. The
  parent verifies evidence and synthesizes; no fixed all-class team runner.

## Shared Boundaries

Before any target fetch or browser interaction, apply the program rules and the
normal `general-security-testing-policy` / `live-testing-policy` chain; load
`resource-safety-policy` for local artifact processing. For script-run coverage
judgment, load `/bb-script-rules`. Offline JS review never authorizes a live
probe. Third-party URLs in scoped JS are read-only context, not targetable scope.

Keep the evidence chain `page/flow -> JS URL -> sha256 -> packet/module ->
behavior -> related request -> next discriminator`. A regex/AST hit, source-map
name, hidden feature, client-side permission check, or public-looking key is a
lead, not proof of reachability, server enforcement, or impact. Missing signals
never establish absence. Keep raw bundles on disk; pass bounded packets to
agents. Preserve provenance and coverage distinctions between inventory, deep
review, and separately validated live behavior.

Class skills own their validation after a concrete handoff. For example,
route a concrete workflow lead to `/business-logic`; send an observed request to
`/analyze-endpoint` before `/idor`, `/access-control`, `/xss`, or other scoped
specialist testing.
Route a complete exposed username/password pair with in-scope provenance to
   `/credential-exposure-validation`; do not turn it into a wordlist candidate.
