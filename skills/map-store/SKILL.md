---
name: map-store
description: Use when an agent learns reusable app, URL, endpoint, auth, defense, vuln-lead, or negative-test behavior that future agents should query by URL, surface, scope, tag, or status.
---

# Map Store

MapStore is the canonical structured app memory and source layer for App
Stories. It answers: "What is true about this app, URL, endpoint, parameter,
flow, role, surface, or defense?"

Use it whenever an agent learns reusable behavior about an endpoint, page, API
route, auth/session flow, CSRF/CSP/framework clue, sandbox, negative test,
tested state, or vulnerability lead.

## Fast Routing

- App/URL/surface fact future agents should query -> `/map-store`.
- Hunt chronology, decisions, hypotheses, handoffs, blockers -> `/bounty-notes`.
- Bulk URL intake, parameter inventory, queue state, per-lane reviewed/tested
  status -> `/url-ingest`.
- Concrete findings, reports, proof packets -> `manual_hunter.py` / `/findings`.
- Storage destination for artifacts -> `/bounty-storage`.
- Replay-grade request templates, permission gates, and retest matrices ->
  `docs/mapstore-request-contracts.md` plus a MapStore pointer.
- Exact payload/probe history -> lane attempts folders, with MapStore storing
  the stable conclusion and sanitized artifact pointer.

If a discovery is both fact and next-step idea, split it: factual behavior here,
hypothesis or handoff in `/bounty-notes`, linked by the same full URL and tags.

Rule of thumb: if an agent would want it while standing at a specific URL,
domain, app surface, role, or defense, write it to MapStore.

## Live Agent Flow

1. Load this skill early so the agent knows MapStore is available, but do not
   ingest broad MapStore contents by default.
2. Start from the user goal and the live surface in front of you. Do not make a
   broad MapStore or findings-ledger read the opening move for creative live
   testing.
3. Query MapStore only when you have a concrete URL, endpoint, surface,
   parameter, role boundary, or vuln class and need targeted tested-state,
   duplicate avoidance, reusable app facts, coverage, or gadget context.
   Every live query should have an explicit intent.
4. Treat `app-facts`, `dedupe`, and `coverage` as the default allowed intents
   during normal find-vulnerability goals. `gadget` requires an active candidate
   vulnerability. `old-leads` is disabled unless the user asked for retest,
   repass, cleanup, duplicate triage, or old-lead review.
5. Treat MapStore results as constraints and prior observations, not as the
   hypothesis generator. If prior notes are narrow, pivot to adjacent untested
   classes instead of inheriting their tunnel vision.
6. Do the work.
7. Write back important positive and negative observations.
8. Use `--scope app` for app-wide facts and `--scope surface` for surface-wide
   facts.
9. Add vuln-class/status tags so specialist agents can filter.
10. Link relevant attempts artifacts when the observation came from a deliberate
   probe or mutation family.
11. If the observation changes hunt direction, add the narrative/handoff to
   `/bounty-notes` too.

## Query Intent Modes

Use intent modes to keep MapStore as lazy retrieval instead of prompt baggage.

- `app-facts`: "What is true about this app/URL/surface?" Use for technology
  stack, JavaScript/app behavior, auth/session model, defenses, framework
  quirks, consumers, and trust boundaries.
- `dedupe`: "Have we tested this, and what did we test it for?" Return bounded
  tested-state, tested-for labels, status counts, and pointers instead of
  full historical writeups.
- `coverage`: "What is thin or already covered for this chosen surface?" Use
  after the agent selected a current surface or route cluster.
- `gadget`: "Given an active candidate vulnerability, what primitives could
  amplify impact?" Use only after the candidate exists.
- `old-leads`: "Show historical leads." Use only for retest/repass/cleanup,
  duplicate triage, report work, or explicit user approval.

CLI example for the two common questions:

```bash
PYTHONPATH=".:$HOME/projects/bounty-core" \
python3 agents/map_store.py query --program <program> --family web_bounty --lane web \
  --url "https://app.example/path" --surface xss --intent dedupe
```

Expected shape:

```text
Intent: dedupe
Tested: partial
Tested for: csrf, xss-reflected
Observations: 2
Pointers:
- failed | xss-reflected | reflected search negative | xss/app.example_s_search/...
```

## Goal-Run Tunnel Guard

Apply this guard only to find-vulnerability / goal / hunt / new-finding runs.
Do not apply it to repass, retest, cleanup, duplicate triage, evidence capture,
or status-review runs.

If the last two test targets were chosen mainly from `old-leads` / old
MapStore entries, or the run has gone roughly 30-45 minutes without a fresh
current-run observation, pause old-lead querying. Before following another old
lead, make three fresh observations from the current app/session, such as:

- a new route, panel, role boundary, or surface
- new JavaScript/API behavior
- changed feature flag, plan, entitlement, or account behavior
- a new trust boundary, renderer, export path, or consumer

This guard does not block `app-facts`, `dedupe`, or `coverage` queries. It only
prevents old vulnerability leads from becoming the path of least resistance in
normal goal runs.

## Opportunistic Lifecycle Hygiene

Do not run a background cleanup pass over MapStore before hunting. Update entry
status only when current testing gives you evidence.

Lifecycle statuses:

- `active`: default; still useful as a current observation or gadget.
- `candidate`: observed or promising, but not proven reusable yet.
- `failed`: tried in the current context and did not work; include what was
  tried and why it failed.
- `needs_recheck`: useful enough to revisit, but current evidence is
  incomplete, ambiguous, or environment-dependent.
- `stale`: app behavior appears to have changed since the note was written.
- `archived`: do not present as an active lead unless the agent explicitly
  reviews archived material.

When a gadget/note fails, do not immediately bury it after one weak attempt.
Write the attempt context or mark `failed`/`needs_recheck`. Use `stale` or
`archived` when repeated testing or clear app behavior proves it should stop
appearing as an active lead.

Every lifecycle downgrade must include an evidence-backed reason. Good reasons
say what was tested, where, and why the observation no longer applies. Avoid
generic reasons such as "old" or "did not work".

## Gadget Entries

Add the `gadget` tag only when an observation is a confirmed, exploitable
primitive that could participate in a stronger cross-class chain. Do not tag
hypotheses, generic leads, unconfirmed sink shape, or negative findings as
`gadget`.

Every `gadget` body must include this capability block:

```text
Capability:
- grants: <access/effect this primitive gives>
- requires: <preconditions, auth/resource state, user interaction, plan gate>
- crosses: <short source->destination boundary label>
- crosses_detail: <optional target-specific nuance>
- chain_status: ready|deferred|watch
- chain_watch: <what future primitive or condition should wake this gadget>
```

Use stable `crosses` labels where possible, for example
`attacker-content->victim-browser`, `client->server`,
`anonymous->authenticated`, `same-account->cross-account`,
`sandboxed-iframe->root-origin`, or `user-input->server-fetch`. Keep messy
target-specific explanation in `crosses_detail`.

Use `chain_status` and `chain_watch` as soft synthesis state, not as gadget
retirement. A gadget that did not chain during the last checkpoint can still be
valuable when a new primitive appears. Prefer:

- `ready`: keep in normal synthesis consideration.
- `deferred`: reviewed against current known gadgets; revisit only when
  `chain_watch` conditions appear.
- `watch`: especially relevant if the named future primitive or app condition
  appears.

Example:

```text
Capability:
- grants: same-origin JS execution in victim session
- requires: victim opens a published report page
- crosses: attacker-content->victim-browser
- crosses_detail: stored attacker-controlled title reaches a victim-owned report
  preview context
- chain_status: watch
- chain_watch: revisit when another gadget grants cross-account delivery,
  notification injection, report auto-open, or trusted embed navigation
```

Query the current gadget ledger with:

```bash
PYTHONPATH=".:$HOME/projects/bounty-core" \
python3 agents/map_store.py query --program <program> --family web_bounty --lane web --tags gadget
```

## Promotion Requirement

Raw Markdown, JSON, screenshots, callback logs, proxy exports, and tool output
may live in the artifact lane, but they are not a substitute for MapStore. Use
`~/workdir/` for disposable WIP and lane `working/scratch/<run-id>/` for
durable-but-unpublished artifacts or quick notes that are worth keeping but are
not themselves app observations. Before an agent finishes a bug bounty run,
every reusable observation must be promoted here:

- URL-specific behavior, tested payloads, response codes, parser results, auth
  gates, negative outcomes, and deductions -> `--scope url`.
- Domain or subdomain behavior such as shared headers, WAF/CDN behavior,
  upload-host behavior, or cross-route auth patterns -> `--scope surface` or
  `--scope app` with the relevant host/domain in the body.
- Program-wide behavior such as plan/role limits, common CSRF/session patterns,
  global rate limits, recurring false positives, or reusable target assumptions
  -> `--scope app`.

Write what was tried and what was learned, not just that "testing happened".
Useful negative observations prevent repeated work, so record them with tags
such as `investigated`, `negative`, `false-positive`, `acl-gated`,
`parser-tested`, `ssrf-negative`, or the relevant vuln-class prefix.

For manual-hunter attempts, do not paste every payload into MapStore. Store:

- durable app behavior
- defense or parser boundary
- pressure state: `cold`, `warm`, `hot`, or `exhausted`
- representative payload families tried
- concise block reason or bypass clue
- attempts artifact path for exact payloads/responses
- next discriminating probe, if any

Example body:

```text
Search param `q` reflects into an HTML attribute in the React preview. Double
quotes are entity-encoded, single quotes and spaces survive, angle brackets are
encoded, and DOMPurify strips event handlers after client reparse. Pressure
state: warm. Attempts:
agent_shared/attempts/xss/search/2026-07-08T150000Z/attempts.jsonl. Next probe:
check markdown/link URL sink from the same value before more attribute payloads.
```

If verbose evidence remains elsewhere, include a sanitized artifact pointer in
the MapStore body. If a reusable program-specific helper script was created,
promote it from `~/workdir/` into the lane `scripts/` directory and include that
script path in the MapStore body when it helps future agents retest or
reproduce. Do not put raw secrets, cookies, CSRF tokens, bearer tokens, API
keys, or full proxy dumps into MapStore.

Exit gate: if a future specialist would need the fact to avoid retesting the
same URL/domain/surface, the run is not complete until that fact is in MapStore.

## Replayable Request Contracts

When an observation records a request that future agents should retest with a
new auth context, role, SDK token, company account, plan, or parser hypothesis,
do not rely on free-form tags alone. Create or update a request contract under
the mounted bounty root and point MapStore to that artifact.

Use `docs/mapstore-request-contracts.md` for the canonical schema. Key rules:

- Store replay shape and source request provenance, not raw cookies, CSRF
  tokens, bearer values, SDK tokens, or API keys.
- Put local request artifacts under `recon/requests/<host>/`.
- Include structured `gate`, `retest_matrix`, `retest_notes`, and
  `next_retest_when` fields.
- Retest matrix keys may be target-specific, but must be lowercase snake_case
  and use `true`, `false`, or `null` values.
- Generate search tags from controlled fields such as `gate.type`,
  `gate.reason`, status, and retest matrix state instead of inventing
  near-duplicate free-form tags.
- Use `agents/map_request_tags.py explain` to normalize custom retest fields and
  generate canonical tags before writing request-contract metadata.

## Commands

Run from `~/projects/bug_bounty_harness` with bounty-core on `PYTHONPATH`.

```bash
PYTHONPATH=".:$HOME/projects/bounty-core"
python3 agents/map_store.py init --program <program> --family web_bounty --lane web
python3 agents/map_store.py query --program <program> --family web_bounty --lane web --url "https://app.example/path" --surface xss
python3 agents/map_store.py query --program <program> --family web_bounty --lane web --tags gadget,confirmed
python3 agents/map_store.py query --program <program> --family web_bounty --lane web --tags gadget --status active,candidate
python3 agents/map_store.py query --program <program> --family web_bounty --lane web --tags gadget --include-archived
python3 agents/map_store.py write --program <program> --family web_bounty --lane web --url "https://app.example/path" --surface xss --scope url --tags "xss-sandbox,investigated" --agent "<agent>" --body-file /tmp/mapstore-body.md
python3 agents/map_store.py update-status --program <program> --family web_bounty --lane web --path "xss/app.example_s_path/example/index.md" --status archived --reason "Retested against current preview flow twice; title no longer reaches the victim preview context." --agent "<agent>"
python3 agents/map_store.py rebuild-crossref --program <program> --family web_bounty --lane web
```

Prefer `--body-file` or `--body-stdin` for Markdown observations. Inline
`--body` is only for simple text; backticks and other shell metacharacters can
be interpreted by the shell before MapStore receives them.

Open `references/routing-examples.md` for MapStore vs Bounty Notes examples.
Open `references/map-store-reference.md` for scope levels, surfaces, tags,
storage layout, family/lane selection, and cross-family pointers.
Open `docs/mapstore-request-contracts.md` for replayable request contracts,
source request IDs, retest matrices, and normalized tag generation.
