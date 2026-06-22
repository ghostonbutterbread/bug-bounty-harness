---
name: analyze-endpoint
description: "Analyze a proxy-observed endpoint into reusable request contracts, parameter dictionaries, sanitized replay templates, and fuzzing handoffs."
---

# Analyze Endpoint

Use when Ryushe asks an agent to "analyze endpoint", inspect proxy history for a request shape, document what an endpoint accepts, or prepare a replay/fuzzing handoff from observed traffic.

This skill turns proxy evidence into a durable endpoint folder. It is not a live-testing permission grant.

## Load Order

1. Read scope, owned-account context, and `general-security-testing-policy`.
2. If proxy history is involved, load `proxy-routing-policy`; use Ryushe-proxy only as a read/compare source when explicitly requested.
3. If account aliases or object ownership are unclear, load `account-management`.
4. Load `/bounty-storage` and resolve the active Bounty Core family/lane before
   writing. Do not hard-code legacy `bounty_recon` roots when a
   `context/target_profile.json` or resolver output exists.
5. If a raw request block or file is available, initialize artifacts:
   ```bash
   python3 "$HARNESS_ROOT/skills/analyze-endpoint/scripts/analyze_endpoint.py" <program> request.raw
   ```
6. Read `$HARNESS_ROOT/prompts/analyze-endpoint-playbook.md` for the full workflow.
7. Read `references/artifact-contract.md` for required artifact fields and merge rules.

## Storage

Write endpoint analysis under the resolved lane's `recon/endpoints/` tree. For
current web-lane targets, this usually means:

```text
~/Shared/web_bounty/{program}/web/recon/endpoints/{host}/{method}_{route_slug}_{hash}/
  contract.json
  parameters.json
  replay.md
  observations.jsonl
  notes.md
```

If a legacy command or prior artifact already created
`~/Shared/bounty_recon/{program}/ghost/endpoints/...`, treat it as a legacy
compatibility location: read or link it, but write new endpoint contracts to the
resolved active lane unless the resolver explicitly selects the legacy path.
Keep this skill's canonical contract shape either way.

## Workflow

1. Identify the endpoint by full URL, method, host, route template, source page, auth lane, and PwnFox color when known.
2. Save sanitized raw shape, not live secrets. Header names, cookie names, body field paths, lengths, hashes, and placeholders are allowed. Raw cookies, bearer tokens, authz headers, CSRF tokens, reset links, passwords, and API keys are not.
3. Build the endpoint contract:
   - method, full URL template, content type, route params
   - required/likely-required headers by role
   - cookie names only
   - body/query schema and observed field paths
   - state-change summary and source UI/referrer
4. Build `parameters.json` as the field dictionary. Every path/header/query/body field gets:
   - type, observed sanitized examples, role, required status, meaning, confidence
   - evidence strings from proxy observations, sibling requests, UI labels, responses, or JS/source hints
   - fuzzing guidance: mutate, keep stable, object-id swap, omit/null/type-change, or do not fuzz
5. Inspect sibling requests before assigning semantics to unclear fields. Compare same route, same `X-*` request marker, nearby UI flow, and frontend JS names. If still unclear, write `unknown` with evidence instead of guessing.
6. Write `replay.md` with a sanitized curl/template and fresh-auth instructions. Use placeholders such as `<FRESH_COOKIE_JAR_GREEN>`, `<FRESH_AUTHZ_GREEN>`, `<USER_ID_GREEN>`.
7. Append each new observation to `observations.jsonl`; merge new fields into `contract.json` and `parameters.json` without deleting older evidence.

## Handoff

- Replay exact shape -> `proxy-curl` or a fresh-auth local replay from `replay.md`
- Mutate known request fields -> `request-exploration`
- Discover hidden fields/params -> `intelligent-fuzzing`
- Object/user/tenant binding -> `access-control` or `idor`
- Header trust or auth/context headers -> `headers`
- CSRF-sensitive state change -> `csrf`

## Stop Conditions

Stop before saving or replaying raw secrets, non-owned private data, unclear account ownership, destructive actions, paid/fulfillment actions, repeated stale-token replay, or active testing through Ryushe's personal proxy without explicit approval and same-host validation.

## Evidence

Record full URL, method, route template, source proxy lane, account alias/PwnFox color, sanitized headers/cookies/body fields, response class if known, artifact path, and confidence. Do not record reusable auth material.
