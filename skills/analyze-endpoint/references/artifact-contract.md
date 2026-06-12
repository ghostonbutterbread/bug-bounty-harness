# Analyze Endpoint Artifact Contract

The endpoint folder is optimized for quick agent retrieval and RAG-style partial loading.

## Files

- `contract.json` is the compact machine-readable endpoint contract.
- `parameters.json` is the field dictionary and fuzzing map.
- `replay.md` is a sanitized replay template with fresh-auth instructions.
- `observations.jsonl` is append-only sanitized evidence from proxy/source/history.
- `notes.md` is human-readable reasoning, open questions, and next tests.

## contract.json

Required top-level keys:

- `schema_version`: currently `1`
- `program`
- `endpoint_id`
- `created_at`
- `updated_at`
- `identity`: method, scheme, host, path, route_template, full_url_template
- `source`: proxy lane, PwnFox color, account alias, referrer, UI flow, observation count
- `request_shape`: content type, header roles, cookie names, query fields, body format, body schema summary
- `auth_context`: auth-required status, account-bound headers, object-bound path/body/header fields
- `state_change`: `none`, `read`, `write`, `delete`, `payment`, `unknown`, plus description
- `replay`: template file, fresh auth requirements, one-time token warning
- `fuzzing_handoff`: safe mutation lanes and skills to load
- `redaction`: what was redacted and how

## parameters.json

Use dotted paths:

- `path.user_id`
- `query.page`
- `header.X-Canva-Request`
- `cookie.CAU`
- `body.recoveryEmailDetails.A?`

Each parameter entry should include:

- `location`: `path`, `query`, `header`, `cookie`, or `body`
- `type`: string, email, number, boolean, object, array, token, cookie, unknown
- `role`: object-id, auth-bound, operation-marker, csrf, content, analytics-noise, browser-context, server-generated, client-generated, unknown
- `required`: true, false, or unknown
- `meaning`: concise semantics or `unknown`
- `confidence`: high, medium, low
- `observed_examples`: sanitized values only
- `evidence`: short evidence strings
- `fuzzing`: mutation guidance and fields to keep stable

Never promote a guess to high confidence without evidence from at least one of:

- sibling requests with controlled deltas
- UI labels or response behavior
- source/frontend JS symbol names
- successful omission/type-change/minimal replay tests

## Replay Rules

Replay artifacts are templates. They must not contain live cookies, bearer tokens, authz values, CSRF tokens, passwords, reset links, or API keys.

Use placeholders:

- `<FRESH_COOKIE_JAR_{LANE}>`
- `<FRESH_AUTHZ_{LANE}>`
- `<CSRF_FROM_LIVE_FLOW>`
- `<USER_ID_{LANE}>`
- `<OWNED_EMAIL>`

Before live replay, resolve fresh auth from an approved owned agent lane. Do not replay through Ryushe's personal proxy unless the proxy-routing policy allows it and Ryushe explicitly approves that active use.

## Merge Rules

- Append new observations; do not overwrite history.
- Add newly observed fields with `required: unknown`.
- If a field disappears in sibling requests, reduce required confidence instead of deleting it.
- Keep contradictory semantics as evidence until a controlled test resolves them.
- Prefer `unknown` over false certainty for obfuscated fields.
