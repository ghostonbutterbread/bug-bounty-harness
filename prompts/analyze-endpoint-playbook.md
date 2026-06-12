# Analyze Endpoint Playbook

Use this playbook when converting proxy-observed traffic into reusable endpoint knowledge for later replay, request exploration, intelligent fuzzing, or authorization testing.

## Goal

Create a sanitized endpoint folder that lets future agents answer:

- what endpoint is this?
- what method, route, headers, cookies, query fields, and body fields does it accept?
- which fields are auth-bound, object-bound, operation markers, generated state, browser context, or likely noise?
- what can be replayed safely with fresh owned-lane auth?
- what fields should fuzzing mutate or keep stable?

## Source Rules

Use proxy history as evidence, not as a credential source.

Allowed to persist:

- method, full URL template, route template
- header names and roles
- cookie names only
- sanitized body/query/path examples
- hashes/lengths/fingerprints for redacted values
- account alias, PwnFox color, owned object IDs when approved
- response class and behavior summary

Do not persist:

- raw cookies
- bearer/authz/session headers
- CSRF/XSRF tokens
- passwords, reset links, API keys, private configs
- raw credential material
- non-owned private data

## Procedure

1. Resolve program and target lane.
2. Load `/proxy-routing-policy` if the source is Caido/Burp/proxy history.
3. Load `/account-management` if account aliases or owned resource IDs matter.
4. Save the raw request to a local temp file if needed.
5. Generate the first artifact folder:

   ```bash
   python3 "$HARNESS_ROOT/skills/analyze-endpoint/scripts/analyze_endpoint.py" <program> request.raw \
     --proxy-lane <source-lane> \
     --pwnfox-color <color> \
     --account-alias <account-alias> \
     --ui-flow <flow-name>
   ```

6. Open `contract.json`, `parameters.json`, and `replay.md`.
7. Improve parameter meanings by checking sibling requests:
   - same route template
   - same product request marker, such as `X-Canva-Request`
   - same UI flow or referrer
   - frontend JS or source names when available
   - controlled deltas from owned-account observations
8. Keep unknowns explicit. Use `meaning: "unknown"` and `confidence: "low"` when evidence is thin.
9. Route next work:
   - exact replay shape -> `/proxy-curl`
   - known-field mutation -> `/request-exploration`
   - hidden field discovery -> `/intelligent-fuzzing`
   - object/account binding -> `/access-control` or `/idor`
   - auth/context headers -> `/headers`
   - CSRF/state-changing browser action -> `/csrf`

## Parameter Dictionary Guidance

Every parameter entry should explain:

- location: path, query, header, cookie, body
- type: string, email, boolean, number, object, array, token, unknown
- role: object-id, auth-bound, operation-marker, browser-context, generated, analytics-noise, content, unknown
- required: true, false, or unknown
- meaning and confidence
- evidence
- fuzzing guidance

For obfuscated fields, save shape and evidence first. Do not invent a semantic name until a sibling request, UI/source clue, or controlled test supports it.

## Replay Guidance

`replay.md` is a template, not a ready secret-bearing command.

Before running it:

- resolve fresh cookies/session from an approved owned lane
- replace `<USER_ID_GREEN>`, `<FRESH_AUTHZ_GREEN>`, `<FRESH_COOKIE_JAR_GREEN>`, and similar placeholders
- run one baseline replay before mutation
- avoid replaying stateful one-time-token flows repeatedly
- do not use Ryushe's personal proxy for active testing unless the proxy policy and Ryushe explicitly allow it

## Done Criteria

An endpoint is analyzed when:

- `contract.json` identifies route, method, request shape, auth context, and handoffs
- `parameters.json` lists all observed fields with roles and confidence
- `replay.md` can be converted into a fresh-auth baseline by a future agent
- `observations.jsonl` contains at least one sanitized source observation
- `notes.md` lists open questions and next safe tests
