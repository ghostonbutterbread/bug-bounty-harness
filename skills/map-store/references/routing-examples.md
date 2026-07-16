# MapStore Routing Examples

## MapStore

Write these to MapStore:

These examples are concrete on purpose, but they are not target-selection
templates. Preserve the reasoning pattern: intended behavior, proven attacker
capability, missing impact, program fit, and wake condition.

- "XSS in Canva render flow lands in a sandboxed viewer; postMessage is the only
  observed parent communication path."
- "XSS on `https://sandbox.example.com` is in scope but low/no-impact today:
  no credentials, no CSRF token, no sensitive data, and no trusted parent-origin
  message path. Revisit only for sandbox escape, account-binding route, or
  trusted parent message abuse."
- "`https://www.example.com/settings/email` requires a fresh CSRF token and
  rejects missing `Origin`."
- "Cloudflare challenge appears across `*.example.com` before authenticated app
  traffic."
- "Tested `/api/projects/{id}` with a second account; cross-account IDs return
  403, not object data."
- "SVG upload intentionally fetches public external URLs for rendering. No
  private-network reachability, auth-bound response disclosure, or parser impact
  observed; record as intended behavior / hold-for-chain, not SSRF."

## Bounty Notes

Write these to Bounty Notes:

- "Ryushe wants the next agent to focus on sandbox-to-export chains."
- "Paused because we need a second account before continuing access-control
  testing."
- "Today's hunt priority is checkout before profile surfaces."
- "Handoff: reviewer should inspect the MapStore entries tagged `xss-sandbox`
  and decide whether the chain is worth deeper testing."

## App Stories

App Stories are built from MapStore observations because agents need structured
filters such as URL, surface, scope, tag, and status. Bounty Notes may reference
an App Story, but should not be the only place where app behavior is recorded.

## Artifact-backed Split

During a run, an agent may produce disposable files under `~/workdir/`, then
promote durable evidence into the lane scratch area, for example:

- `working/scratch/<run-id>/story-media-video-endpoint.md`
- `working/scratch/<run-id>/story-media-video-endpoint-probe.json`
- `working/scratch/<run-id>/story-media-video-acl-bypass.json`

keep those as verbose evidence, then promote the reusable conclusion:

- MapStore URL entry: endpoint path, auth gate, tested request variants,
  callback result, negative/positive deduction, status tags, and sanitized
  artifact pointers.
- Bounty Notes handoff: why the path was explored, what account or permission
  would unblock the next test, and which MapStore entry to read first.

If the run creates a reusable program-specific script, promote it to
`scripts/<script-name>` in the same program/lane and link that path from
MapStore when it is useful for retesting.

## Attempts-backed Split

When a specialist is actively testing a vulnerability class, keep exact
payloads and response details in an attempts folder:

- `agent_shared/attempts/xss/search/2026-07-08T150000Z/attempts.jsonl`
- `agent_shared/attempts/ssrf/import-url/2026-07-08T153000Z/attempts.jsonl`

Then write the durable conclusion to MapStore:

- "Search param `q` reflects into a quoted attribute. Double quotes and angle
  brackets are encoded, spaces and single quotes survive, and client-side
  reparse still strips event handlers. Pressure state: warm. Attempts:
  `agent_shared/attempts/xss/search/2026-07-08T150000Z/attempts.jsonl`. Next probe:
  markdown/link URL sink from the same value."
- "Image import `url` triggers a backend fetch to public callbacks. Direct
  RFC1918 targets are blocked before fetch; redirect handling remains unknown.
  Pressure state: hot. Attempts:
  `agent_shared/attempts/ssrf/import-url/2026-07-08T153000Z/attempts.jsonl`. Next
  probe: compare public redirect vs private redirect."

Bounty Notes should explain why the agent kept pressure, paused, pivoted, or
left the remaining next probe for another agent. Do not make Bounty Notes the
only place where the URL/surface behavior is recorded.
