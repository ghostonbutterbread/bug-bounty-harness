# MapStore Routing Examples

## MapStore

Write these to MapStore:

- "XSS in Canva render flow lands in a sandboxed viewer; postMessage is the only
  observed parent communication path."
- "`https://www.example.com/settings/email` requires a fresh CSRF token and
  rejects missing `Origin`."
- "Cloudflare challenge appears across `*.example.com` before authenticated app
  traffic."
- "Tested `/api/projects/{id}` with a second account; cross-account IDs return
  403, not object data."

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
