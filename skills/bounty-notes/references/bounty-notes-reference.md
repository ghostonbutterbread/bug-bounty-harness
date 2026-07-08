# Bounty Notes Reference

## Load Order

1. Resolve active program, family, and lane from `/me`,
   `context/target_profile.json`, or the user request.
2. Read `prompts/bounty-notes-playbook.md` when methodology is needed.
3. Use `agents/bounty_notes.py` for deterministic note and artifact writes.
4. Use specialist systems for owned state: findings, coverage, URL review, and
   hunter-memory claims.

## Examples

MapStore, not only Bounty Notes:

- "XSS in Canva render flow lands in a sandboxed viewer; postMessage is the only
  observed parent communication path."
- "`https://www.example.com/settings/email` requires a fresh CSRF token and
  rejects missing `Origin`."
- "Tested `/api/projects/{id}` with a second account; cross-account IDs return
  403, not object data."

Bounty Notes:

- "Ryushe wants the next agent to focus on sandbox-to-export chains."
- "Paused because we need a second account before access-control testing."
- "Today's hunt priority is checkout before profile surfaces."
- "Handoff: inspect MapStore entries tagged `xss-sandbox` and decide whether
  the chain is worth deeper testing."

## Do Not Write

- Findings directly into final reports; import through `manual_hunter.py`.
- Already-tested state as prose only; mark coverage or URL review state.
- Endpoint, domain, surface, or app behavior only in Markdown/JSON artifacts;
  promote reusable facts and negative deductions to MapStore, then link the
  artifact path from the MapStore body or Bounty Notes handoff.
- Raw cookies, bearer tokens, API keys, credentials, private headers, or full
  proxy dumps into notes.

## Exit Checklist

Before finishing:

1. Leave disposable WIP in `~/workdir/`; do not treat it as durable evidence.
2. Promote durable-but-unpublished notes and sanitized artifacts into
   `working/scratch/<run-id>/`.
3. Promote reusable program-specific scripts into `scripts/`.
4. Write reusable URL/app/surface observations to `/map-store`, including
   artifact and script pointers when useful.
5. Promote narrative learning into `notes/` with URL, tags, report/hypothesis,
   and links where possible.
6. Add or update promising hypotheses.
7. Add a handoff.
8. Import findings through the finding pipeline.
9. Link reports/findings back to hypotheses or notes.
10. Mark coverage or URL review state in the correct ledger.
