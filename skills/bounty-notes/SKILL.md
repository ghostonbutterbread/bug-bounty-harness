---
name: bounty-notes
description: Use when bug bounty agents need to write durable notes, hypotheses, handoffs, FAQs, or scratch artifact references without scattering markdown across working directories.
---

# Bounty Notes

Use this as the router for bug bounty note-taking. It tells agents where to put
temporary artifacts, durable knowledge, hypotheses, handoffs, and report-ready
material in the current program lane.

## Store Boundaries

`/bounty-notes` is the human investigation journal. Use it for chronology,
decisions, hypotheses, handoffs, FAQs, blockers, next-agent guidance, and
pointers to sanitized artifacts.

It is not the primary app-memory store. If the note says what the application,
URL, endpoint, parameter, auth flow, or defense actually does, write that
technical observation to `/map-store` first, then link or summarize it here when
it affects the hunt narrative.

Do not use ad hoc files such as `working/<run-id>/notes.md`,
`working/scratch/<run-id>/notes.md`, or `$HARNESS_SHARED_BASE/{program}/ghost/<skill>/notes.md`
as the only record of reusable hunt knowledge. Those files may exist as
run-local scratch, but any reusable discovery must be promoted before the agent
finishes.

Use the neighboring stores for their owned state:

- `/map-store`: URL-anchored or app-wide observations, endpoint behavior, auth
  patterns, CSRF/CSP/framework clues, negative test results, tested state, and
  cross-surface vulnerability leads. This is the source for app stories.
- `/url-ingest`: bulk URL intake, URL/parameter dedupe, queue state,
  reviewed/dismissed decisions, and URL coverage state. This is not a prose note
  store.
- `manual_hunter.py` / `/findings`: concrete findings, report drafts, and proof
  packets.
- `me_ledger.py` / coverage ledgers: already-tested state and coverage.

If a discovery is both an observation and a hypothesis, write the factual
observation to `/map-store` and the testable chain or narrative to
`/bounty-notes`, linked by the full URL and shared tags.

## Bounty Notes vs App Stories

Bounty Notes answer: "What happened in this hunt, what did we decide, and what
should the next agent do?"

App Stories answer: "How does this part of the application behave across URLs,
surfaces, roles, states, and defenses?"

App Stories should be built from `/map-store` observations because agents need
structured filters such as URL, surface, scope, tag, and status. Bounty Notes
can reference an App Story, but should not be the only place where app behavior
is recorded.

Fast routing rule:

- Would an agent want this when standing at a specific URL, domain, app surface,
  role, or defense? Write it to `/map-store`.
- Would an agent want this when resuming the overall hunt, understanding why a
  decision was made, or picking the next work item? Write it to
  `/bounty-notes`.
- If it is both factual app behavior and a next-step idea, split it: factual
  observation in `/map-store`, hypothesis or handoff here, linked by the same
  full URL and tags.

Examples that belong in `/map-store`, not only Bounty Notes:

- "XSS in Canva render flow lands in a sandboxed viewer; postMessage is the
  only observed parent communication path."
- "`https://www.example.com/settings/email` requires a fresh CSRF token and
  rejects missing `Origin`."
- "Cloudflare challenge appears across `*.example.com` before authenticated
  app traffic."
- "Tested `/api/projects/{id}` with a second account; cross-account IDs return
  403, not object data."

Examples that belong in Bounty Notes:

- "Ryushe wants the next agent to focus on sandbox-to-export chains."
- "Paused because we need a second account before continuing access-control
  testing."
- "Today's hunt priority is checkout before profile surfaces."
- "Handoff: reviewer should inspect the three MapStore entries tagged
  `xss-sandbox` and decide whether the chain is worth deeper testing."

## Load Order

1. Resolve the active program, family, and lane from `/me`, `context/target_profile.json`,
   or the user request.
2. Read `prompts/bounty-notes-playbook.md`.
3. Use `agents/bounty_notes.py` for deterministic note and artifact writes.
4. Use specialist systems for their owned state:
   - Findings and report material: `manual_hunter.py` / `/findings`
   - Coverage and already-tested state: `me_ledger.py` / `coverage.json`
   - URL review state: `/url-ingest`
   - Attempt/claim memory for experiments: `/hunter-memory`

## Canonical Buckets

Default lane root:

`~/Shared/{family}/{program}/{lane}/`

Write to:

- `notes/_index/` for generated lookup files. Start with `_index/active.md`
  when the user says "last note," "what were we just testing," or gives a
  fuzzy request.
- `working/scratch/<run-id>/` for raw/generated artifacts, extracted JSON,
  screenshots, prompt bundles, and temporary logs.
- `notes/timeline/YYYY-MM-DD.md` for chronological activity and decisions.
- `notes/hypotheses/<slug>.md` for testable ideas or assumption chains.
- `notes/handoffs/<run-id>.md` for takeover-ready summaries.
- `notes/faq/<slug>.md` for stable solved target facts.
- `notes/index.md` for pointers to useful durable notes.

Do not write:

- Findings directly into final report directories. Import them through
  `manual_hunter.py`.
- Already-tested state as prose only. Mark coverage or URL review state in the
  appropriate ledger.
- Raw cookies, bearer tokens, API keys, credentials, private headers, or full
  proxy dumps into notes.

## Commands

Initialize notes for a lane:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
python3 agents/bounty_notes.py init <program> --family web_bounty --lane web
```

Write a hypothesis:

```bash
python3 agents/bounty_notes.py note <program> \
  --family web_bounty \
  --lane web \
  --bucket hypotheses \
  --title "Avatar metadata reaches admin review" \
  --status untested \
  --agent codex \
  --run-id <run-id> \
  --url "https://www.canva.com/api/profile/avatar" \
  --tag avatar \
  --body "Check filename, EXIF, SVG title, moderation queue, and email render contexts."
```

Write a handoff:

```bash
python3 agents/bounty_notes.py note <program> \
  --family web_bounty \
  --lane web \
  --bucket handoffs \
  --title "<run-id>" \
  --slug "<run-id>" \
  --agent codex \
  --run-id <run-id> \
  --body-file /tmp/handoff.md
```

Store artifacts under scratch:

```bash
python3 agents/bounty_notes.py artifact <program> \
  --family web_bounty \
  --lane web \
  --run-id <run-id> \
  --agent codex \
  --source /tmp/sanitized-response.json \
  --note "Sanitized baseline response shape"
```

Search for notes by URL, tag, report/FID, bucket, or text:

```bash
python3 agents/bounty_notes.py search <program> \
  --family web_bounty \
  --lane web \
  --url "canva.com/api/profile/avatar"

python3 agents/bounty_notes.py search <program> \
  --family web_bounty \
  --lane web \
  --report FID-123
```

Link an existing hypothesis to a handoff, report stub, or another note:

```bash
python3 agents/bounty_notes.py link <program> \
  --family web_bounty \
  --lane web \
  --source hypotheses/avatar-metadata-reaches-admin-review.md \
  --target ../reports/findings/active/FID-123.md \
  --relationship report
```

## Exit Checklist

Before an agent finishes:

1. Put raw/generated material in `working/scratch/<run-id>/`.
2. Write every reusable URL/app/surface observation to `/map-store`.
3. Promote narrative learning into `notes/` with `--url`, `--tag`, `--report`,
   `--hypothesis`, and `--link` metadata whenever possible.
4. Add or update each promising hypothesis in `notes/hypotheses/`.
5. Add a handoff under `notes/handoffs/`.
6. Import real findings through the finding pipeline.
7. Link reports/findings back to the hypothesis or investigation notes.
8. Mark coverage or URL review state in the right ledger.
