---
name: url-ingest
description: Use when importing, indexing, filtering, queueing, checking, or marking recon URLs in the SQLite-backed per-lane URL review tracker.
---

# URL Ingest

URL Ingest is the durable URL/parameter review index, queue, and per-lane
tested-state system. It is how agents answer "has this URL or parameter already
been looked at?" It is not the canonical recon aggregate writer and it is not
the notes layer.

Use it for:

- bulk URL intake into the SQLite review index
- large-list filtering and noise reduction
- queue selection for agents
- URL/route/parameter review status
- per-lane tested/deep-reviewed/dismissed state

Use recon-bus (`tool-run`, `scripts/recon_bus.py append`, `promote-run`, and
`watch-runs`) for aggregate promotion into canonical recon stores such as
`aggregated/urls.txt`, `alive.txt`, `params_raw.txt`, `jsfiles.txt`,
`wild.txt`, and `dirs.txt`.

Use `/map-store` for technical observations learned from a URL. Use
`/bounty-notes` for timeline, hypotheses, handoffs, FAQs, and narrative.

## Core Flow

1. Preserve raw recon/tool output in its run directory.
2. Promote reusable recon output through recon-bus when it should update
   canonical aggregate stores.
3. Ingest large URL sets into URL Ingest when agents need review queues,
   filtering, or tested/untested state.
4. Query `brief`, `next`, `status`, `params`, or `history` before testing.
5. After testing, `mark` URL/parameter coverage with agent, skill, family,
   technique, notes, and evidence path.

## Commands

```bash
cd ~/projects/bug_bounty_harness
python3 agents/url_ingest.py init <program>
python3 agents/url_ingest.py ingest <program> --source urls.txt --run-id <run-id> --scope-filter auto
python3 agents/url_ingest.py brief <program> --limit 20
python3 agents/url_ingest.py next <program> --lane xss --skill xss --test-family reflected-probe --param-preset xss --limit 25
python3 agents/url_ingest.py status <program> --lane xss --url "https://target.example/path?q=x"
python3 agents/url_ingest.py params <program> --lane ssrf --untested --limit 25
python3 agents/url_ingest.py mark <program> --url "https://target.example/path?q=x" --lane xss --status surface_reviewed --skill xss --test-family reflected-probe --param q --notes "No reflection observed."
```

Open `references/url-ingest-reference.md` for the review-index role, recon-bus
aggregate split, status semantics, scope-filter behavior, Hoster ingest, and
supported lanes.
