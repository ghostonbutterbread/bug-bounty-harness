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

If a discovery is both fact and next-step idea, split it: factual behavior here,
hypothesis or handoff in `/bounty-notes`, linked by the same full URL and tags.

Rule of thumb: if an agent would want it while standing at a specific URL,
domain, app surface, role, or defense, write it to MapStore.

## Mandatory Agent Flow

1. Query first for the URL/surface.
2. Do the work.
3. Write back important positive and negative observations.
4. Use `--scope app` for app-wide facts and `--scope surface` for surface-wide
   facts.
5. Add vuln-class/status tags so specialist agents can filter.
6. If the observation changes hunt direction, add the narrative/handoff to
   `/bounty-notes` too.

## Commands

Run from `~/projects/bug_bounty_harness` with bounty-core on `PYTHONPATH`.

```bash
PYTHONPATH=".:$HOME/projects/bounty-core"
python3 agents/map_store.py init --program <program> --family web_bounty --lane web
python3 agents/map_store.py query --program <program> --family web_bounty --lane web --url "https://app.example/path" --surface xss
python3 agents/map_store.py write --program <program> --family web_bounty --lane web --url "https://app.example/path" --surface xss --scope url --tags "xss-sandbox,investigated" --agent "<agent>" --body "Observation..."
python3 agents/map_store.py rebuild-crossref --program <program> --family web_bounty --lane web
```

Open `references/routing-examples.md` for MapStore vs Bounty Notes examples.
Open `references/map-store-reference.md` for scope levels, surfaces, tags,
storage layout, family/lane selection, and cross-family pointers.
