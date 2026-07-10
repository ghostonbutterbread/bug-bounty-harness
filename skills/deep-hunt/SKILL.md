---
name: deep-hunt
description: "Use when running a section-scoped deep web hunt that maps one app area, keeps hypotheses separated, and hands bounded work to focused child skills."
---

# Deep Hunt

Use this when Ryushe wants agents to go deep on one live web URL, route
cluster, or app section instead of testing many unrelated URLs shallowly.

Deep Hunt is an orchestrator skill. The parent agent owns mapping, hypothesis
separation, child-agent packets, and progress tracking. Child agents own one
bounded lane at a time.

## Load Order

Follow the Cold-Start Doctrine from `agents/index.md`:

1. **Scope Gate** — Read scope, approved account/resource context, and
   live-testing policy. Check `~/Shared/scopes/{program}/` first, then
   `~/Shared/bounty_recon/{program}/scope/`. If no scope exists, try
   `/pullscope`. If the program has no published scope, write `no scope` stub.
2. **Cold Surface Pass** — Read `$HARNESS_ROOT/prompts/deep-hunt-playbook.md`.
   Look at the target URL/section with fresh eyes. Observe behavior directly.
   Do NOT query MapStore, ledger, url-ingest, or prior leads yet.
3. **Novelty Quota** — Identify 3-5 fresh surfaces, flows, parameters, roles,
   or assumptions from direct observation before following any existing leads.
4. **Memory Overlay** — Now query prior state as needed:
   - `/url-ingest` stats/next/history for the program
   - `/live-map` summary and relevant handoff packets
   - `/hunter-memory` summaries for the section or vulnerability lane
   - program knowledge and prior findings
5. Choose one URL, one section, or one tight route cluster.
6. Create a hypothesis board for that URL/section.
7. Spawn or brief focused child lanes only after each packet has a clear
   boundary, safety rule, and stop condition.

Historical confirmed findings, old reports, ledger entries, and MapStore
`#do-not-retest` notes are coordination inputs, not success conditions. Use
them to avoid duplicate retests, understand tested boundaries, or extend an
existing FID with new evidence. Do not count old findings as satisfying the
current deep-hunt goal unless Ryushe explicitly asked for status, portfolio
review, duplicate triage, report cleanup, revalidation, or extending a known
finding.

## Commands

```text
/deep-hunt <program> --section <section-or-route-cluster>
/deep-hunt <program> --url <full-url>
/deep-hunt <program> --from-params <params.txt> --section <hint>
/deep-hunt <program> --from-url-index --section <route-or-host-filter>
/deep-hunt <program> --manual-companion <human-current-flow>
```

This skill currently defines the orchestration protocol. Use existing
`url-ingest`, `live-map`, `hunter-memory`, browser/proxy, and vulnerability-lane
skills for concrete actions.

## Section Rule

Prefer one URL or one section at a time:

- search/results
- SSO/login/callback
- workspace/project sharing
- upload/avatar/profile media
- checkout/billing/coupons
- app/plugin/integration pages
- export/download/share links

Do not mix unrelated sections in one child packet.

For URL-deep-dive work, slower is preferred. A child agent should understand
the chosen URL's response, linked JavaScript, parameters, related route cluster,
and a few low-noise probes before moving on. It is acceptable for many URLs to
remain unreviewed if the reviewed URLs have better notes and cleaner coverage.

If raw HTTP reaches a plain 403/401, classify it first. Normal app/server
forbidden responses belong in `/403`, `/error-triage`, auth, access-control, or
header analysis. Route to `/chromium-test` only when the response suggests
Cloudflare/managed challenge pages, browser-only token failures, bot-defense
HTML, TLS/header fingerprinting, or similar browser-only behavior before app
behavior is visible. Use approved agent-owned or Caido-profile auth/session
material only in memory, and do not log raw secrets.

## Hypothesis Rule

Do not cap useful hypotheses artificially. If one parameter suggests XSS,
redirect, SSRF, and auth-state behavior, keep all four hypotheses if evidence
supports them.

The constraint is separation:

- one hypothesis has one owner lane
- one lane has one test family at a time
- each attempt records what changed and what was learned
- failed payloads become scoped boundaries, not global dismissals

## Child-Agent Packets

Each child gets only:

- program and section name
- relevant full URLs or route cluster
- relevant parameters and where they appear
- related JavaScript files or sink/source notes
- account/resource boundary and destructible status
- selected skill and technique family
- prior scoped attempts from hunter memory
- optional `/error-mapper` probe pack when parser/error behavior is relevant
- exact stop condition

Never pass raw cookies, bearer tokens, passwords, reset links, API keys, broad
proxy dumps, or unrelated app history.

## Output

Record the run under the program's shared artifacts:

```text
$HARNESS_SHARED_BASE/{program}/agent_shared/deep-hunt/<section>/<run_id>/
```

Recommended files:

- `SECTION.md` — section map and scope/account notes
- `hypotheses.jsonl` — one hypothesis per line
- `handoffs/*.json` — child-agent packets
- `attempts.jsonl` — parent-level attempt and routing log
- `summary.md` — completed work, boundaries, findings, next deep section

Promote to findings only through the owning lane's proof standard.
