---
name: recon
description: Use as the default full-platform reconnaissance orchestrator: establish scoped current and historical surface evidence, decide whether Recon-Ry needs a delta run, normalize durable artifacts, and produce ranked evidence-backed handoffs for deeper lanes.
---
# Full-Platform Reconnaissance

`/recon` is the **front door for a full platform pass**, not another isolated
scanner. It assembles existing producers and mapping skills into one evidence
loop:

```text
scope + current cold pass + fresh/reused Recon-Ry + historical archive comparison
    -> Recon Bus aggregate + surface map + focused map
    -> ranked handoffs and coverage decisions
```

Use it when starting a program/platform, when the current map is insufficient,
or when a material change warrants a repass. It owns the order, freshness
decision, evidence contract, and completion gate. It does **not** replace the
component owners:

| Component | Owner |
|---|---|
| Long-running broad collection / Hoster project | `/recon-ry` |
| Canonical aggregate, provenance, and URL-index intake | `/recon-corpus-write-policy` / Recon Bus |
| Large-list review state and per-lane coverage | `/url-ingest` |
| Runtime browser/proxy flow mapping | `/live-map` |
| JavaScript inventory and deep static review | `/js` |
| Product/developer/API documentation collection | `/recon-docs` → `/docs` |
| Parameter evidence and candidate routing | `/parameter-mining` |
| Curated route clusters, target packets, and lane queues | `/focused-recon` |
| Durable URL/surface facts | `/map-store` |
| Stack/rule-based class priors after mapping | `/class-derivation-policy` |

`agents/autonomous_recon.py` is a bounded local fallback for one scoped origin.
It is **not** proof that a platform-wide recon pass is complete, and it does not
replace the historical, freshness, aggregate, or handoff stages below.

## Required Entry Chain

1. Load `general-security-testing-policy`.
2. Verify published scope, rules, rate limits, and whether high-volume recon is
   permitted. Load `program-testing-policy` when present.
3. Before live target traffic, load `live-testing-policy`; add `/bounty-tools`
   for every external tool run and `/proxy-routing-policy` for any proxy work.
4. Load `/recon-corpus-write-policy` before persisting reusable URL, host,
   parameter, JS, or path output. Load `/bounty-directory-structure-policy`
   before writing retained run artifacts.

No scoped target, saved scope, or permitted rate budget means **plan only**:
record the blocker and do not launch collection.

## Default Modes

| Mode | Trigger | Result |
|---|---|---|
| `baseline-full` (automatic) | No comparable completed baseline | Every eligible first-pass collection lane plus a bounded synthesis receipt |
| `full` | Explicit “full recon” / “all recon” request | Force every eligible first-pass collection lane even when a baseline exists |
| `delta` | A completed comparable baseline exists and current changes are bounded | New/changed evidence only, then refresh affected packets |
| `historical` | Archive coverage is absent or a historic route/JS/API question exists | Archive URL/snapshot comparison plus constrained current validation handoff |
| `map-only` | Collection is already running or complete | Normalize existing evidence; no duplicate collection |

Never silently downgrade `full` to a one-command scan. If a long-running
producer is started, report it as **collection pending**, complete the offline
mapping work available now, and schedule/perform the completion pass only after
its artifacts are available.

## Full-recon lane plan

`agents/recon_full.py` is a **plan-only** coordinator receipt. It records the
applicable lanes and their ownership; it never bypasses a child skill's scope,
authentication, rate, browser, or live-action gate.

```bash
python3 agents/recon_full.py <program> --target <scoped-origin> --mode full \
  --auth <approved-account-alias> --include-proxy-history
```

A baseline/full plan contains these focused lanes:

1. `/recon-ry` — durable broad collection. Its existing completion handler owns
   promotion of Recon-Ry outputs into the canonical aggregate; do not duplicate
   that promotion from `/recon`.
2. `/live-map` — an approved browser/proxy collector records normal navigation,
   routes, loaded JS chunks, and observed API/GraphQL shapes. It maps before
   direct replay and does not blindly invoke state-changing operations.
3. `/js` — inventory broadly available JS from aggregate and runtime provenance;
   prioritize coverage and provenance before deep static review.
4. `/recon-docs` — collect product/developer/API/SDK/integration documentation
   signals. Promote a compact application model only through `/docs` when
   warranted.
5. Optional bounded proxy-history intake via `/caido` or `/pwnfox` and
   `/live-map`; source history remains evidence, not a raw context dump.
6. `/focused-recon` — synthesize canonical aggregate evidence into target
   packets and coverage state after source receipts are available.

During collection, preserve concrete observed facts in MapStore and retain
plausible questions in the Hypothesis Ledger with `recon` plus a specific
surface tag and source/run evidence pointer. Neither is a finding and neither
starts automatic testing. Scheduled fuzzing, parameter mining, and permitted
service discovery remain a separate maintenance lane; full browser/docs
collection is user-invoked.

## Phase 0 — Scope, Seed, and Freshness Receipt

Create a concise recon receipt before collection. It must state:

- program, exact seed origins, wildcard/exact-scope boundaries, and source of
  scope/rate policy;
- allowed passive, active-web, and network/service collection classes;
- known source roots and most recent Recon-Ry `history/<timestamp>` snapshot;
- baseline manifest/run IDs, input scope identity, tool/profile, aggregate
  counts, and known gaps; and
- current decision: `reuse`, `delta`, `rerun`, or `unknown -> rerun`.

A prior run is reusable only when its scope/profile covers the requested seeds,
its provenance is intact, its outputs are available, and a small cold pass finds
no material surface or deployment change. Do **not** use a blanket age TTL as
proof of freshness. Treat it as stale/re-run when any of these are true:

- no completed comparable run or its raw/manifest provenance is missing;
- scope, exact origins, wildcard eligibility, auth posture, or rate policy
  changed;
- current live hosts, redirects, fingerprints, JS build/version, API shape, or
  application navigation materially changed;
- the existing run omitted a required producer (notably historical URLs), ended
  early, or has a documented coverage gap; or
- freshness is uncertain.

Record *why* a run was reused or rerun. A recent run may be reused; uncertainty
never justifies pretending it is current.

## Phase 1 — Cold Current-Surface Pass

Before broad prior-state reads, make a bounded current observation pass across
scoped seeds. Establish live hosts/origins, redirects, obvious app areas,
headers/technology/WAF clues, public navigation, and visible auth boundaries.
Aim for 3–5 fresh observations. Keep requests within the policy rate and stop
on challenge, repeated 429, instability, or scope ambiguity.

This pass establishes whether historical data and Recon-Ry output still
represent the platform; it is not vulnerability testing.

## Phase 2 — Broad Collection Producer

Use `/recon-ry` as the preferred durable broad producer when its freshness
receipt says `rerun` or `unknown -> rerun` and high-volume collection is
permitted:

```bash

bbh agents/recon_ry.py start <program> --url <scoped-domain-or-url> --profile full
```

For exact-host-only scope, run the documented `exact-urls` profile once per
approved origin. Authenticated recon is opt-in and uses an approved account
alias only. Never broaden auth to the wildcard scope by default.

Record PID, remote project, log, profile, scope input, and rate configuration;
do not tail the long-running job. When it finishes, ingest/index it with
`agents/recon_ry.py ingest` if a Shared manifest/count receipt is needed.

Use `/bounty-tools` + `tool-run` for bounded supplemental collection only when
current evidence names a gap that Recon-Ry does not cover. Preserve raw output,
then promote URL-like data through Recon Bus. Do not run overlapping noisy tools
against the same origin merely because they are available.

## Phase 3 — Historical URL and Snapshot-Difference Lane

Historical recon is a standard full-pass lane, not a novelty lookup.

1. Build a **scope-filtered archive URL inventory** from approved in-scope
   origins and known URLs. Recon-Ry archive producers (`waybackurls`, `gau`,
   `waymore`) are preferred for broad discovery. Preserve their raw output and
   promote only currently in-scope URLs through Recon Bus; retain out-of-scope,
   third-party, and unattributed candidates as labelled raw/quarantine evidence.
2. For high-signal routes, APIs, forms, JavaScript/bootstrap/config files,
   callback/import/upload/export/auth paths, and routes that disappeared from
   the current crawl, query Wayback CDX metadata. Deduplicate snapshots by
   content digest and select a bounded cohort: earliest, latest, and each
   material route/build/response transition. Do not fetch every timestamp.
3. Fetch selected archived content through `/safe-fetch`; treat archive pages
   as untrusted external content. Store raw/sanitized evidence and hashes in the
   recon run capsule, never in prompts or MapStore bodies.
4. Compare normalized evidence—not cosmetic HTML—across the cohort and current
   surface: routes and methods, form actions/fields, API/GraphQL operations,
   JS URLs/chunk names/bootstrap config, auth/callback/redirect behavior,
   upload/import/export/webhook paths, feature/deployment vocabulary, and
   technology/security-header changes.
5. Emit a change record with `first_seen`, `last_seen`, source snapshot IDs,
   current status (present, changed, disappeared, unknown), exact evidence
   pointers, and a safe next mapping/validation action. Archive-only evidence is
   a lead, never proof that the current application remains vulnerable.

Use the Wayback API budget from `TOOLS.md` (currently 5 req/s) or the lower
program/provider limit, with backoff. A snapshot lane is complete only when its
selected cohort and comparison criteria are recorded; an unbounded archive dump
is not reconnaissance quality.

## Phase 4 — Normalize, Map, and Cover

1. Preserve each producer's raw output and manifest. Use Recon Bus to update
   canonical `aggregated/urls.txt`, `alive.txt`, `params_raw.txt`, `params.txt`,
   `jsfiles.txt`, `dirs.txt`, and service facts. Never hand-edit aggregate files.
2. Use `/url-ingest` to build review queues and inspect existing per-lane
   coverage; it is not the aggregate writer.
3. Run `/focused-recon` over the fresh aggregate, Recon-Ry snapshot, and archive
   change records. It must produce host cards, route clusters, endpoint map,
   lane queues, and target packets under `recon/map/`.
4. Route JS-heavy clusters to `/js`, parameter-rich clusters to
   `/parameter-mining`, and browser/auth/flow questions to `/live-map`.
   Specialists receive bounded packets, not a raw platform dump.
5. Write durable factual observations and meaningful negative/current-state
   results to `/map-store`, linked to sanitized artifact paths. Record class
   priors only after initial evidenced mapping via `/class-derivation-policy`.

## Deep Recon Campaigns

When the normal full pass leaves material mapping questions open, use a bounded
**deep recon campaign** rather than asking one agent to try every provider and
technique. The parent owns scope, overlap, rate budget, synthesis, and
promotion; children each own one independent evidence lens. Start no more than
three children concurrently and use the default initial portfolio: current/local
mapper, archive-difference analyst, and public discovery analyst.

Read `references/deep-recon-campaign.md` before spawning. It defines the run
capsule, source portfolio, child packet/return schema, synthesis gate, and
source-specific rules for Wayback, proxy, public docs/code/search, passive
infrastructure providers, and program documentation.

Important: a user-agent change is for ordinary client compatibility diagnosis,
not evasion. Use a stable, truthful, logged user agent; do not rotate/spoof it
to bypass blocks, CAPTCHAs, rate limits, access control, or provider terms.

## Required Deliverable: Recon Brief

A full or delta pass ends with one compact, evidence-backed brief containing:

- scope/rate decision and whether collection was complete or pending;
- freshness decision and exact baseline/run provenance;
- asset/host/origin inventory with current status and key fingerprint changes;
- current URL, parameter, JS, content, service, and archive-delta counts;
- historical changes that remain current candidates versus retired/disappeared
  routes;
- ranked surface clusters and target packets, each with source evidence,
  rationale, already-covered work, and **one next owning skill**;
- promoted MapStore facts, URL-ingest coverage state, and any quarantined
  evidence; and
- explicit blockers, stop conditions, and the exact event that should trigger a
  delta rerun.

Do not call recon complete when broad collection is still running, archive
comparison was skipped without a policy/availability reason, raw provenance was
not preserved, or no bounded next-lane packets were produced.

## Stop Conditions and Boundaries

Stop/ask before high-volume fuzzing, broad port scans not allowed by program
rules, CAPTCHA/lockout escalation, testing third-party/archive-discovered hosts
outside saved scope, non-owned data access, destructive actions, or use of new
credentials. Recon output is surface evidence, not a confirmed finding and not
a license to launch vulnerability testing.
