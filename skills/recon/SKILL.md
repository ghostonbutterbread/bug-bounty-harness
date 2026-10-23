---
name: recon
description: "Use when initializing a program fully or running full-platform reconnaissance: establish a scoped baseline, enrich runtime evidence, and hand off ranked surfaces."
---
# Full-Platform Reconnaissance

`/recon` is the **front door for a full platform pass**, not another isolated
scanner. It assembles existing producers and mapping skills into one evidence
loop:

```text
scope + current cold pass + fresh/reused Recon-Ry + eligible surface-expansion lanes
    -> Recon Bus baseline aggregate + surface map + focused map
    -> continuous browser/proxy/JS/route enrichment
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
| Concrete documentation/behavior comparison | `/docs` (only after a specific surface question exists) |
| Parameter evidence and candidate routing | `/parameter-mining` |
| Curated route clusters, target packets, and lane queues | `/focused-recon` |
| Durable URL/surface facts | `/map-store` |
| Stack/rule-based class priors after mapping | `/class-derivation-policy` |

`agents/autonomous_recon.py` is a bounded local fallback for one scoped origin.
It is **not** proof that a platform-wide recon pass is complete, and it does not
replace the historical, freshness, aggregate, or handoff stages below.

If Ryushe asks to **design** recurring maintenance rather than invoke a full
pass, consult `/bounty-tools`' on-demand
`references/recon-maintenance-automation.md`. Its scheduler/queue contract is
explicitly proposed and offline-review-only; do not treat the existing
`recon_full.py`, `tool-run`, or `watch-runs` as that scheduler or enable a worker.

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

## Two Horizons: Baseline Then Continuous Enrichment

`full` establishes one thorough, durable **surface baseline**. Its goal is to
maximize authorized knowledge of hosts, DNS/IP/certificate relationships,
eligible services, virtual hosts, current and historical URLs, JavaScript, and
search/dork-derived candidates—not to deeply understand every application flow
or bundle before work can proceed.

The baseline is complete when all selected collection lanes have preserved raw
evidence and manifests, every promoted record is scope-checked and attributed,
the canonical aggregate is merged, and the remaining coverage gaps are named.
It is not complete merely because a tool ran, and it is not held open until
every route or JavaScript chunk receives deep review.

Subsequent browsing and scoped testing are **continuous enrichment**: new
browser routes, task-scoped agent-proxy observations, loaded JavaScript hashes,
parameters, redirects, service facts, and observed request shapes update their
normal stores (`/live-map`, `/js`, Recon Bus, `/url-ingest`, and `/map-store`).
They do not restart the full baseline. Re-run a Recon-Ry delta or a selected
collection lane only after a material deployment/scope change, a new coverage
gap, or freshness uncertainty.

Ordinary `/recon` does not fetch program/vendor documentation or public code
without a concrete mapping question. Program initialization `--mode full|api|params`
is the explicit exception: it includes bounded public-documentation **discovery**
by default; `--mode js --include-docs` also opts in. This is not a license to
fetch vendor code or treat linked assets as target scope. `/recon-docs` owns
source-attributed candidate collection; `/docs` reviews only justified Program
Doc topics.

## Full-recon lane plan

`agents/recon_full.py` is a **plan-only** coordinator receipt. It records the
applicable lanes and their ownership; it never bypasses a child skill's scope,
authentication, rate, browser, or live-action gate.

```bash
bbh agents/recon_full.py <program> --target <scoped-origin> --mode full \
  --include-proxy-history
```

A baseline/full plan contains these focused lanes:

1. `/recon-ry` — durable broad collection. Its existing completion handler owns
   GAU/Wayback/archive URL collection and promotion of its outputs into the
   canonical aggregate; do not duplicate those producers or that promotion from
   `/recon`.
2. `/live-map` — an approved browser/proxy collector records normal navigation,
   routes, loaded JS chunks, and observed API/GraphQL shapes. It maps before
   direct replay and does not blindly invoke state-changing operations.
3. `/js` — inventory broadly available JS from aggregate and runtime provenance;
   prioritize coverage and provenance before deep static review.
4. Optional bounded proxy-history intake via `/caido` or `/pwnfox` and
   `/live-map`; source history remains evidence, not a raw context dump.
5. `/focused-recon` — synthesize canonical aggregate evidence into target
   packets and coverage state after source receipts are available.

During collection, preserve concrete observed facts in MapStore and retain
plausible questions in the Hypothesis Ledger with `recon` plus a specific
surface tag and source/run evidence pointer. Neither is a finding and neither
starts automatic testing. Scheduled fuzzing, parameter mining, and permitted
service discovery remain a separate maintenance lane; full browser/docs
collection is user-invoked. Documentation is retrieved later only for a
concrete evidence-backed comparison question.

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

Before any **active** Recon-Ry profile, assess the whole saved scope, not just
the selected seed. A program may grant wildcard hosts **and** a restricted
exact origin/path elsewhere. The wrapper can accept `snap` (the default) or
`--profile full` for that mixed set while reducing the restricted URL to a hostname in its scope file;
the wildcard grant must not silently broaden a separately restricted asset.
Do not launch either broad profile on the mixed set unless program authorization explicitly
covers the resulting host-wide activity **or** every enabled active stage is
verified to exclude the restricted origin/path at request time. A seed-host
check or post-run output filter is not that proof. If unresolved, defer the
active broad run and handle the narrow asset only within its own passive/source
review boundary.

Use `/recon-ry` as the preferred durable broad producer when its freshness
receipt says `rerun` or `unknown -> rerun` and high-volume collection is
permitted:

```bash

bbh agents/recon_ry.py start <program> --url <scoped-domain-or-url>
```

This defaults to Recon-Ry's reduced `snap` profile even when `/recon --mode full`
selected the broad-collection phase. Use `--profile full` only when its extra
stages are explicitly chosen and approved. For exact-host scope, account for
**every eligible root host**; one-host smoke
is not scope-wide coverage. Do not convert a path-scoped repository/package
URL into a host-wide seed or enumerate sibling hosts from an exact-host grant;
name such assets as deferred source review. The current Recon-Ry scope filter
reduces root URLs to hostnames: it does **not** enforce scheme or port, and
post-run artifact filtering cannot undo an out-of-scope request. If the grant
is limited to a particular origin (scheme/port) or allowed path, do not run
active `exact-urls` stages until their request-level destinations are actually
constrained and verified, or the program separately approves the wider host
activity. Passive/source review remains available within its own rules.

For an authorized host-wide `exact-urls` run, check each enabled stage's
request behavior against saved scope before launch. Use a distinct
`--remote-project` for each host; starts default to the same program project.
Start the next host **only after** the previous detached job has completed and
its log/project receipt has been inspected; `--rate-limit-rps` is per project,
not an aggregate concurrent limiter. Do not use the detached multi-host queue
as an implicit containment or rate guarantee. Filter URL-bearing output to
saved scope before active follow-on use, but never treat that as request-level
protection. Authenticated recon is opt-in with an approved account alias; never
broaden auth to wildcard scope by default.

Record PID, remote project, log, profile, scope input, and rate configuration;
do not tail the long-running job. When it finishes, ingest/index the **recorded
project** with `agents/recon_ry.py ingest` if a Shared manifest/count receipt is
needed. Ingest each completed exact-host project with its own host target;
the helper does not descend from the program root into nested projects.

Use `/bounty-tools` + `tool-run` for bounded supplemental collection only when
current evidence names a gap that Recon-Ry does not cover. Preserve raw output,
then promote URL-like data through Recon Bus. Do not run overlapping noisy tools
against the same origin merely because they are available.

## Phase 2B — Eligible Surface-Expansion Lanes

For a `full` baseline, select the following independent evidence lenses only
when the saved scope and program rules permit them. They complement Recon-Ry;
they do not rerun its GAU, Wayback, or broad archive/URL stages. Start no more
than three workers concurrently, keep the parent responsible for rate budgeting
and promotion, and queue the rest after each return changes the map.

1. **DNS/IP/certificate correlation** — begin from approved wildcard hosts and
   preserve hostname ↔ A/AAAA/CNAME ↔ IP ↔ TLS certificate/SAN relationships,
   plus observation time and source. Historical DNS and public service sources
   are timestamped hints, not authorization. A shared IP, ASN neighbor, or
   co-hosted domain never expands scope.
2. **Scoped service and vhost inventory** — before any request, require an
   exact saved-scope hostname match or a program-declared CIDR; attribution
   alone is not enough. Record host × port × service evidence and use bounded
   virtual-host checks only for approved wildcard-domain candidates. Quarantine
   unattributed or correlation-only IP records instead of adding them to
   automatic queues.
3. **Targeted search/dork discovery** — run a modest, provider-compliant query
   set against approved domains or assets. Return source-attributed in-scope
   candidate URLs and hostnames; search results are leads, not current facts.
   Do not bypass CAPTCHAs, create bulk accounts, rotate identity, or read
   documentation/public code broadly during this baseline.

Each worker preserves raw provider/tool output in its managed run root and
returns only normalized candidates, evidence pointers, scope status, and stop
conditions. The parent validates attribution and current scope before Recon Bus
promotion. This preserves valuable legacy, migration, origin, and
DNS-invisible-surface discovery without turning correlation into authorization.

## Phase 3 — Historical Snapshot Difference (Evidence-Gap Lane)

Recon-Ry owns the broad archive URL inventory. Consume its completed raw output
and scope-filtered aggregate; do not launch a second GAU, Wayback, Waymore, or
other broad archive collector during a normal full pass. This lane runs only
when a named mapping question remains after that output is available.

1. Preserve and compare the completed Recon-Ry archive URL evidence with the
   current scope-filtered aggregate. Retain out-of-scope, third-party, and
   unattributed candidates as labelled raw/quarantine evidence.
2. For a named high-signal route, API, form, JavaScript/bootstrap/config file,
   callback/import/upload/export/auth path, or route that disappeared from
   the current crawl, query bounded Wayback CDX metadata. Deduplicate snapshots
   by content digest and select a bounded cohort: earliest, latest, and each
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
6. Treat later browser navigation, task-scoped agent-proxy evidence, newly loaded
   JS hashes, route/parameter observations, redirects, and approved service
   changes as incremental enrichment. Promote each through its owning contract
   rather than rerunning `full`; trigger a delta only for a material change,
   explicit coverage gap, or freshness uncertainty.

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

## Program initializer handoff

Treat **`init <program>`** as basic initialization. Explicit
**`init <program> full|js|api|params`** (and “initialize” equivalents) are
owning-agent workflows: resolve the named program/platform and published
scope/rules, run `bbh scripts/program_init.py <program> --platform <platform>
--mode <mode>`, then execute the generated handoff. Never infer a program or
silently downgrade to basic when collection is blocked. Do not dispatch on a
failed/partial initializer; report bootstrap and collection separately.

Basic creates directories, scope and front-door metadata only. Every non-basic
mode ensures a comparable `/recon` baseline: **full** adds scoped JS, API,
docs and parameters; **js** adds scoped JS; **api** ensures JS then maps API;
**params** ensures JS and API before `/parameter-mining`. Reuse verified current
producer receipts; refresh missing, incomplete or materially stale evidence.
The CLI writes a deterministic **pending plan**, not a completed run, at the
web (or API) lane's `recon/_meta/full-recon-handoff.json` for full or
`recon/_meta/init-<mode>-handoff.json` for a focused mode. Docs discovery is
default for full/api/params; `--include-docs` opts JS into it. Non-basic pulls
use `~/Shared/scopes` and reject alternate `--shared-root`, `--skip-scope`,
and empty saved scope; a dry run requires existing scope. Basic retains its
existing options and behavior.

### Owning-agent execution contract

The CLI writes only a proposal. The **owning Hermes agent**, not the CLI, must
execute the following after a named program and published rules are available:

1. Read the generated JSON and current saved scope/rules. Load the entry-chain
   policies above plus `resource-safety-policy` and `bb-script-rules` before
   scripts. Obtain approval for request-level destinations (origins, ports and
   paths), active/passive classes, redirects, and an **aggregate** rate budget
   across children. If mixed wildcard and restricted paths cannot be enforced
   at request time, block the broad active producer; post-filtering is not a
   substitute. No budget or scope approval means stop with a blocker, not an
   offline handoff called complete.
2. For **full**, dispatch two bounded independent workers with `delegate_task`:
   `full-recon` loads `/recon` and checks comparable baseline freshness first;
   `js-url-acquisition` loads `/js-pull` and `/live-map` on approved initial
   seeds. Start them together only when the shared rate/destination budget can
   contain both. The parent feeds newly scope-validated recon page/subdomain
   URLs into incremental JS acquisition; a newly found URL is not automatically
   an authorized request destination. For a focused mode, ensure the `/recon`
   receipt first, then ensure JS. Reuse current hash-addressed JS evidence,
   refreshing the stale or missing portion. A scoped surface with no JS gets an
   explicit no-JS receipt; API mapping may proceed from runtime/spec evidence.
   A detached Recon-Ry PID is not a completion receipt. Give workers exact
   seeds, scope/rate allocation, policy chain, output root and expected receipt;
   read their manifests and gaps, not merely their self-reports. Stop on
   challenge, repeated 429 or scope drift.
3. For **full/api/params**, after the JS checkpoint, assign
   `katana-endpoints` using only approved page/JS inputs. Check installed
   `katana -h`; use `-jc` with bounded memory/rate and request-level destination
   and redirect containment, or record an explicit skip receipt. Preserve raw
   output through `/bounty-tools`; do not duplicate Recon-Ry archives. Start
   bounded `public-docs` discovery concurrently with initial collection when
   selected, but wait for its completed/skip receipt before API mapping so
   documented operations are not silently omitted. Docs are claims, not scope.
4. Once JS, Katana and selected docs have receipts, assign `api-mapping` to
   `/api-surface-mapping`; keep declared/source routes distinct from observed
   operations and never invoke candidate operations as a discovery test. In
   **full** mode, API mapping may start from approved initial seeds while the
   broad `/recon` worker runs; do not gate it on detached Recon-Ry completion.
   When full recon completes, run `api-reconciliation` against its final
   discoveries, acquiring missing scoped JS and refreshing affected API records
   (or record an evidenced no-change result) before parameter mining and final
   promotion. Focused API/params instead require a comparable `/recon` receipt
   before JS and API. For **full/params**, after recon, JS, API and docs receipts,
   dispatch `/parameter-mining`: correlate query/path/body/header/form/GraphQL
   fields to operations and source pointers. Name-only vocabulary is not an
   accepted parameter or a runnable URL; no automatic active fuzzing follows
   collection.
5. **Recon Bus is the canonical corpus.** At each completed producer checkpoint,
   scope-check and promote attributed reusable full URLs (including
   parameterized URLs), JS URLs, eligible hosts and content paths through
   `/recon-corpus-write-policy` and Recon Bus `promote-run` or `append`.
   URL promotion probes new URLs by default: count those requests against the
   shared rate budget and enforce destination/redirect containment, or use
   deliberate record-only `--liveness unknown` / `--no-probe` until authorized.
   Preserve raw manifests and quarantine rejected candidates; never hand-edit
   aggregates, create a parallel flat corpus, or repeat Recon-Ry's own archive
   promotion. Downstream workers query Recon Bus for current input; source
   operation and name-only field records remain in their attributed run artifacts
   until they yield an eligible URL/route. After **all** selected producer
   receipts exist (and later discoveries are reconciled), verify promotion counts
   and run `url-ingest-review` through `/url-ingest` for bounded next packets and
   existing lane coverage.

Keep an owning run capsule with per-stage `completed`, `reused`, `skipped`,
`pending`, or `blocked` status, input manifests, freshness/coverage decisions,
Recon Bus promotion references and remaining gaps. If a child fails or is still
running, hold downstream dependencies and do not mark the mode complete. Reruns
refresh the generated **pending** handoff from scope; do not store worker progress
there. The CLI and `agents/recon_full.py` are plan-only; neither spawns workers
or runs target traffic. Do not replace supervised `delegate_task` with an
unapproved `hermes chat -q` launcher.
