---
name: js-hunt
description: Use when hunting JavaScript for behaviors, hidden surfaces, and testable security leads.
---

# JavaScript Hunt

An unqualified “hunt the JavaScript” runs this **whole adaptive methodology**.
The agent maps the app's client-visible behaviors, chooses consequential or
unusual flows, traces them deeply, and hands off specific questions. It does
not stop at endpoint extraction, run a fixed vulnerability-class matrix, or
claim exhaustive coverage from a scanner. Collection mechanics belong to
`/js-pull`; class-specific live validation belongs to the owning skills.

## Connect the code with the application

For a live JS hunt, the parent can use `live-map` and the task browser/proxy to
understand the relevant feature, actual request and loaded assets, then trace the
corresponding code; a source-derived action or consumer can in turn guide the
next browser observation. Use `technology-research` when a stack detail changes
the question. Correlate the page, flow and asset; code alone does not establish
current reachability or server enforcement. A strong lead need not wait for a
complete map or inventory. Explicitly offline work stays offline; offline workers
never send target requests. Collection-only requests remain collection-only.

## Start and Focus

- For an unqualified standalone hunt, assess whether existing material is
  sufficient for a meaningful hunt: consider relevance to app feature families,
  account/flow coverage, provenance, freshness, and known gaps, not file count
  alone. Reuse suitable artifacts. If inventory is missing or insufficient, use
  `/js-pull` to acquire missing scoped material when live collection is
  permitted. Existing recon/proxy URLs and task-browser observations can seed
  collection; drive relevant features to discover runtime and lazy-loaded
  assets as useful. Review completed material incrementally and return to
  meaningful unreviewed families after following a strong lead. If collection
  fails or is blocked, continue with available artifacts and report failed,
  unattempted, and missing coverage; do not claim a complete hunt.
- Trace a strong lead or available local artifact immediately; an inventory is
  not a prerequisite. Explicitly offline work uses available artifacts with no
  network collection and names missing material as a gap. Collection-only work
  stops after collection. For a narrower current question, collect only what is
  useful to that question when permitted, not an automatic broad campaign.
  Use whichever inventory metadata, provenance and complete packet paths exist.
  An interrupted inventory may lack final indexes or provenance: review its
  complete packets and record missing metadata as gaps, without resuming
  acquisition in offline work. Work in bounded
  page/flow, bundle-family, route-cluster, or module packets, not a giant prompt.
  Read `source_sites` beside `sink_sites` in bundle and source-map module rows;
  account for truncated/capped sites before declaring a source or sink absent.
  A shared file or nearby offset is a review lead, not a proven data-flow edge.
- For a standalone local artifact without an inventory, inspect the available
  file and relevant local context directly, citing the path and function or
  offsets. Record unavailable provenance and unreviewed material as gaps; do not
  invent a URL, packet, page/flow, request, library entry, or coverage. Skip
  inventory-only queries and observation writes when their inputs do not exist.
- **Only when the library exists**, scope the queue from recorded coverage, not
  from run names. If library records are unavailable, review available files or
  complete packets and report the unknown queue and coverage as gaps instead.
  Content-review
  state lives in sha256-keyed `js_observations` in the library's
  `js_info.sqlite`; `/js-pull` owns writing it and defines the status vocabulary.
  An observation records **depth**, not completion. `/url-ingest` owns per-lane
  URL/parameter *testing* state — a different question, so consult both.
  Selecting run roots by name prefix resembles a currency filter but is not one,
  and can silently drop whole in-scope hosts while the totals still look large;
  group by host and state per-host never-observed, shallow/unknown, and
  deep-claimed counts before
  calling a queue scoped. Use the following two **disjoint** content queues;
  multiple observations may exist for a hash, so a shallow row must not put a
  hash with a deep claim in both queues:

  ```sql
  -- tier 1: no observations for this content
  SELECT DISTINCT a.js_url, a.sha256 FROM js_url_aliases a
  WHERE NOT EXISTS (SELECT 1 FROM js_observations o WHERE o.sha256 = a.sha256);

  -- tier 2: observed, but no deep-review status claim (evidence unchecked)
  -- includes swept, triaged, legacy observed, and unrecognized statuses
  SELECT DISTINCT a.js_url, a.sha256 FROM js_url_aliases a
  WHERE EXISTS (SELECT 1 FROM js_observations o WHERE o.sha256 = a.sha256)
    AND NOT EXISTS (
      SELECT 1 FROM js_observations o WHERE o.sha256 = a.sha256
        AND o.status IN ('deep_reviewed', 'exhausted')
    );
  ```
  Audit unrecognized statuses **independently** of those two queues: a hash may
  have both a deep claim and an unknown-status observation, so the tier 2 query
  alone cannot reveal every legacy/unknown row.

  ```sql
  SELECT DISTINCT a.js_url, a.sha256, o.status FROM js_url_aliases a
  JOIN js_observations o ON o.sha256 = a.sha256
  WHERE o.status IS NULL OR o.status NOT IN
    ('swept', 'triaged', 'deep_reviewed', 'exhausted');
  ```
  Inspect evidence behind `deep_reviewed`/`exhausted` before excluding that
  content from a **specific lens/flow** queue; these content-level queries are
  coarse status summaries, not evidence checks. Exclusion from tier 2 is not
  verification of complete coverage across features or lenses. Reconcile
  unknown statuses; do not count them as completed coverage.
- Default **broad hunt**: survey all meaningful application-owned feature
  families represented in the inventory, including a classless anomaly pass.
  Rank then deep-review selected flows. When inventory is too large, declare
  which families were sampled and which remain unreviewed; no fixed number of
  leads or agents substitutes for a coverage decision.
- Narrow hunt: `--focus endpoints`, `--focus params`, `--focus secrets`,
  `--focus application-logic`, or `--focus dataflows`. These are named views of
  the same pipeline, not separate parsers or mandatory subagent roles. Spend
  depth on the requested view, and report strong adjacent evidence without
  pretending to have broadly reviewed other areas. Natural-language synonyms
  route here too.

## 1. Behavior Map and Deep Trace

Load `/js` and read its `skills/js/references/analysis-lens.md` (relative to the
BBH repository root) for the canonical behavior
map, request builders, state and authority, secrets and anomalies, prioritization,
source-to-consumer deep trace, evidence ladder and specialist handoffs. Apply the
same lens to the current packet or broader campaign; do not maintain a second
analysis methodology here. For a sink/signature inventory, the lens routes to
`references/static-signal-review.md` under this skill. Revisit broad coverage
before ending so a strong lead does not silently replace the remaining hunt.

## 2. Campaign Coverage and Handoff

For each selected lead, retain controllability, observed versus inferred edges,
a hypothesis, missing proof and the next discriminator. Live validation is a
separate policy-governed step on scoped, owned resources; offline workers never
send target requests. Treat third-party URLs as context, not automatic scope.

Output three bounded sections:

1. **Surface map:** feature families, actions, request/field vocabulary, and
   noteworthy decisions or data flows with evidence pointers.
2. **Selected lead packets:** behavior and why it matters; exact local evidence
   and available JS URL, sha256, packet path, page/flow and request reference;
   source-to-consumer or transaction trace; controllability; observed versus
   inferred edges; missing proof; next discriminator; owning specialist skill.
3. **Coverage and handoffs:** reviewed and unreviewed bundle/flow families,
   truncated maps or missing runtime evidence, candidate wordlists/contracts,
   and separate scoped live-validation hypotheses. When the required inventory
   records exist, mark `/url-ingest` inventory versus `deep_reviewed` only for what
   was actually reviewed, and record per-chunk content coverage through
   `js_analyzer.py observe`; coverage stated only in synthesis prose is not
   queryable and gets re-done. If records are absent, including in an interrupted
   inventory, report exact local coverage and its limits rather than creating or
   claiming indexed coverage. Send useful
   verified observations through `/map-store` and durable notes, not raw bundle
   dumps; dedupe run-local proposals before promoting.

Use the analysis lens's specialist routes, including `rce-deserialization`
for encoded round-tripped state or a behavior-capable object-loader lead. The
specialist owns discovery cues and proof; client encoding alone does not prove a
backend loader.

## Scale and Execution

For a small run, the parent can inspect bounded packets itself. For independent
packets, use the native fanout in `skills/js/references/offline-fanout.md`:
role-based surface map and anomaly review, then a focused tracer only when
warranted, with at most three active JS-review subagents. The parent allocates
bounded packets, verifies cited functions, merges duplicates, and covers gaps
without spawning one worker per vulnerability class. Store each worker report
separately under `native_fanout/`. No repository-specific team runner and no
live validation inside this offline pass. `deep` means more evidence-selected
tracing; `offline-fanout` names the optional execution strategy, not another
method.

### Example handoff (illustrative, not a finding)

A workspace invite builder sends `workspaceId`, `email`, and `role`; a UI picker
supplies `viewer`. The JS shows the client's allowed values and request shape,
**not** the server's authorization. The lead asks whether this actor can assign
other roles to an owned workspace member; an observed request and a bounded
owned-account comparison would belong to `/analyze-endpoint` and then
`/access-control`. Until then, status is **requires server confirmation**.
