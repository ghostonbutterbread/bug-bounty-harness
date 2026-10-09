# JavaScript Offline Fanout

Use this reference from `/js-hunt` when the inventory has enough independent
packets for native-subagent review. An unqualified "hunt the JavaScript" runs
the adaptive methodology whether or not fanout is warranted; this reference
only owns the optional offline execution strategy.

The purpose is broad offline depth: download once, review locally with native
subagents, synthesize in the parent model, and hand only selected hypotheses to
live testing later. There is no repository-specific JavaScript team runner. The
active parent reads inventory artifacts and directly dispatches bounded worker
tasks through its native delegation capability.

## Principles

- The classifier accelerates routing; it never excludes a class.
- Script outputs are deterministic seed sets, not exhaustive coverage. Hits are
  starting places; misses are not evidence that a technology, bundle, or class
  was fully searched. Agents own unfamiliar and semantic interpretation.
- Use the active CLI's native subagents and ask its native model selector or
  advertised model list for the fast option in the parent's family/generation.
  Do not encode provider or model names in BBH. If that CLI cannot make the
  selection, use its configured worker model or inherit the parent without
  claiming a cheaper route.
- Delegate by complementary **review role**, not vulnerability class or one
  subagent per packet. Default to at most three active JS-review subagents in
  the run: surface/behavior map, classless anomaly review, and one focused
  transaction/dataflow tracer when evidence warrants it. The parent owns
  packet allocation and synthesis; reuse a role across bounded packets or
  inspect remaining packets directly. Do not multiply roles when volume grows.
  Count other active JS-review workers against the same three slots and release
  a slot before a follow-up. Narrow specialist follow-up belongs to a separate
  policy-governed validation task, not an enlarged offline team.
- Live requests are not allowed in the offline campaign.
- Role workers keep peripheral vision and report narrower specialist follow-up
  needs without spawning a class-specific worker for each lead.
- Include a classless anomaly pass in the first wave when delegating.
- Promote outputs into findings, MapStore gadget candidates, endpoint handoffs,
  or live-validation hypotheses.
- Treat MapStore as lazy retrieval, not prompt baggage. Query it when current
  evidence gives a concrete URL, surface, field, or tag set.
- Missing MapStore context means a lead is unlinked/new-to-current-index, not
  automatically globally novel.
- Agents write MapStore proposals to the run-local candidate file; a later
  synthesis/promoter pass decides what becomes durable MapStore memory.

## Flow

1. Run `agents/js_analyzer.py inventory` to collect, hash, dedupe, chunk, and
   packet JavaScript. Pass an explicit `--run-id` or `--output-root` when early
   packet review is intended so the consumer knows the run root. During a long
   run, newly visible `packets/*.md` and
   `source_map_packets/**/*.md` files are complete atomic publications and may
   be reviewed immediately; final JSON/JSONL indexes are available only after
   inventory finishes.
2. After completion, read the run's `manifest.json`, `metadata.jsonl`,
   `packets.jsonl`, and any `source_map_modules.jsonl`. Group related packet
   paths by page, bundle family, route cluster, or source-map boundary. Keep each
   worker's input bounded and independent; do not paste full bundles into
   prompts.
3. If independent packets justify delegation, dispatch a first wave with at
   most two complementary roles: surface/behavior mapper and classless anomaly
   reviewer. Divide packets between them; the parent reviews uncovered packets
   or gives a role another bounded packet after it returns. Each task includes
   exact local paths, provenance, the offline-only boundary, and a structured
   output contract requiring cited evidence, confidence, missing proof, and
   suggested follow-up.
4. Let the active CLI apply its native model routing. Ask its model selector or
   advertised model list for the current fast sibling of the parent model's
   family/generation. Never guess or hardcode the name; when selection is not
   available, use the configured worker or inherited parent and report that
   fallback honestly.
5. The parent checks cited packet/function evidence, merges duplicates, and
   rejects unsupported regex-only claims.
6. For a selected transaction or dataflow requiring depth, assign a focused
   tracer as the third role, or recycle a freed slot. Do not dispatch a batch
   per attack class. The parent retains coverage ownership and performs any
   remaining synthesis itself.
7. Synthesize selected results into findings, MapStore candidates, endpoint/
   request-shape handoffs, wordlists, or policy-governed live hypotheses.
   Native workers remain offline throughout.

The three complementary roles are `js-surface-map`, `js-anomaly-review`, and
`js-focused-trace` (only when warranted). Assign each a distinct packet and
output path; a role can cover multiple related features over successive bounded
assignments. `quick`, `look`, `deep`, and `full` adjust review depth and packet
coverage, not the number of worker roles or the three-active-worker limit.

## Expected Outputs

Native fanout outputs live under:

```text
<js-run-root>/native_fanout/
├── mapstore_candidates.jsonl
├── synthesis.md
└── reports/
    ├── surface-map-01.json
    └── anomaly-review-01.json
```

Give each worker a unique report path. Parallel workers do not append to a
shared artifact; the parent verifies and combines their candidate objects.

The native fanout should produce:

- reviewed findings when packet evidence is already strong enough
- MapStore gadget candidates for reusable primitives or app behavior
- endpoint/request-shape handoffs for `/analyze-endpoint`
- wordlist or route candidates for `/create-wordlists`
- live-validation hypotheses with exact provenance, ownership/rate/safety
  notes, and stop conditions

## MapStore Candidate Flow

Offline agents must not write durable `recon/maps/` observations directly.
When a worker sees reusable app memory, a gadget, a negative result, or
validation state that future agents may need, it returns a candidate object in
its report. After evidence review, the parent serializes accepted candidates to:

```text
<js-run-root>/native_fanout/mapstore_candidates.jsonl
```

Required candidate fields:

- `kind`: `mapstore_candidate`
- `surface`: MapStore surface or JS lane, such as `js/access-control`
- `scope`: `app`, `surface`, or `url`
- `tags`: search tags such as `js`, `gadget`, `negative`,
  `needs-live-validation`, and the relevant vuln class
- `title`: short durable observation title
- `body`: concise reusable behavior or primitive
- `evidence_refs`: packet, manifest, provenance, or report paths
- `promote_reason`: why future agents should see this
- `dedupe_hint`: stable key for merging similar candidates before promotion

The synthesis/promoter pass queries existing MapStore, dedupes candidates, and
promotes only useful durable observations. If a query has no match, the lead is
new-to-current-index; continue normal analysis and avoid claiming global
novelty from absence alone.

Do not let offline agents validate against the live app directly. Live testing
starts from the selected hypothesis queue and follows `live-testing-policy`.
