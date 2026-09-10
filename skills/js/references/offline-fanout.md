# JavaScript Offline Fanout

Use this reference when Ryushe asks to "dig into the JS", "vuln test the JS",
"run JS deep", or otherwise spend agent budget on local JavaScript artifacts.

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
- Prefer the active Hermes profile's configured fast/low-cost delegation model
  for high-volume packet review. Do not encode provider or model names in BBH;
  when no delegation override is configured, children inherit the parent.
- Offline agents should fan out by broad attack-surface category by default.
  Use the old narrow lens matrix only when Ryushe intentionally chooses that
  spend.
- Live requests are not allowed in the offline campaign.
- Category agents stay in their broad family but report narrower specialist
  follow-up needs in a peripheral-vision field.
- Always include a classless anomaly lane when budget allows.
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
   packet JavaScript.
2. Read the run's `manifest.json`, `metadata.jsonl`, `packets.jsonl`, and any
   `source_map_modules.jsonl`. Group related packet paths by page, bundle family,
   route cluster, or source-map boundary. Keep each worker's input bounded and
   independent; do not paste full bundles into prompts.
3. Call the active agent's native delegation tool with a first-wave batch:
   one or more general-map workers plus a classless anomaly worker. Each task
   packet includes exact local paths, relevant provenance rows, the offline-only
   boundary, and a structured output contract requiring cited evidence,
   confidence, missing proof, and suggested follow-up category.
4. Let Hermes apply the profile's configured delegation model. Prefer a
   fast/low-cost sibling tier for this volume pass, but never hardcode names or
   claim that routing occurred when children inherited the parent model.
5. The parent model reads the returned reports, checks cited packet/function
   evidence, merges duplicates, and rejects unsupported regex-only claims.
6. Dispatch a second native batch only for categories supported by stage-one
   evidence. Keep the classless anomaly lane in the first wave so classifier
   misses do not become exclusions.
7. The parent synthesizes selected results into findings, MapStore candidates,
   endpoint/request-shape handoffs, wordlists, or policy-governed
   live-validation hypotheses. Native workers remain offline throughout.

Default native fanout uses broad task categories:

- `js-general-map`: planner and JavaScript surface map
- `js-client-side-trust`: DOM, postMessage, storage, workers, browser trust
- `js-auth-account-tenant`: auth, ATO, access control, IDOR, tenants
- `js-api-request-contracts`: API clients, request shape, GraphQL, headers,
  parser/normalization
- `js-import-export-fetch-media`: uploads, imports, exports, URL fetchers,
  webhooks, media/file flows
- `js-commerce-feature-logic`: payment, entitlements, feature gates, cache,
  workflow state
- `js-secrets-config-integrations`: usable secrets, config, external pivots
- `js-anomaly-hunter`: classless weirdness and missed assumptions

Use narrow lens workers only for deliberate high-budget follow-up
(`js-dom-xss`, `js-idor`, `js-payment`, etc.); do not eagerly create the old
fixed matrix.

## Modes

- `quick`: a small general-map/anomaly batch, then at most the strongest
  evidence-selected follow-up.
- `look`: general map, anomaly, and common evidence-selected categories.
- `deep`: bounded first-wave fanout followed by all justified broad categories.
- `full`: same staged shape as `deep`, with a larger explicitly approved budget.

## Expected Outputs

Native fanout outputs live under:

```text
<js-run-root>/native_fanout/
├── mapstore_candidates.jsonl
├── synthesis.md
└── reports/
    ├── general-map-01.json
    └── anomaly-01.json
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
