# JavaScript Offline Fanout

Use this reference when Ryushe asks to "dig into the JS", "vuln test the JS",
"run JS deep", or otherwise spend agent budget on local JavaScript artifacts.

The purpose is broad offline depth: download once, review locally with many
lenses, synthesize, and hand only selected hypotheses to live testing later.

## Principles

- The classifier accelerates routing; it never excludes a class.
- Offline agents may fan out widely because they read local packets, not the
  target application.
- Live requests are not allowed in the offline campaign.
- Specialist agents stay in their lane but report off-lane primitives in a
  peripheral-vision field.
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
2. Build a local campaign from the inventory run:

   ```bash
   python3 agents/js_offline_campaign.py prepare \
     --js-run-root ~/Shared/web_bounty/<program>/web/recon/js/<run-id> \
     --mode deep
   ```

3. Inspect the generated command without starting agents:

   ```bash
   python3 agents/js_offline_campaign.py run \
     --campaign-root ~/Shared/web_bounty/<program>/web/recon/js/<run-id>/offline_campaign
   ```

4. Start the offline `zero_day_team` fanout only when that is the intended use
   of budget:

   ```bash
   python3 agents/js_offline_campaign.py run \
     --campaign-root ~/Shared/web_bounty/<program>/web/recon/js/<run-id>/offline_campaign \
     --execute
   ```

The wrapper hides the raw `zero_day_team` flags. The generated command uses a
local `offline_target`, `--hunt-type web` for storage routing, `--target-kind
web-js` for artifact identity, and `--brainstorm-only` so only the generated
web-JS profiles run.

## Modes

- `quick`: cartography, request-shape, DOM XSS, and anomaly lanes.
- `look`: cartography, request-shape, common web-JS lanes, anomaly, plus lanes
  triggered by cheap inventory signals.
- `deep`: broad web-JS class matrix plus anomaly.
- `full`: same current lane set as `deep`; reserved for future heavier modes.

## Expected Outputs

Offline campaign outputs live under:

```text
<js-run-root>/offline_campaign/
├── manifest.json
├── mapstore_candidates.jsonl
├── mapstore_candidate_schema.json
├── offline_target/
│   ├── index.json
│   └── packets/*.md
└── brainstorm/spec.md
```

The offline campaign should produce:

- reviewed findings when packet evidence is already strong enough
- MapStore gadget candidates for reusable primitives or app behavior
- endpoint/request-shape handoffs for `/analyze-endpoint`
- wordlist or route candidates for `/create-wordlists`
- live-validation hypotheses with exact provenance, ownership/rate/safety
  notes, and stop conditions

## MapStore Candidate Flow

Offline agents must not write durable `recon/maps/` observations directly.
When an agent sees reusable app memory, a gadget, a negative result, or
validation state that future agents may need, it appends one JSON object to:

```text
<js-run-root>/offline_campaign/mapstore_candidates.jsonl
```

The generated brainstorm spec uses the absolute path for this file because
`zero_day_team` workers run from per-agent working directories.

Use the generated schema:

```text
<js-run-root>/offline_campaign/mapstore_candidate_schema.json
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
