# JavaScript Offline Fanout

Use this reference when Ryushe asks to "dig into the JS", "vuln test the JS",
"run JS deep", or otherwise spend agent budget on local JavaScript artifacts.

The purpose is broad offline depth: download once, review locally with
mapper-led category agents, synthesize, and hand only selected hypotheses to
live testing later. The intended high-level entrypoint is `agents/js_team.py`;
`agents/js_offline_campaign.py` is the lower-level adapter that builds the
offline target and brainstorm spec. `agents/js_offline_team.py` runs local JS
review workers with Hermes' `file` toolset only; it never calls zero_day_team.

## Principles

- The classifier accelerates routing; it never excludes a class.
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
2. Preview the staged JavaScript Team plan. Deep mode starts with only
   `js-general-map` and `js-anomaly-hunter`; follow-up categories are selected
   after reviewing their output. Without `--campaign-root` or `--write-plan`,
   this uses a temporary campaign and removes it after printing the plan:

   ```bash
   python3 agents/js_team.py dry-run \
     --js-run-root ~/Shared/web_bounty/<program>/web/recon/js/<run-id> \
     --mode deep
   ```

3. Run the planner/anomaly wave when agent budget is intended. Workers receive
   only local artifact paths and Hermes' `file` toolset; they have no terminal,
   web, browser, or proxy tools:

   ```bash
   python3 agents/js_team.py run \
     --js-run-root ~/Shared/web_bounty/<program>/web/recon/js/<run-id> \
     --mode deep \
     --stage planner \
     --execute
   ```

4. After reading mapper/anomaly reports, explicitly approve selected follow-up
   lanes, then run them:

   ```bash
   python3 agents/js_offline_team.py approve \
     --campaign-root ~/Shared/web_bounty/<program>/web/recon/js/<run-id>/offline_campaign \
     --lane api-request-contracts \
     --lane auth-account-tenant

   python3 agents/js_team.py run \
     --js-run-root ~/Shared/web_bounty/<program>/web/recon/js/<run-id> \
     --follow-up-lane api-request-contracts \
     --follow-up-lane auth-account-tenant \
     --stage follow-up \
     --execute
   ```

   Use `--auto-follow-up-from-signals` only when you want deterministic
   metadata-triggered follow-ups before mapper output has been reviewed.

5. To inspect the lower-level generated campaign directly, build it from the
   inventory run:

   ```bash
   python3 agents/js_offline_campaign.py prepare \
     --js-run-root ~/Shared/web_bounty/<program>/web/recon/js/<run-id> \
     --mode deep
   ```

6. For a no-aftermath dry run of the lower-level fanout adapter, preview
   the generated campaign and team command in a temporary directory. This does
   not start `zero_day_team`, does not make live requests, and removes the temp
   campaign by default:

   ```bash
   python3 agents/js_offline_campaign.py dry-run \
     --js-run-root ~/Shared/web_bounty/<program>/web/recon/js/<run-id> \
     --mode deep
   ```

   Add `--campaign-root <path>` or `--keep-artifacts` only when the generated
   spec needs to be inspected afterward.

7. Inspect the generated command from a kept campaign without starting agents:

   ```bash
   python3 agents/js_offline_campaign.py run \
     --campaign-root ~/Shared/web_bounty/<program>/web/recon/js/<run-id>/offline_campaign
   ```

8. Start the lower-level offline `zero_day_team` fanout only when one-shot
   all-lane execution is intentionally desired:

   ```bash
   python3 agents/js_offline_campaign.py run \
     --campaign-root ~/Shared/web_bounty/<program>/web/recon/js/<run-id>/offline_campaign \
     --execute
   ```

The wrapper hides the raw `zero_day_team` flags. The generated command uses a
local `offline_target`, `--hunt-type web` for storage routing, `--target-kind
web-js` for artifact identity, `--brainstorm-only` so only the generated web-JS
profiles run, and the policy-aware scheduler/category-master flags so the
runtime keeps using shared ledger/review/coverage primitives.

Default `--granularity category` creates broad agents:

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

Use `--granularity lens` only for deliberate high-budget runs that should
preserve the old narrow matrix (`js-dom-xss`, `js-idor`, `js-payment`, etc.).

## Modes

- `quick`: planner, client-side trust, API/request contracts, and anomaly.
- `look`: planner, common web-JS categories, anomaly, plus categories triggered
  by cheap inventory signals.
- `deep`: the full broad category set.
- `full`: same current category set as `deep`; reserved for future heavier
  modes.

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
