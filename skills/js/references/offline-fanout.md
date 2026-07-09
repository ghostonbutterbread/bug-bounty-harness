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

Do not let offline agents validate against the live app directly. Live testing
starts from the selected hypothesis queue and follows `live-testing-policy`.
