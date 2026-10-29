---
name: live-map
description: "Build runtime application maps from browser exploration, proxy traffic, manual observations, or hybrid source/runtime evidence."
---

# Live Map

Use this for runtime application mapping, including mapping inside a
vulnerability-specific investigation. The question below is a mapping lens,
not a requirement to initialize the universal map for every specialist probe;
specialist testing and lineage stay with the relevant class skill. The Load
Order applies when building that universal runtime map.

## Connect the application views

For live application behavior, use the authorized task browser and its task-MITM
to explore relevant features, user actions, requests, and state changes.
`browser-session-policy` also permits direct HTTP for small, known-shape
questions. Let runtime and available source evidence inform each other rather
than treating one as a prerequisite for the other:

- **Runtime → source:** use the observed page, interaction, request and loaded
  assets to select relevant JavaScript, source maps or available local code.
- **Source → runtime:** use a discovered input, action, transform or consumer
  to choose a useful live observation, then return to the code with what the
  browser and proxy show. `js` owns web-JS collection and tracing; `appmap`
  applies to available local source or extracted binaries, not every website.
- Use `technology-research` when a concrete stack question can change the next
  investigation; do not assume an observed library is active in every flow.

Preserve page/flow and asset provenance; distinguish code-derived possibilities
from actual browser/proxy behavior, server effects and proven impact. Missing
lenses remain unknown, not evidence of absence. A complete map, source census,
or stack sweep is not a prerequisite to following a strong authorized lead.
Explicitly offline work stays offline. `browser-session-policy` owns the browser
and its live-action boundary; specialist skills own class-specific testing.

## Consumer question

While mapping a user-influenced value or state change, ask: **Where else can
this value go, and who might consume it after this point?** Follow observed
behavior to later processors, stored views, or effects. Distinguish evidenced
consumers from plausible but unverified next steps; record an unobserved
boundary as unknown. A safe first render settles only that render. This is
not an exhaustive consumer census or permission to test an external service
outside the program's scope.

## Capability promotion

The JSONL runtime map records observed routes and flows; it is not the
MapStore's named Application Behavior index. When a concrete, user-influenceable
parser, attachment pipeline, renderer, fetcher, or transform is evidenced,
write the supporting URL observation to `/map-store` first, then create or
update one named Behavior with its existing MapStore-relative observation paths.
Keep the behavior factual: observed controls and consumers versus unknown next
boundaries. A negative class test does not erase the evidenced capability;
put deliberate probes in Attempts and unresolved exploit reasoning in the
private Hypothesis Ledger. A Lead needs a separate bounded security question.

For a material browser-backed or stateful surface, correlate available client
JavaScript/request builders, normal owned-session browser flow, and task-MITM
request evidence; label an unavailable lens as a coverage gap, not a made-up
observation or a universal block on mapping. The full procedure and CLI
contract remain with `/map-store` and `prompts/live-map-playbook.md`.

`/live-map` complements `/appmap`:
- `/appmap` maps local source or extracted binaries.
- `/live-map` maps runtime behavior from browser navigation, proxy traffic, and manual observations.
- `/mental-map` remains the detailed flow-note workflow; `/live-map` writes the universal JSONL map that other skills can query.

## Load Order

1. Read `prompts/live-map-playbook.md`.
2. Read scope, live-testing policy, and approved account context.
3. Initialize or load `$HARNESS_SHARED_BASE/{program}/agent_shared/application-map/`.
4. Capture or ingest one small exploration slice at a time.
5. Build bounded handoff packets before spawning child agents.

## Commands

```bash
bbh agents/live_map.py init <program>
bbh agents/live_map.py add-route <program> --url https://target.example/my-account?id=123 --auth-state user-a --source browser
bbh agents/live_map.py add-route <program> --url https://target.example/admin --source browser --blind-mode
bbh agents/live_map.py ingest <program> --input observations.jsonl --source proxy
bbh agents/live_map.py ingest <program> --input observations.jsonl --source browser --blind-mode
bbh agents/live_map.py build-handoffs <program> --skill access-control
bbh agents/live_map.py build-handoffs <program> --skill access-control --blind-mode
bbh agents/live_map.py summary <program>
```

## Output

Writes to:

`$HARNESS_SHARED_BASE/{program}/agent_shared/application-map/`

Primary artifacts:
- `routes.jsonl`
- `flows.jsonl`
- `objects.jsonl`
- `auth-boundaries.jsonl`
- `state-actions.jsonl`
- `hypotheses.jsonl`
- `handoffs/*.json`
- `summary.md`

## Child-Agent Rule

Do not pass page titles, lab titles, external Academy/training-platform hrefs, solution text, raw proxy dumps, cookies, bearer tokens, passwords, or broad app history to child agents.

For PortSwigger or any training target that exposes the lab name in the page chrome, use `--blind-mode` while ingesting observations and while building packets. The map should store neutral runtime observations, not lab titles or challenge hints. Blind packets also include browser redaction JavaScript that the parent/scout can run before child snapshots.

When extracting links in blind mode, keep same-origin links only. Discard external Academy/training-platform URLs before logging or handing data to child agents; their slugs can reveal the lab.

Pass only the handoff packet plus the relevant skill pack. The child should treat map entries as exploration leads, not proof.
