# Live Map Playbook

## Purpose

Build a reusable runtime application map before vulnerability-specific testing.

The goal is to make agents explore from observed app behavior instead of from leaked vulnerability labels. A scout maps routes, flows, object references, auth boundaries, and state-changing actions. Focused child agents receive only narrow map slices.

## Relationship To Other Maps

- `/appmap`: source/static map for local code, extracted apps, binaries, and generated brainstorm specs.
- `/mental-map`: human-readable flow notes from Caido/proxy traffic.
- `/live-map`: universal runtime JSONL map from browser, proxy, manual, or hybrid observations.

Use `/live-map` for live web testing and any case where future agents should reuse previously explored areas.

## Storage

Canonical output:

```text
$HARNESS_SHARED_BASE/{program}/agent_shared/application-map/
```

Files:

- `manifest.json`: schema, version, artifact names, timestamps.
- `routes.jsonl`: observed absolute URLs/endpoints, method, status, auth state, tags.
- `flows.jsonl`: grouped user journeys such as login, profile, upload, checkout, invite, export.
- `objects.jsonl`: object references observed in paths/query/flows.
- `auth-boundaries.jsonl`: behavior differences between logged-out, user A, user B, admin/owner, tenant A/B.
- `state-actions.jsonl`: create/update/delete/finalize/export/upload/invite/reset actions.
- `hypotheses.jsonl`: candidate testing lanes inferred from symptoms.
- `handoffs/*.json`: bounded child-agent packets.
- `summary.md`: current map counts and usage notes.

## Exploration Modes

### Browser

Use browser navigation when you need real UI behavior:

- visit home/dashboard/account/search/profile/settings areas
- click through reachable menus and workflow starts
- record routes with auth state and short notes
- avoid destructive actions unless the account/resource is marked destructible

### Proxy

Use proxy traffic when you need request order or hidden API calls:

- capture one flow at a time
- keep state-changing requests, redirects, token fetches, validation calls, and final status checks
- drop analytics, static assets, duplicate polling, and unrelated third-party traffic
- normalize into route/flow/object/action observations before ingesting

### Hybrid

Use hybrid when source/static AppMap exists:

- point live routes to static route/controller/component evidence when available
- keep raw static AppMap artifacts in their own run root
- store only pointers or summaries in live-map observations

## Observation JSONL

Each line can be a route:

```json
{"type":"route","method":"GET","url":"https://target.example/my-account?id=wiener","status":200,"auth_state":"user:wiener","title":"My account"}
```

Or a manual flow:

```json
{"type":"flow","name":"profile update","flow_type":"user-profile","entry_url":"https://target.example/my-account","auth_state":"user-a","routes":["R0001","R0002"]}
```

Or an auth boundary:

```json
{"type":"auth-boundary","route":"GET /admin","logged_out_status":302,"user_status":403,"admin_status":200}
```

## Workflow

1. Initialize the map:

```bash
python3 agents/live_map.py init <program>
```

2. Add browser-discovered routes:

```bash
python3 agents/live_map.py add-route <program> \
  --url "https://target.example/my-account?id=wiener" \
  --method GET \
  --auth-state user-a \
  --source browser
```

For blind training runs, do not store page titles or lab/challenge hints in the map:

```bash
python3 agents/live_map.py add-route <program> \
  --url "https://target.example/admin" \
  --source browser \
  --blind-mode
```

3. Ingest normalized proxy/manual observations:

```bash
python3 agents/live_map.py ingest <program> --input observations.jsonl --source proxy
```

Use blind ingestion for PortSwigger or other challenge platforms where raw browser/proxy observations may include lab titles, breadcrumbs, banners, or challenge descriptions:

```bash
python3 agents/live_map.py ingest <program> --input observations.jsonl --source browser --blind-mode
```

4. Build child-agent packets:

```bash
python3 agents/live_map.py build-handoffs <program> --skill access-control
```

For blind training runs, especially PortSwigger labs where the live page can expose the lab name in the top-left banner, build blind packets:

```bash
python3 agents/live_map.py build-handoffs <program> --skill access-control --blind-mode
```

5. Spawn child agents using only the packet and the relevant skill pack.

## Symptom Routing

Route by observed app artifacts, not vulnerability labels:

- Object IDs, GUIDs, user/account/profile parameters -> `/access-control` horizontal pack.
- Org/workspace/team/project/tenant IDs -> `/access-control` tenant pack.
- Role, permission, admin, owner, plan hints -> `/access-control` vertical pack.
- Export, attachment, file, media, CDN, signed-link routes -> `/access-control` storage-links pack.
- Wrong-order, stale state, replay, skipped step -> `/access-control` workflow pack.
- Logged-out/authenticated/expired-session deltas -> `/access-control` auth-state pack.
- GraphQL `id`, `node`, `gid`, cursor, batched resolver args -> `/access-control` GraphQL-BOLA pack.
- Method/header/path/parser discrepancies -> `/bypass`.
- State-changing forms with weak token/origin signals -> `/csrf`.
- Repeated submit/finalize/checkout/invite/delete actions -> `/race`.

## Handoff Rules

Child agents get:

- one hypothesis
- the smallest relevant routes
- related object references
- account/resource boundary and destructible status when known
- one skill pack path
- stop condition

Child agents do not get:

- vulnerability title or expected class
- page title, lab title, breadcrumbs, or top-page training-lab banners
- solution text
- raw page/proxy dumps
- unrelated map history
- cookies, bearer tokens, passwords, auth headers, reset links, or verification codes

## Blind Mode

Use `--blind-mode` when training pages, lab platforms, or challenge wrappers leak the expected vulnerability class through titles, banners, breadcrumbs, or lab status headers.

Blind mode:

- removes title-like and freeform hint fields from stored observations when ingesting with `--blind-mode`
- removes `title` and freeform `notes` from route records before writing child handoff packets
- adds a `blind_mode` block with a browser redaction snippet
- tells the child to ignore page titles, lab banners, breadcrumbs, and back-to-lab links

For blind benchmark runs, use `--blind-mode` at both ingestion and handoff time. Otherwise the map itself can become a side channel even if the final child packet is redacted.

The parent or scout may run the packet's `blind_mode.browser_redaction_js` in the live browser before capturing snapshots for a child. This should be done before the child sees browser DOM. The snippet is for hiding training-lab chrome only; it is not proof and it is not a target bypass.

## Proof Standard

The live map is not a finding. It only creates leads.

Promote only after a child agent proves unauthorized read, list, export, write, delete, workflow transition, privileged action, or cross-tenant access using approved owned accounts/resources.
