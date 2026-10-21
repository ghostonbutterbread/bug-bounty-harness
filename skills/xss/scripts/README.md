# XSS Scripts

Canonical home for deterministic helper scripts that support the XSS skill.

Agents should put reusable XSS automation here when the script belongs to the
vulnerability class rather than one target. The maintained canary helper and
the JS inventory's paired source/sink passes are documented below:

- Spec: `docs/xss-canary-reflection-mapper-spec.md`
- Script: `xss_canary_mapper.py`
- Purpose: ingest parameter, proxy, JavaScript, URL, and browser evidence; inject
  unique inert canaries; crawl/search for reflections; classify sink context;
  and write compact XSS-lane packets for agent reasoning.

Expected artifact shape for mapper-style scripts:

- `sources.jsonl` — candidate input vectors such as query params, body fields,
  headers, cookies, storage keys, form fields, and router params.
- `sinks.jsonl` — observed reflection or render locations.
- `edges.jsonl` — source-to-sink relationships with context and encoding notes.
- `agent_packets/*.md` — small handoff packets for `/xss`, `/reflected-xss`,
  `/stored-xss`, or `/dom-xss` workers.

Rules:

- Scripts collect and classify. Agents reason over high-signal edges.
- Prefer existing tools for discovery: Dalfox, kxss, Gxss, Dursgo, Katana,
  Arjun, proxy-store, JS analyzer, URL-ingest, and live-map outputs.
- Never write live cookies, bearer tokens, API keys, CSRF tokens, private
  configs, or other secrets into mapper artifacts.
- Keep live use scope-aware, low-rate, and tied to owned accounts/resources.

## `agents/xss_source_sites.py` (JS inventory pass)

- **Purpose:** Bounded static named-input review sites in the same JS artifacts
  scanned for sinks; not a standalone live scanner or proof of attacker control.
- **Runner:** `bbh agents/js_analyzer.py inventory <program> --input <js-url-list>
  --target-host <scoped-host>` via `/js`. The analyzer calls
  `scan_source_sites` on retained bundles and packetized source-map modules.
- **Outputs:** `source_sites` plus `source_sites_truncated` in `metadata.jsonl`
  and `source_map_modules.jsonl`; named sites in the matching review packets;
  counts and caps in `manifest.json`. Compare them with the sibling `sink_sites`
  and a route-bound parameter corpus; proximity/name overlap is not a flow.
- **Mutates:** Inventory artifacts only; the JS analyzer can fetch scoped JS and
  source maps under its normal controls. This module itself sends no requests.
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest -q agents/test_xss_source_sites.py
  agents/test_xss_source_integration.py agents/test_js_analyzer.py` from an
  isolated repository worktree.
- **Coverage:** Non-exhaustive, per-rule/asset capped static seeds. Some request
  body fields, dynamic keys, and backend writers require `/parameter-mining`
  and manual trace rather than this scanner.

## `agents/xss_sink_sites.py` (JS inventory pass)

- **Purpose:** Bounded static call-site and API/attribute review seeds for
  browser/framework HTML, script, URL and conditional interpreter sinks; not
  a standalone live scanner, taint trace or browser execution proof.
- **Runner:** `bbh agents/js_analyzer.py inventory <program> --input <js-url-list>
  --target-host <scoped-host>` via `/js`. The analyzer calls
  `scan_sink_sites` on retained bundles and packetized source-map modules.
- **Outputs:** `sink_sites` plus `sink_sites_truncated` in `metadata.jsonl`
  and `source_map_modules.jsonl`; matched signatures and offsets in review
  packets; counts and caps in `manifest.json`. Compare with `source_sites`
  and the actual caller, loaded route, and browser consumer.
- **Mutates:** Inventory artifacts only; the analyzer may fetch scoped JS and
  source maps under its normal controls. This module sends no requests.
- **Verification:** `agents/test_xss_sink_sites.py` and
  `agents/test_js_analyzer.py` in an isolated repository worktree.
- **Coverage:** Non-exhaustive, per-signature/asset capped static seeds; dynamic
  property names, unpacketized modules, server templates and runtime-only
  consumers require stack-specific and browser review.

## `xss_canary_mapper.py`

- **Purpose:** Plan inert canaries, scan saved or bounded live responses, and
  publish source-to-sink packets for agent-led XSS review.
- **Inputs:** Parameter, proxy, JavaScript, URL, browser, planned-request, and
  saved-response artifacts selected by the invoked subcommand.
- **Outputs:** `sources.jsonl`, `sinks.jsonl`, `edges.jsonl`, planned/private
  replay records, responses, and atomic agent packets under the declared output
  directory.
- **Mutates:** Local artifacts in every mode; `fetch` and `browser-fetch` also
  send scope-validated, rate-limited canary requests under explicit live-use
  controls.
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest skills/xss/scripts/test_xss_canary_mapper.py -q`
- **Owner/scope:** XSS skill.
- **Last verified:** 2026-09-10.
- **Coverage:** Reflection signatures and sink classifications are
  non-exhaustive seeds; misses remain unknown until agent review.

Plan canaries from URL/tool/source artifacts:

```bash
bbh skills/xss/scripts/xss_canary_mapper.py plan \
  --input urls-or-tool-output.txt \
  --out-dir /tmp/xss-map \
  --run-id target-001
```

Scan saved responses for the generated canaries:

```bash
bbh skills/xss/scripts/xss_canary_mapper.py scan \
  --sources /tmp/xss-map/sources.jsonl \
  --response saved-responses.jsonl \
  --out-dir /tmp/xss-map
```

One-shot fixture/offline use:

```bash
bbh skills/xss/scripts/xss_canary_mapper.py map \
  --input sources.jsonl \
  --response responses.jsonl \
  --out-dir /tmp/xss-map \
  --run-id target-001
```

`planned_requests.jsonl` records public redacted mutated GET URLs and marks
custom body/header/form sources for a future submitter. The paired
`private_replay_requests.jsonl` file is written with `0600` permissions and keeps
the raw replay URL for local live collection when the source URL contained
secret-looking query parameters.

## Live Collection

HTTP collection is live by default for the `fetch` command, but it requires
either saved program scope or an explicit host allowlist:

```bash
bbh skills/xss/scripts/xss_canary_mapper.py fetch \
  --planned /tmp/xss-map/planned_requests.jsonl \
  --out-dir /tmp/xss-map \
  --program target \
  --max-requests 20 \
  --rate-delay 0.5
```

Use `--offline` to make `fetch` write an empty `responses.jsonl` without sending
requests.

Browser collection uses Playwright when installed. This is useful for pages that
need JavaScript rendering or browser storage inspection:

```bash
bbh skills/xss/scripts/xss_canary_mapper.py browser-fetch \
  --planned /tmp/xss-map/planned_requests.jsonl \
  --out-dir /tmp/xss-map \
  --program target \
  --storage-state /path/to/playwright-storage-state.json
```

If a URL contains secret-looking query fields, public artifacts redact those
values. Live replay of that exact URL requires the private replay artifact and an
explicit `--allow-sensitive-replay` flag.

Safety rules enforced by the script:

- Live modes require saved `--program` scope or one or more `--allow-host` values.
- `--program` loads saved scope from `~/Shared/scopes/<program>/` with legacy
  bounty recon fallback; `--rate-delay` defaults to normalized policy fields
  when present, otherwise `0.5` seconds.
- Secret-looking query parameters are redacted in artifacts.
- Private replay URLs are stored only in `private_replay_requests.jsonl` with
  owner-only file permissions.
- Secret-bearing replay requires explicit `--allow-sensitive-replay`.
- The script does not accept raw cookie or authorization headers on the command
  line.
