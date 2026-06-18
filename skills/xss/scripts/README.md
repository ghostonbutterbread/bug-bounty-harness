# XSS Scripts

Canonical home for deterministic helper scripts that support the XSS skill.

Agents should put reusable XSS automation here when the script belongs to the
vulnerability class rather than one target. The first planned script is the XSS
canary reflection mapper:

- Spec: `/home/ryushe/projects/bug_bounty_harness/docs/xss-canary-reflection-mapper-spec.md`
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

## Canary Reflection Mapper

Plan canaries from URL/tool/source artifacts:

```bash
python3 skills/xss/scripts/xss_canary_mapper.py plan \
  --input urls-or-tool-output.txt \
  --out-dir /tmp/xss-map \
  --run-id target-001
```

Scan saved responses for the generated canaries:

```bash
python3 skills/xss/scripts/xss_canary_mapper.py scan \
  --sources /tmp/xss-map/sources.jsonl \
  --response saved-responses.jsonl \
  --out-dir /tmp/xss-map
```

One-shot fixture/offline use:

```bash
python3 skills/xss/scripts/xss_canary_mapper.py map \
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
python3 skills/xss/scripts/xss_canary_mapper.py fetch \
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
python3 skills/xss/scripts/xss_canary_mapper.py browser-fetch \
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
