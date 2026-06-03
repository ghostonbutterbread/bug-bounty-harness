# Intercepted Proxy Playbook

Use this playbook when a live test needs browser-generated traffic to pass through Caido before the agent captures or modifies anything.

## Goal

Make intercepted proxy work reproducible:

1. choose the correct proxy route for the runtime
2. launch the browser with the actual proxy listener
3. enable intercept or a scoped `INTERCEPT` Tamper rule
4. trigger one browser action
5. modify and forward only the selected request
6. turn intercept off and verify cleanup

## Route Resolution

Determine where the agent is running:

```bash
hostname
echo "$GHOST_AGENT_RUNTIME"
```

Use the route table first:

```text
/home/ryushe/projects/ai-policies/skills/proxy-routing-policy/data/proxy_routes.json
```

Expected defaults:

- `ghostonbread` / OpenClaw: browser proxy `http://hoster:8080`, MCP `http://hoster:3333/mcp`
- `hoster`: browser proxy `http://localhost:8080`, MCP `http://localhost:3333/mcp`
- `ryushespc` / Abommie: browser proxy `http://localhost:8080`, MCP `http://localhost:3333/mcp`

The browser proxy is the HTTP/SOCKS listener. The MCP endpoint is the control API. Do not substitute one for the other.

## Preflight

Check MCP reachability:

```bash
KAIDO_MCP_PROXY_URL="${KAIDO_MCP_PROXY_URL:-http://hoster:3333/mcp}"
curl -sS --max-time 5 "$KAIDO_MCP_PROXY_URL" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"ghost-intercept","version":"1.0"}}}'
```

Check that the browser proxy listener is reachable from the runtime:

```bash
curl -sS --max-time 5 -x "$BROWSER_PROXY" https://example.com/ >/tmp/proxy-check.html
```

If proxy TLS interception is expected, browser launches must include:

```text
--proxy-server=$BROWSER_PROXY
--ignore-certificate-errors
```

## Browser Launch

Preferred harness launcher:

```bash
cd "$HARNESS_ROOT"
python3 skills/chromium-test/scripts/chromium_test.py <program> "<task>" \
  --proxy-server "$BROWSER_PROXY" \
  --url "<target-url>" \
  --json
```

Verify the returned JSON includes the same proxy listener. If using Playwright directly, pass the equivalent proxy option and keep the same certificate-error handling:

```python
browser = chromium.launch(
    headless=False,
    proxy={"server": browser_proxy},
    args=["--ignore-certificate-errors"],
)
```

## Intercept Modes

### Manual Caido Intercept

Use when a human/operator is driving the UI:

1. Enable intercept in Caido.
2. Trigger one browser action.
3. Forward irrelevant setup/static requests.
4. Stop on the target request.
5. Modify one approved field.
6. Forward once.
7. Turn intercept off.

### Scoped Tamper Rule

Use when MCP exposes Tamper rule management but not an interactive pause/edit primitive.

Create one temporary rule:

- `sources`: `["INTERCEPT"]`
- condition: exact host/path/request family
- operation: one field/header/query/body mutation
- name prefix: `ghost-<program>-<lane>-<timestamp>`

After the action:

1. watch request history for the mutated request
2. record sanitized response shape
3. disable and delete the rule
4. list Tamper collections to confirm no Ghost rule remains

## Serialized Agent Rule

When only one proxy lane is available, agents must run one at a time:

1. Agent A arms intercept/rule.
2. Browser action runs.
3. Agent A captures result.
4. Agent A disables/deletes intercept/rule and verifies cleanup.
5. Only then may Agent B start.

Do not run parallel agents against the same browser proxy unless Ryushe explicitly says there are enough isolated proxy lanes.

## Action Trail Template

```text
intercepted-proxy:
- runtime hostname:
- lane: agent | ryushe | desktop
- browser proxy:
- caido mcp:
- browser launch: chromium-test | playwright | existing browser
- proxy flag present: yes|no
- ignore cert errors present: yes|no
- mode: manual-intercept | scoped-tamper-rule
- rule/intercept name:
- host/path condition:
- target full URL:
- method:
- mutation:
- forwarded non-target requests:
- result status/type:
- app state observed:
- cleanup: intercept off | rule disabled/deleted
- stop condition:
```

## Stop Conditions

Stop if:

- the browser is not visibly sending traffic through Caido
- the browser was launched without a proxy when interception is required
- the target request cannot be distinguished from surrounding traffic
- intercept cannot be disabled or the temporary rule cannot be deleted
- the mutation would touch non-owned data, spend money, submit to human review, finalize payment, delete accounts, or create unclear cleanup work
