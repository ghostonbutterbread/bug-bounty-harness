# Intercepted Proxy Playbook

Use this playbook when an authorized live test needs to capture or selectively
modify browser-generated traffic while its request context is fresh. The
default agent transport is a task-owned MITM listener, not Caido. Only an agent
executing locally on Abommie may explicitly select local Caido as active
transport; elsewhere Caido is read-only source history.

## Goal

Make intercepted proxy work reproducible:

1. provision the task MITM and launch the browser with its trusted CA
2. confirm one safe browser-generated baseline in its private flow file
3. choose observation/replay, or a supported exact-match interception mechanism
4. trigger one browser action
5. if interception is supported, modify and forward only the selected request;
   otherwise replay the captured request through the same task MITM
6. remove any temporary rule and verify cleanup

## Route Resolution

Run the browser provisioner on the intended browser node. Its default `--proxy
mitm` starts a private listener, generates the task CA, imports it into the
isolated profile, and returns `task_proxy.proxy_server`, `ca_cert`, and
`flow_file` metadata. The agent must use that listener for browser actions and
later direct replay; `hoster:8080` and a Caido MCP endpoint are not fallback
HTTP proxies. Outside Abommie, use Caido only as separately labeled read-only
source evidence. The Abommie-only local Caido exception is explicit, never an
automatic fallback for MITM startup failure.

## Preflight

Verify the provisioner's task proxy listener, generated CA, owner-restricted
flow file, and `proxy_cert_mode: import` / `proxy_cert_status.status: trusted`
receipt. Confirm a safe in-scope browser-generated baseline flow before any
mutation. If proxy startup or CA import fails, stop and diagnose that task
transport; do not fall back to shared 8080, Caido, or certificate-ignore.

## Browser Launch

For this bug-bounty engagement, request the browser through the required
harness provisioner. It preserves profile ownership and queues rather than
bypassing node resource admission:

```bash

bbh skills/chromium-test/scripts/browser_provisioner.py request \
  <program> <account> --agent-id "$AGENT_ID" --run-id "$RUN_ID" \
  --purpose "<task>" --url "<target-url>"
```

On `queued` or `queued-timeout`, preserve the exact account/task, perform only
non-browser preparation, and retry with bounded backoff. Never call
`chromium_test.py` directly to bypass this admission step. The underlying
launcher prefers Playwright's bundled Chromium when available and otherwise
falls back to system Chromium/Chrome. Verify the provisioned browser's
owner-recorded route uses the expected listener. If using Playwright directly
for an explicitly approved implementation/recovery path, pass the equivalent
proxy and trusted CA configuration; do not treat `--ignore-certificate-errors`
as ordinary interception setup.

## Intercept Modes

### Manual Caido Intercept (Abommie-only explicit exception)

Use only when the agent is executing locally on Abommie with its own permitted
Caido transport and a human/operator is driving the UI. Do not route remote
agent traffic through Ryushe's personal Caido:

1. Enable intercept in Caido.
2. Trigger one browser action.
3. Forward irrelevant setup/static requests.
4. Stop on the target request.
5. Modify one approved field.
6. Forward once.
7. Turn intercept off.

### Scoped Tamper Rule

Use only on the explicit Abommie local-Caido lane when MCP exposes Tamper rule
management but not an interactive pause/edit primitive. For the default task
MITM lane, use one temporary exact host/path rule in that task's MITM process
and verify its removal after the selected request. The ordinary provisioner
starts a capture listener, not a hot-edit control API: if this task has no
supported way to install and remove such a rule, capture the request and use a
bounded direct replay instead. Do not silently switch active traffic to Caido.

For an explicit Abommie Caido lane, create one temporary rule:

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

When only one interception-capable lane is available, agents must run one at a time:

1. Agent A arms intercept/rule.
2. Browser action runs.
3. Agent A captures result.
4. Agent A disables/deletes intercept/rule and verifies cleanup.
5. Only then may Agent B start.

Do not run parallel agents against the same interception rule or browser proxy.
Independent task-owned capture lanes can run concurrently.

## Action Trail Template

```text
intercepted-proxy:
- runtime hostname:
- lane: agent | ryushe | desktop
- browser proxy:
- caido mcp (Abommie-only, when explicitly selected):
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

- the browser is not visibly sending traffic through its selected task MITM
  (or explicitly permitted local Caido on Abommie)
- the browser was launched without a proxy when interception is required
- the target request cannot be distinguished from surrounding traffic
- intercept cannot be disabled or the temporary rule cannot be deleted
- the mutation would touch non-owned data, spend money, submit to human review, finalize payment, delete accounts, or create unclear cleanup work
