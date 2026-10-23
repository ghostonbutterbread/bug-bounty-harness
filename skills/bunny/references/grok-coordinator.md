# Bunny — Grok coordinator preset

This is a coordinator/worker routing overlay, not a new collaboration contract.
Load `bunny` and its selected mode. The bootstrap agent and Grok coordinator
read this reference; ordinary workers load only their applicable mode/policy
chain. No target action is authorized merely by selecting these models.

## Interpret the request

- `bunny grok w/ glm <objective>` or `bunny grok with glm <objective>`:
  coordinator **`grok-4.6` / high**; workers **`glm-5.3-flash` / max**.
  “Flash Max” means the Flash model at max reasoning, not an invented model ID.
- `bunny grok <objective>` selects the same coordinator, with ordinary worker
  inheritance. An explicit worker model/provider replaces that inheritance;
  do not silently replace an explicit non-GLM selection with the GLM preset.
- `bunny multi grok w/ glm <objective>` keeps the existing multi-program limits.
  Explicit collaborative/offhand selection still uses its existing contract;
  `multi` plus offhand still requires clarification before dispatch.
- `bunny model grok <objective>` is the existing worker alias, **not** this
  coordinator preset. Do not reinterpret a program/objective containing “grok”.

These exact model/effort selections are a user-requested routing contract:
resolve them against the authenticated runtime, rather than substituting a
newer Grok, another GLM variant, or lower reasoning when unavailable.

## Select an authenticated coordinator transport

Inspect on the host/profile that will actually run the campaign. Do not copy
credentials between profiles, hosts, CLIs, or providers. Presence of a saved
login is only a lead; confirm the selected route with a read-only model call.
Use existing auth/status tools and report only non-secret route metadata.

- **Hermes xAI:** load `hermes-agent` and its provider reference. Check
  `hermes auth status xai-oauth` and `hermes auth status xai`. Either authenticated
  xAI route is eligible if it serves `grok-4.6` at high. Prefer a working
  subscription route, then a working API route. Use invocation-scoped launch:

  ```bash
  hermes chat --provider xai-oauth --model grok-4.6 --reasoning high
  # For authenticated API-key access, use --provider xai instead.
  ```

- **Grok Build CLI:** discover the installed `grok`, read its current help and
  provider skill/docs, and check its **own** auth. Hermes xAI auth is not Grok
  CLI auth. Verify the effective model is `grok-4.6`, reasoning is high, and
  its tools can launch/control the separately authenticated GLM workers below.
  Use the CLI's verified session-level controls; do not invent a reasoning
  flag or alter its persistent defaults. A CLI that cannot enforce the model,
  effort, approvals, or cross-model worker control is not an eligible route.

If both transports work, prefer Hermes xAI because its mixed-provider worker
path is already defined in `bunny`; an explicitly requested transport wins if
eligible. If one fails authentication or model access, try the other eligible
transport before reporting blocked. If neither works, request the missing
login/access without requesting secrets in chat. Do not silently use a relay,
fall back to the current model, or install/change global configuration.

## Transfer coordination; admit GLM workers

If the current session is not already verified as Grok 4.6 high, start an owned
interactive Grok coordinator in a real PTY using the selected transport. Hand
off the original objective, mode, worker route/effort, applicable policy chain,
resolved program/family/lane, existing campaign evidence and leases, aggregate
budget, and checkpoint/stop expectations. Wait for its read-only acceptance
and actual model/provider/effort and approval status before admitting target
actions. The bootstrap agent remains a user/transport relay, **not a second
campaign coordinator**; it does not independently allocate or steer workers.
Record the coordinator session/process identity in the existing campaign record.

For the GLM preset, resolve an authenticated provider serving the exact Flash
model and max effort through `bunny`'s provider rules. Direct Z.AI is an example,
not a required credential source:

```bash
hermes chat --provider zai --model glm-5.3-flash --reasoning max
```

These commands open interactive sessions; send the bounded packet only after
route and approval verification. Load the selected mode's worker contract and
use the actual native per-worker model/provider/**effort** override when all
three are enforceable. Otherwise Grok starts/steers owned interactive Hermes
workers with explicit per-invocation model, provider, and `--reasoning max`.
A model name or “max” in a prompt is not an override. Hermes `delegate_task`
cannot enforce this mixed route; do not mutate global delegation settings.

Verify each worker's effective model, provider and reasoning effort, plus the
PTY/approval gate in `bunny`, before live work. Do not silently reduce max when
a provider does not support it. Missing GLM auth/access blocks GLM dispatch;
it does not authorize Grok workers instead. No headless approval bypass or
Grok `--always-approve` for live testing. Use the chosen mode for checkpoint
transport, steering, evidence read-back and confirmed process exit; Hoster
launches additionally use `hoster-ssh`. A lost coordinator/worker transport is
a reconciliation blocker, not permission for a competing replacement run.
