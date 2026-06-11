# Hybrid Playbook

## Purpose

Hybrid combines a persistent planner with swappable worker CLIs.

Use it when the task benefits from:

- Codex/GPT-5.5 goal-mode persistence for mapping, routing, monitoring, and
  completion checks
- OpenCode/OpenRouter/DeepSeek, Claude, or another CLI for focused deep probes
- reusable skill routing instead of one bespoke runner per vulnerability class

## Mental Model

The planner is not a request engine. The planner owns:

- broad classification
- lane splitting
- worker packet quality
- monitoring worker artifacts
- deciding whether the original goal is complete
- spawning or drafting the next narrow packet when gaps remain

Workers own one lane at a time:

- DOM/reflected XSS
- SSRF/API URL-fetch behavior
- auth/access-control/session behavior
- parser/error behavior
- fuzzing/content discovery
- object/tenant/design ownership boundaries

## Config Principles

Prefer CLI engines by default:

```yaml
planner:
  engine: codex
  model: gpt-5.5
  transport: cli

worker:
  engine: opencode
  model: deepseek/deepseek-v4-pro
  transport: cli

max_requests_per_worker: 0
monitor_workers: true
browser_escalation: challenge_only
```

API engines are allowed only when config explicitly asks for them. The first
runner slice plans API engines but executes CLI engines only.

`max_requests_per_worker: 0` means unlimited by arbitrary cap, not unlimited by
policy. Workers still obey scope, rate, ownership, target stress, CAPTCHA,
program limits, and live-testing stop conditions.

## CLI Shape

```bash
python3 agents/hybrid_runner.py deep-dive recon canva --input params.txt
```

This creates a plan. Add `--execute` only when the configured CLIs should be
spawned.

Override engines and models per run:

```bash
python3 agents/hybrid_runner.py deep-dive recon canva \
  --input params.txt \
  --planner codex \
  --planner-model gpt-5.5 \
  --worker opencode \
  --worker-model openrouter/deepseek/deepseek-chat \
  --max-requests-per-worker 0
```

## Planner Loop

1. Resolve canonical recon input from `/url-ingest` aggregate storage.
2. Classify the full input into route/host/param clusters.
3. Create focused worker packets by lane.
4. Spawn workers only when execution is approved.
5. Monitor logs and artifact directories.
6. After each worker completes, read its summary and attempts.
7. Decide if the goal is complete.
8. If incomplete, create the next narrow worker packet with exact evidence.

Do not let one worker absorb every lane. If a new category appears, create a
handoff packet.

## Worker Packet Standard

Each worker packet must include:

- program
- lane and owning skill(s)
- representative full URLs
- route clusters
- parameter keys
- rate and request-budget semantics
- exact output directory
- stop conditions
- required artifacts

Workers must write at least:

- `attempts.jsonl`
- `summary.md`
- optional `handoff.json`

## Skill Augmentation

Hybrid does not replace skills. It routes to them:

- `/url-ingest` for input and review-state memory
- `/deep-hunt` for slow URL/cluster depth
- `/error-mapper` for tiny parser/error probes
- `/xss`, `/dom-xss`, `/reflected-xss`, `/stored-xss`
- `/ssrf`
- `/access-control`, `/idor`, `/jwt-auth`
- `/fuzz`
- `/headers`, `/403`, `/error-triage`

## Safety

Use the active live-testing and proxy-routing policy.

Plain app/server 403 or 401 responses are not automatic browser triggers.
Browser escalation is for Cloudflare, managed challenge, bot defense,
browser-only token, TLS/header fingerprint, or similar client-fingerprint
boundaries.

Do not persist or print secrets. Do not pass raw auth/session material into
worker packets.
