---
name: hybrid
description: "Use when running a config-driven hybrid bug bounty workflow where a persistent planner such as Codex/GPT-5.5 maps and monitors focused worker CLIs such as OpenCode/OpenRouter/DeepSeek, Claude, or Codex."
---

# Hybrid

Use this when Ryushe asks for a hybrid run, hybrid deep dive, or a planner plus
swappable worker-agent workflow.

Hybrid is a universal orchestration layer. It should augment existing skills
instead of replacing them. The planner maps, splits, monitors, and replans. The
workers own focused lanes such as XSS, SSRF, auth, API parser behavior, fuzzing,
or error mapping.

## Engine

- CLI: `agents/hybrid_runner.py`
- Playbook: `prompts/hybrid-playbook.md`
- Default planner: Codex with `gpt-5.5`
- Default worker: OpenCode with `deepseek/deepseek-v4-pro`
- Default request cap: `max_requests_per_worker=0`

`max_requests_per_worker=0` means no arbitrary hard request cap. It does not
override scope, rate limits, stop conditions, account/resource ownership,
target stress, or safety policy.

## Commands

```bash
python3 agents/hybrid_runner.py deep-dive recon canva --input params.txt

python3 agents/hybrid_runner.py deep-dive recon canva \
  --input params.txt \
  --planner codex \
  --planner-model gpt-5.5 \
  --worker opencode \
  --worker-model deepseek/deepseek-v4-pro \
  --max-requests-per-worker 0

python3 agents/hybrid_runner.py deep-dive xss canva \
  --input ~/Shared/web_bounty/canva/web/recon/aggregated/params.txt \
  --worker claude \
  --worker-model claude-sonnet-4-6
```

Planning is safe by default. Add `--execute` only when the configured worker
CLIs should actually be spawned.

## Workflow

1. Resolve the input file. Relative names such as `params.txt` are resolved
   from the program aggregate store:
   `~/Shared/web_bounty/<program>/web/recon/aggregated/`.
2. Build a planner packet and focused worker packets.
3. Route worker packets by lane and skill:
   - XSS and frontend routes: `/deep-hunt`, `/dom-xss`, `/reflected-xss`,
     `/error-mapper`
   - URL-fetch/API/embed: `/ssrf`, `/headers`, `/error-mapper`
   - auth/OAuth/session: `/access-control`, `/jwt-auth`, `/error-triage`
   - object/design/template boundaries: `/access-control`, `/idor`
4. Execute workers only when explicitly requested.
5. Monitor artifacts and replan from worker outputs.

## Output

Hybrid run artifacts are written under:

```text
~/Shared/web_bounty/<program>/web/recon/hybrid-runs/<run-id>/
```

Important files:

- `plan.json`
- `config.resolved.json`
- `planner_packet.md`
- `worker_packets/*.md`
- `worker_packets/*.json`
- `classification.jsonl`
- `monitor_state.json`
- `workers/<packet-id>/`

## Safety

Load live-testing, proxy-routing, and lane policy before live execution.

Workers may explore deeply when `max_requests_per_worker=0`, but only while the
work remains scoped, rate-limited, evidence-driven, and below stop conditions.
Plain app/server 403 or 401 responses are not automatic browser triggers.
Escalate to browser only for Cloudflare, managed challenge, bot defense,
browser-only token, TLS/header fingerprint, or similar client-fingerprint
boundaries.

Never pass raw cookies, bearer tokens, reset links, private headers, API keys,
or secrets into worker packets. Use approved auth/session material in memory
only when policy allows it.

Spawned workers should log only the state needed for the test: user/account
label if known, authenticated vs anonymous, cookie/header names and counts,
redirect host/path, status, content type, length, response fingerprints,
framework/JS/API clues, parameter behavior, and evidence paths. They must not
log cookie values, bearer values, CSRF values, nonce/state values, private
headers, or sensitive query values.
