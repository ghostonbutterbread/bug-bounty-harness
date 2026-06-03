# Skill Registry

Universal index of all available bug bounty skills.

---

## Configuration

Skills use paths from `config.env` or environment variables.

**Note:** `config.env` is gitignored. Run `./setup.sh --init` to create it from `config.env.example`.

### Environment Variables (override config.env)

| Variable | Description | Default |
|----------|-------------|---------|
| `HARNESS_ROOT` | Bug bounty harness repo root | `~/projects/bug_bounty_harness` |
| `HARNESS_SHARED_BASE` | Base for bounty recon data | `~/Shared/bounty_recon` |
| `HARNESS_WORDLISTS` | Wordlists directory | `~/wordlists` |
| `CLAUDE_SKILLS_DIR` | Claude Code skills directory | `~/.claude/skills` |
| `CODEX_SKILLS_DIR` | Codex skills directory | `~/.agents/skills` |
| `GHOST_SKILLS_DIR` | Ghost/OpenClaw workspace skills directory | `~/.openclaw/workspace/skills` |
| `KAIDO_MCP_PROXY_URL` | Caido MCP proxy URL for traffic capture and replay | `http://127.0.0.1:3333/mcp` |

### Config File

First time setup:
```bash
./setup.sh --init  # Creates config.env from config.env.example
```

Edit `config.env` in the repo root:
```bash
HARNESS_SHARED_BASE="${HOME}/Shared/bounty_recon"
HARNESS_ROOT="${HOME}/projects/bug_bounty_harness"
CLAUDE_SKILLS_DIR="${HOME}/.claude/skills"
CODEX_SKILLS_DIR="${HOME}/.agents/skills"
GHOST_SKILLS_DIR="${HOME}/.openclaw/workspace/skills"
KAIDO_MCP_PROXY_URL="http://127.0.0.1:3333/mcp"
```

### Setup Commands

```bash
# First time setup
./setup.sh --init

# Sync skills after updating
./setup.sh --sync

# Show current config
./setup.sh --config

# Override with env vars
HARNESS_ROOT=/custom/path ./setup.sh --sync
```

---

## Available Skills

| Skill | Command | Playbook |
|-------|---------|----------|
| **xss** | `/xss {program}` | `prompts/xss-playbook.md` |
| **access-control** | `/access-control {program}` | `prompts/access-control-playbook.md` |
| **idor** | `/idor {program}` | `prompts/idor-playbook.md` |
| **sqli** | `/sqli {program}` | `prompts/sqli-playbook.md` |
| **ssti** | `/ssti {program}` | `prompts/ssti-playbook.md` |
| **ssrf** | `/ssrf {program}` | `prompts/ssrf-playbook.md` |
| **fuzz** | `/fuzz {program}` | `prompts/fuzz-playbook.md` |
| **recon** | `/recon {program}` | `prompts/recon-playbook.md` |
| **recon-ry** | `/recon-ry {program}` | `prompts/recon-ry-playbook.md` |
| **csrf** | `/csrf {program}` | `skills/csrff/SKILL.md` |
| **mental-map** | `/mental-map {program}` | `prompts/mental-map-playbook.md` |
| **caido** | `/caido {mcp-url-or-host?}` | `skills/caido/SKILL.md` |
| **agent-proxy** | `/agent-proxy` | `skills/agent-proxy/SKILL.md` |
| **ryushe-proxy** | `/ryushe-proxy` | `skills/ryushe-proxy/SKILL.md` |
| **intercepted-proxy** | `/intercepted-proxy {program} {target-flow}` | `prompts/intercepted-proxy-playbook.md` |
| **mullvad** | `/mullvad` | `prompts/mullvad-playbook.md` |
| **temporary-email** | `/temporary-email {create|read|show|accounts}` | `skills/temporary-email/SKILL.md` |
| **live-map** | `/live-map {program}` | `prompts/live-map-playbook.md` |
| **url-ingest** | `/url-ingest {init|ingest|status|mark|search|stats} {program}` | `skills/url-ingest/SKILL.md` |
| **brainstorm-spec** | `/brainstorm-spec {program}` | `prompts/brainstorm-spec-playbook.md` |
| **appmap** | `/appmap {program} {target_path}` | `prompts/appmap-playbook.md` |
| **appmap-research-librarian** | `/appmap-research-librarian init {program}` | `prompts/appmap-research-librarian-playbook.md` |
| **electron** | `/electron {program} {target_path}` | `prompts/electron-playbook.md` |
| **prompt-injection** | `/prompt-injection {program} {target_url}` | `prompts/prompt-injection-playbook.md` |
| **payment-testing** | `/payment-testing {program} {checkout-or-billing-context}` | `prompts/payment-testing-playbook.md` |
| **bypass** | `/bypass {target_url} {type}` | `prompts/bypass-playbook.md` |
| **403** | `/403 {target_url}` | `skills/403/SKILL.md` |
| **headers** | `/headers {target_url}` | `prompts/headers-context-pack.md` |
| **error-triage** | `/error-triage {target_url}` | `prompts/error-triage-context-pack.md` |
| **single-request-grabber** | `/single-request-grabber {target_url}` | `prompts/single-request-grabber-context-pack.md` |
| **chromium-test** | `/chromium-test {program} {task}` | `prompts/chromium-test-playbook.md` |
| **chromium-handoff** | `/chromium-handoff {cdp_port}` | `skills/chromium-handoff/SKILL.md` |
| **pfp** | `/pfp {program} {goal}` | `prompts/pfp-playbook.md` |
| **shared-skill-creator** | `/shared-skill-creator {project} {skill-name}` | `prompts/shared-skill-creator-playbook.md` |
| **me** | `/me {program}` | `skills/me/SKILL.md` |

---

## Skill Templates

- Template chooser: `SKILL_TEMPLATE.md`
- Executable harness/module template: `docs/executable-harness-template.md`
- RAG-style skill template: `docs/rag-skill-template.md`
- Skill-tree and handoff template: `docs/skill-tree-handoff-template.md`

---

## How to Invoke

### Slash Commands
```
/xss superdrug
/access-control superdrug account-orders
/idor superdrug
/sqli superdrug
/ssti superdrug
/ssrf superdrug
/fuzz superdrug
/recon superdrug
/recon-ry superdrug --url example.com --profile full
/csrf superdrug
/mental-map superdrug
/caido 192.168.0.135
/agent-proxy
/ryushe-proxy
/intercepted-proxy canva billing-flow
/mullvad
/temporary-email create
/live-map superdrug --source browser
/brainstorm-spec canva --family binaries --lane exe --target-kind electron-exe
/appmap canva /home/ryushe/Shared/binaries/canva/exe/input/app_asar --target-kind electron-exe --focus rce --write-specs
/appmap-research-librarian init canva --category electron-ipc --research-query electron rce --target-kind electron-exe
/electron canva /home/ryushe/Shared/binaries/canva/exe/input/app_asar --dry-run-prompts
/prompt-injection canva https://target.example/ai-assistant --mode map
/payment-testing canva checkout-flow
/bypass https://target.example/admin 403 --program target
/403 https://target.example/admin --program target
/headers https://target.example/api/resource --program target
/error-triage https://target.example/api/resource --program target
/single-request-grabber https://target.example/settings/delete --program target
/chromium-test superdrug pfp
/chromium-test canva upload-flow --account qa-primary --url https://www.canva.com/
/chromium-handoff 9224
/pfp canva profile-picture
/shared-skill-creator bounty-harness bypass "endpoint bypass testing workflow"
/me notion --hunt-type source
/me canva --hunt-type source --lane exe
/access-control canva project-sharing
```

### Local Skill Audit Labs

```bash
# Prompt injection vulnerable local lab: starts, tests, and shuts down
python3 agents/prompt_injection_lab.py --eval --json
```

### Agent Spawn
```python
spawn_codex(
    task="Hunt for xss on superdrug",
    context={
        "program": "superdrug",
        "playbook": "$HARNESS_ROOT/prompts/xss-playbook.md",
        "findings": "$HARNESS_SHARED_BASE/superdrug/ghost/skills/xss/findings.md",
        "knowledge": "$HARNESS_SHARED_BASE/superdrug/ghost/knowledge.md"
    }
)
```

---

## Provider Skill Locations

| Provider | Directory |
|----------|-----------|
| Claude Code | `~/.claude/skills/` (or `$CLAUDE_SKILLS_DIR`) |
| Codex | `~/.agents/skills/` (or `$CODEX_SKILLS_DIR`) |
| Ghost/OpenClaw | `~/.openclaw/workspace/skills/` (or `$GHOST_SKILLS_DIR`) |

Sync with: `./sync_skills.sh` or `./setup.sh --sync`; both publish from canonical source `skills/{name}/` to all provider targets by default.

---

## Program Knowledge

Per-program knowledge file:
```
{HARNESS_SHARED_BASE}/{program}/ghost/knowledge.md
```

**Read before starting any work.** Contains:
- What's been tested
- What's been found
- What's next
- WAF/filter observations
- Authentication details

---

## Creating New Skills

1. Prefer `/shared-skill-creator <project> <skill-name>` for shared skills.
2. Create skill wrapper: `skills/{name}/SKILL.md`
3. Create playbook if needed: `prompts/{name}-playbook.md`
4. Create sync metadata if the skill should publish `_meta.json`
5. Create harness if needed: `agents/{name}_hunter.py`
6. Add to this registry
7. Commit and push the owning repo.
8. Run `aiskillsync sync all --repo bounty-harness`

---

## File Structure

```
bug_bounty_harness/
├── config.env              # Config (edit for your paths)
├── setup.sh               # Setup script (--init, --sync, --config)
├── sync_skills.sh         # Sync skills to providers
├── prompts/               # Playbooks
│   ├── xss-playbook.md
│   └── ...
├── agents/live_map.py     # Runtime/browser/proxy application map writer
├── skills/                # Skill wrappers (source)
│   ├── xss/SKILL.md
│   └── ...
├── .claude/skills/        # Synced for Claude Code
├── .agents/skills/        # Synced for Codex
├── .openclaw/workspace/skills/ # Synced for Ghost/OpenClaw
└── SKILL_REGISTRY.md      # This file
```

---

*Last updated: 2026-05-25*
