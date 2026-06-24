---
name: map-store
description: Use when an agent discovers or observes anything about an application (endpoints, auth patterns, CSRF tokens, CSP headers, technology stack, XSS leads, SSRF candidates, IDOR surfaces, sandbox context, etc.) and needs to store those observations in a URL-anchored, cross-surface queryable map so other agents don't rediscover the same information.
---

# Map Store — URL-Anchored Surface Observations

Write surface observations into the canonical `recon/maps/` directory so every agent can query "what do we know about this URL?" across all surfaces.

## When to use this skill

- You are inspecting URLs, JS, API endpoints, or app pages and learn something about them
- You discover auth patterns, CSRF tokens, CSP headers, framework versions, or technology clues
- You find leads (XSS, SSRF, IDOR, etc.) — tag them so vulnerability agents see them
- You deduce something app-wide (e.g., "renderer is sandboxed") that every agent should know
- You arrive at a URL and want to see what was already discovered there

## CLI reference

All commands run from the harness repo with bounty-core on the path:

```bash
cd ~/projects/bug_bounty_harness
PYTHONPATH=".:$HOME/projects/bounty-core"

# One-time init per program
python3 agents/map_store.py init --program <program> --family web_bounty --lane web

# Write a URL-specific observation
python3 agents/map_store.py write \
  --program <program> --family web_bounty --lane web \
  --url "https://app.com/login" --surface js \
  --body "## Obs\n- CSRF token _csrf\n- jQuery 3.6, no CSP\n" \
  --tags "csrf,no-csp" --scope url \
  --agent "<agent-name>"

# Query before testing — what do we know about this URL?
python3 agents/map_store.py query \
  --program <program> --family web_bounty --lane web \
  --url "https://app.com/login"

# Query filtered by surface (XSS agent sees only XSS + tagged relevance)
python3 agents/map_store.py query \
  --program <program> --family web_bounty --lane web \
  --url "https://app.com/login" --surface xss

# Write app-wide observation (visible to every agent at every URL)
python3 agents/map_store.py write \
  --program <program> --family web_bounty --lane web \
  --surface electron --scope app \
  --body "Renderer sandboxed. No nodeIntegration." \
  --tags "sandboxed-renderer" \
  --crossfamily "binaries/<program>/exe"

# Write surface-wide observation (applies to all URLs within this surface)
python3 agents/map_store.py write \
  --program <program> --family web_bounty --lane web \
  --surface xss --scope surface \
  --body "All XSS in this app is sandbox-only." \
  --tags "sandbox-only"

# Regenerate cross-reference views
python3 agents/map_store.py rebuild-crossref \
  --program <program> --family web_bounty --lane web
```

## Scope levels

| Scope | When | Visible to |
|-------|------|------------|
| `url` (default) | Observation tied to a specific URL | Agents querying that URL |
| `surface` | Observation applies to all URLs of this surface type | Agents querying any URL within this surface |
| `app` | Observation applies to the entire application | Every agent, every URL |

## Surface types

Common surfaces: `js`, `api`, `auth`, `forms`, `xss`, `ssrf`, `idor`, `sqli`, `recon`, `electron`, `bac`, `fuzz`

## Tag conventions

- **Descriptive tags**: `csrf`, `no-csp`, `sourcemap`, `rate-limit`, `jwt`
- **Vuln-class prefix tags**: `xss-reflected`, `xss-stored`, `ssrf-webhook`, `idor-user-id` — these auto-match when a vuln agent queries with `--surface xss`
- **Cross-surface relevance**: `xss-relevant`, `ssrf-relevant` — explicit signal this observation matters to another surface
- **Status tags**: `investigated`, `low-impact`, `confirmed`, `false-positive`

Tag naming rules:
- Lowercase, hyphenated: `csrf-validated`, `no-csp`, `xss-reflected`
- Tags starting with `{surface}-` are auto-visible to that surface's agent

## Agent flow (MANDATORY)

Every agent that inspects application surfaces MUST follow this flow:

1. **Query first** — `map_store.py query --url <url> --surface <your-surface>`
   - Read what prior agents already discovered at this URL
   - Check app-wide and surface-wide observations
2. **Do your work** — inspect, test, analyze
3. **Write back** — `map_store.py write --url <url> --surface <your-surface> ...`
   - Store what you found, even if negative ("CSRF validated, no bypass")
   - Tag with vuln-class prefix if relevant to other agents
4. **If you deduce something app-wide** — write with `--scope app`
   - "Renderer is sandboxed" — every agent needs this
5. **If you confirm/close a lead** — update the observation
   - `--tags "investigated,low-impact"` so the next agent doesn't re-investigate

## Storage layout

```
recon/maps/
├── map.jsonl              ← Index: query this, don't read raw
├── _app/index.md          ← App-wide observations
├── {surface}/
│   ├── _surface/index.md  ← Surface-wide observations
│   └── {url_dirname}/index.md  ← URL-specific observations
└── _crossref/
    └── {url_dirname}/index.md  ← Auto-generated: all surfaces for this URL
```

The filesystem mirrors the URL structure. `map.jsonl` is machine-readable — query it, don't parse the directory tree.

## Family/lane selection

- Web targets: `--family web_bounty --lane web`
- API targets: `--family web_bounty --lane api`
- Binary/source targets: `--family binaries --lane exe` (or `apk`, `mac`)

## Cross-family pointers

Use `--crossfamily` to link observations across families:

```bash
# From binaries/exe, point to web
python3 agents/map_store.py write \
  --program canva --family binaries --lane exe \
  --surface electron --scope app \
  --body "Renderer sandboxed." \
  --crossfamily "web_bounty/canva/web"
```

Web agents querying with `--cross-family` will see the exe observation.
