# MapStore Reference

## Scope Levels

| Scope | Use | Visible to |
|---|---|---|
| `url` | URL-specific behavior | Agents querying that URL |
| `surface` | Behavior applying to one surface type | Agents querying that surface |
| `app` | App-wide behavior | Every agent and URL |

## Common Surfaces

`js`, `api`, `auth`, `forms`, `xss`, `ssrf`, `idor`, `sqli`, `recon`,
`electron`, `bac`, `fuzz`

## Tag Conventions

- Descriptive: `csrf`, `no-csp`, `sourcemap`, `rate-limit`, `jwt`
- Vuln-class: `xss-reflected`, `xss-stored`, `ssrf-webhook`, `idor-user-id`
- Cross-surface: `xss-relevant`, `ssrf-relevant`
- Status: `investigated`, `low-impact`, `confirmed`, `false-positive`

Use lowercase hyphenated tags. Tags beginning with `{surface}-` are visible to
that surface's agent.

## Storage Layout

```text
recon/maps/
├── map.jsonl
├── _app/index.md
├── {surface}/
│   ├── _surface/index.md
│   └── {url_dirname}/index.md
└── _crossref/{url_dirname}/index.md
```

Agents query `map.jsonl`; do not parse the directory tree directly.

## Family/Lane

- Web: `--family web_bounty --lane web`
- API: `--family web_bounty --lane api`
- Binary/source: `--family binaries --lane exe|apk|mac`

## Cross-Family Pointer

```bash
python3 agents/map_store.py write \
  --program canva --family binaries --lane exe \
  --surface electron --scope app \
  --body "Renderer sandboxed." \
  --crossfamily "web_bounty/canva/web"
```
