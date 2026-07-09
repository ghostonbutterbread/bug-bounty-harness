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
- Chain synthesis: `gadget`

Use lowercase hyphenated tags. Tags beginning with `{surface}-` are visible to
that surface's agent.

## Lifecycle Status

Lifecycle status is separate from tags. Use tags for classification and
filtering; use status for whether an observation should appear as an active
lead.

Statuses:

- `active`: default current observation.
- `candidate`: promising but not proven reusable.
- `failed`: tested in a current context and did not work.
- `needs_recheck`: ambiguous or environment-dependent; revisit when useful.
- `stale`: app behavior likely changed.
- `archived`: keep searchable, but hide from default query results.

Archived entries remain in MapStore. Query them explicitly with
`--include-archived` or `--status archived`.

Update status when an agent has evidence from the current surface:

```bash
python3 agents/map_store.py update-status \
  --program canva \
  --family web_bounty \
  --lane web \
  --path "xss/app.canva.com_s_report/stored-preview-gadget/index.md" \
  --status stale \
  --reason "Retested current report preview twice; title is escaped before render." \
  --agent xss-worker
```

### Gadget Capability Convention

Use the `gadget` tag only for genuinely confirmed, exploitable primitives that
could participate in an attack chain. Do not use it for hypotheses,
interesting behavior, negative results, generic leads, or unconfirmed sink
shape.

When writing a `gadget` entry, include a compact capability block near the top
of the body:

```text
Capability:
- grants: same-origin JS execution in victim session
- requires: attacker can create a published report; victim visits report page
- crosses: attacker-content->victim-browser
- crosses_detail: stored attacker-controlled title renders in a victim-owned
  report preview context
- chain_status: watch
- chain_watch: revisit if another gadget grants notification delivery,
  cross-account share injection, report auto-open, or trusted embed navigation
```

Fields:

- `grants`: what access, effect, or primitive this finding gives.
- `requires`: preconditions such as auth level, account tier, object ownership,
  user interaction, processing delay, or plan gate.
- `crosses`: a short, stable boundary label using `source->destination` form
  when possible, such as `attacker-content->victim-browser`,
  `anonymous->authenticated`, `client->server`, `same-account->cross-account`,
  `sandboxed-iframe->root-origin`, or `user-input->server-fetch`.
- `crosses_detail`: optional free text for target-specific nuance.
- `chain_status`: soft synthesis state. Use `ready`, `deferred`, or `watch`.
  This is not a permanent exhausted/retired flag.
- `chain_watch`: the future primitive, app condition, or capability crossing
  that should make agents reconsider this gadget.

The short `crosses` value should be stable enough for cheap filtering. Put
messy target-specific details in `crosses_detail` instead of inventing many
near-duplicate boundary labels.

Use `chain_status` and `chain_watch` to keep old gadgets findable without
dumping every historical primitive into every synthesis context. A gadget can
be `deferred` after one synthesis pass and still become high-priority when a new
matching primitive appears.

Suggested values:

- `ready`: include in normal synthesis passes.
- `deferred`: already reviewed against current known gadgets; wake when
  `chain_watch` conditions appear.
- `watch`: especially relevant if the named future primitive appears.

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

Query confirmed gadgets across every surface:

```bash
python3 agents/map_store.py query \
  --program canva \
  --family web_bounty \
  --lane web \
  --tags gadget,confirmed
```

Default queries hide `archived` entries. Use `--status active,candidate` for
active gadget synthesis and `--include-archived` when intentionally reviewing
old material.

## Family/Lane

- Web: `--family web_bounty --lane web`
- API: `--family web_bounty --lane api`
- Binary/source: `--family binaries --lane exe|apk|mac`

## Cross-Family Pointer

```bash
python3 agents/map_store.py write \
  --program canva --family binaries --lane exe \
  --surface electron --scope app \
  --body-file /tmp/mapstore-body.md \
  --crossfamily "web_bounty/canva/web"
```
