# Harness Scripts

Cross-skill BBH command-line helpers live here. The repository-specific
placement and maintenance owner is [`../SCRIPT_POLICY.md`](../SCRIPT_POLICY.md).
Before adding another script, search this index, the linked skill indexes below,
and established `agents/` modules.
For invocation and lane resolution, follow the canonical owner in
[`../agents/index.md`](../agents/index.md) and
[`../docs/bbh-launcher.md`](../docs/bbh-launcher.md).
The examples below use the checkout-local `scripts/bbh` shim so feature-worktree
verification executes that checkout. Installed skill commands must use
`bbh <repository-relative-path> ...` as required by the canonical launcher
guidance; do not copy the checkout-local form into a skill.

Script output follows
[`../docs/executable-harness-template.md`](../docs/executable-harness-template.md):
deterministic mechanics are reusable, but regexes, signatures, classifiers, and
hardcoded lists are non-exhaustive seeds unless a closed input universe and
complete parser are proven. Agents inspect cited evidence and keep unknowns
open. If a script emits no coverage declaration, treat it as
`exhaustive: false`; missing metadata never upgrades confidence.

Before running verification commands, create this checkout's dependency
environment with `./setup.sh --install-python-deps`. The commands below use that
checkout-local interpreter.

## Skill-owned script indexes

- [Account Management](../skills/account-management/scripts/README.md)
- [Analyze Endpoint](../skills/analyze-endpoint/scripts/README.md)
- [Bounty Tools categories](../skills/bounty-tools/scripts/README.md)
- [BountyLens](../skills/bountylens/scripts/README.md)
- [Chromium Handoff](../skills/chromium-handoff/scripts/README.md)
- [Chromium Test](../skills/chromium-test/scripts/README.md)
- [Proxy Curl](../skills/proxy-curl/scripts/README.md)
- [XSS](../skills/xss/scripts/README.md)

## `bbh`

- **Purpose:** Portable executable shim that forwards to `bbh.py` using the
  current interpreter.
- **Inputs:** The same repository-relative helper path and arguments as
  `bbh.py`.
- **Outputs:** The same dispatch or diagnostic output as `bbh.py`.
- **Mutates:** Only through the selected helper; diagnostic modes are read-only.
- **Example:** `scripts/bbh --root`
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest tests/test_bbh_launcher.py -q`
- **Owner/scope:** Bug Bounty Harness / portable dispatcher shim.
- **Last verified:** 2026-09-10.

## `bbh.py`

- **Purpose:** Dispatch a repository-owned helper from the same selected checkout
  and Python environment as the `bbh` launcher.
- **Inputs:** Repository-relative helper path and its arguments; `--root` and
  `--print-command` provide diagnostics.
- **Outputs:** Executes the selected helper or prints a resolved path/root.
- **Mutates:** Only through the selected helper; diagnostic modes are read-only.
- **Example:** `scripts/bbh --print-command agents/js_analyzer.py`
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest tests/test_bbh_launcher.py -q`
- **Owner/scope:** Bug Bounty Harness / cross-skill lane-safe dispatch.
- **Last verified:** 2026-09-10.

## `goal_router.py`

- **Purpose:** Classify an explicit `/goal` objective and create a small,
  policy-neutral routing brief.
- **Inputs:** Program, objective, and optional URL, class, mode, or run directory.
- **Outputs:** JSON planning output or explicit run-state files.
- **Mutates:** `init` writes only the declared run directory; no target traffic.
- **Example:** `scripts/bbh scripts/goal_router.py plan --program example --objective "Find a new vulnerability"`
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest tests/test_goal_router.py -q`
- **Owner/scope:** Bug Bounty Harness / goal routing mechanics.
- **Last verified:** 2026-09-10.

## `preview_mcp.py`

- **Purpose:** Query Preview's curated security-write-up retrieval API without
  placing its API key in artifacts.
- **Inputs:** Search query, retrieval controls, and external credential source.
- **Outputs:** Cited JSON search results on stdout.
- **Mutates:** No repository or target state; performs the requested API search.
- **Example:** `scripts/bbh scripts/preview_mcp.py search --query "DOM clobbering"`
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest tests/test_preview_mcp.py -q`
- **Owner/scope:** Bug Bounty Harness / external research retrieval adapter.
- **Last verified:** 2026-09-10.

## `program_init.py`

- **Purpose:** Initialize a program's canonical Bounty Core Shared lane and its
  non-secret mounted-artifact lane before first work or a stale-program refresh.
- **Inputs:** Program slug, required `--platform` for a scope pull or explicit
  `--skip-scope`; optional repeatable `--lane`; optional Shared/artifact roots.
- **Outputs:** Shared program layout/context, scope-derived web recon seeds,
  initialization manifest, artifact pointer, and mounted artifact directories.
- **Mutates:** Creates missing directories and front-door metadata only; never
  deletes or overwrites existing program files.
- **Example:** `scripts/bbh scripts/program_init.py example --platform bugcrowd --lane web --lane apk`
- **Preview:** `scripts/bbh scripts/program_init.py example --skip-scope --dry-run --json`
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest tests/test_program_init.py -q`
- **Owner/scope:** Bug Bounty Harness / cross-program bootstrap.
- **Dependencies:** Python 3 and the checkout-local Bounty Core environment;
  network access only when `--platform` pulls scope.
- **Last verified:** 2026-09-10.

## `recon_bus.py`

- **Purpose:** Expose Recon Bus append, query, run promotion, repair, mirror,
  verification, and one-shot watcher commands through the selected BBH lane.
- **Inputs:** Program and subcommand-specific artifact, run, and output controls.
- **Outputs:** Structured receipts and canonical artifact paths.
- **Mutates:** `query` and `verify` are read-only; write subcommands mutate only
  their declared Recon Bus stores and projections.
- **Example:** `scripts/bbh scripts/recon_bus.py query example --artifact urls --format path`
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest tests/test_recon_bus.py -q`
- **Owner/scope:** Bug Bounty Harness / canonical recon artifact bus.
- **Last verified:** 2026-09-10.

## `research_map.py`

- **Purpose:** Initialize, validate, index, and query the
  Markdown-authoritative ResearchMap corpus.
- **Inputs:** Corpus root, command, query terms, and optional class/technology
  filters.
- **Outputs:** Corpus layout, validation receipt, SQLite FTS index, or cited
  query briefing.
- **Mutates:** `init` and `index` write only under the selected corpus root;
  `validate` and `query` are read-only.
- **Example:** `scripts/bbh scripts/research_map.py query --terms "custom protocol parser" --class xss`
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest tests/test_research_map.py -q`
- **Owner/scope:** Bug Bounty Harness / portable AppSec research cards.
- **Last verified:** 2026-09-10.

## `safety_incident.py`

- **Purpose:** Forward explicit agent-reported safety incidents to the pinned
  Bounty Core store; this is not request interception or automatic detection.
- **Inputs:** `--program`, `--lane`, required `--profile` (absolute path to the
  selected lane's `context/target_profile.json`), optional `--family` and
  `--root` (must match the profile), then
  `record` with producer, run ID, category, optional severity (unknown by
  default; low/medium/high/critical for colored alerts), action, subject, impact,
  and containment; `--no-notify` disables delivery. Provider also supports manual
  `notify <incident_id>` (may duplicate ambiguous delivery). For this command
  only, `DISCORD_SAFETY_WEBHOOK_URL` takes precedence; if unset, the CLI reads
  `$HOME/.config/bounty-core/safety-webhook-url` (regular, current-user-owned,
  owner-only permissions (mode 0600 recommended), no symlink, at most 4096
  bytes). Keep this credential off-repo;
  do not put it in program Shared or pass it as a command-line argument.
- **Outputs:** JSON incident and optional notification receipt on stdout; a
  bounded saved-ID/action status on stderr after durable write and before delivery;
  lane-local `safety_incidents/events.jsonl` and notification attempts when enabled.
- **Mutates:** Validates profile identity and canonical storage path before any
  provider call; missing/inconsistent profile fails closed, without a default
  Shared or cwd/environment-root fallback. Appends to the selected program/lane store; notification may send
  a Discord alert unless `--no-notify` is passed. Stop and contain unsafe work
  independently; avoid secrets in input fields. An absent, unsafe, or invalid
  secret file emits a generic warning, still records the incident, and yields
  the provider's `not-configured` notification receipt (exit 1). `--no-notify`
  skips secret loading and has no notification receipt.
- **Example:** `scripts/bbh scripts/safety_incident.py --program example --lane web --profile /path/to/Shared/web_bounty/example/web/context/target_profile.json record --producer agent --run-id run-1 --category other --action "Stopped task" --subject "Owned fixture" --impact "None observed" --containment "No further action" --no-notify`
- **Verification:** `.venv/bin/python -m pytest tests/test_safety_incident.py -q`
  (disposable profile/HOME, fake secret and nondefault shared base; no live send).
- **Owner/scope:** Bug Bounty Harness CLI adapter / Bounty Core storage and delivery.
- **Coverage limit:** Only incidents explicitly reported by callers are recorded.
- **Last verified:** 2026-10-15.

## `tool_run.py`

- **Purpose:** Run a recon tool into a canonical per-tool run directory and
  preserve command, stdout, stderr, manifest, and optional promotion evidence.
- **Inputs:** Program, wrapper controls, `--`, and the exact tool command.
- **Outputs:** Run directory, immutable execution artifacts, JSON receipt, and
  optional Recon Bus promotion.
- **Mutates:** Creates the declared tool run and may promote successful output;
  use `--no-promote` for collection-only behavior.
- **Example:** `scripts/bbh scripts/tool_run.py --help`
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest tests/test_recon_tool_run.py -q`
- **Owner/scope:** Bug Bounty Harness / provenance-preserving recon tool runs.
- **Last verified:** 2026-09-10.
