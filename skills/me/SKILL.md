---
name: me
description: Use when the user asks for /me, a Ghost-aware bug bounty hunting briefing, current target context for Codex/Claude, manual hunt coordination, fresh/default hunt context, bounty harness storage paths, ledger/coverage coordination, or how to write findings into Ghost's current bounty pipeline.
---
# Ghost Hunting — /me skill

Use this skill to brief an agent before manual bug bounty hunting. The goal is to make the agent use Ghost's current harness layout instead of guessing paths, editing JSON directly, or writing reports into cwd.

## Current harness roots

- Harness repo: `/home/ryushe/projects/bug_bounty_harness`
- Manual hunt CLI: `/home/ryushe/projects/bug_bounty_harness/agents/manual_hunter.py`
- Ledger coordination CLI: `/home/ryushe/projects/bug_bounty_harness/agents/me_ledger.py`
- Shared storage resolver: `agents/storage_resolver.py` → `bounty_core.storage`
- Bounty Core package: `/home/ryushe/projects/bounty-core`

Always use absolute script paths unless already running from the harness repo.

## Canonical storage layout

The harness now resolves target storage through Bounty Core. Do not use legacy `~/Shared/bounty_recon/{program}/ghost/...` as the write target unless a command explicitly resolves there.

Default lanes:

- Web/API targets: `family=web_bounty`, lanes `web` or `api`
- Binary/source targets: `family=binaries`, lanes `apk`, `exe`, or `mac`
- Current manual-hunter default: `hunt_type=source` → `family=binaries`, `lane=apk`

Canonical layout:

```text
~/Shared/{family}/{program}/{lane}/
├── reports/
│   ├── raw/                 # raw/manual input reports
│   ├── findings/{state}/    # editable generated finding reports
│   ├── daily/               # daily status navigation
│   ├── categories/          # vuln-class navigation
│   ├── severity/            # severity navigation
│   └── index/               # summary indexes
├── ledgers/
│   ├── ledger.json          # canonical dedupe ledger
│   ├── findings.jsonl       # raw findings stream when present
│   ├── coverage.json        # explored surface coverage
│   ├── shared_brain/        # indexed target/surface context
│   ├── indexes/             # agent-readable indexes
│   └── traces/              # run traces
├── context/
│   ├── target_profile.json
│   ├── me_context.md
│   └── session_handoff.md
├── notes/{faq,hypotheses,handoffs,timeline}/
├── working/scratch/
└── recon/                   # urls, params, js, maps, artifacts
```

For `family=binaries`, `input/{original,extracted,metadata}` also exists.

## Best path: let manual_hunter build context

For a normal Ghost-aware hunt, run:

```bash
python3 /home/ryushe/projects/bug_bounty_harness/agents/manual_hunter.py {program} --hunt --hunt-type source
```

Useful overrides:

```bash
# Fresh hunt: omit prior ledger/coverage from prompt, but still dedupe writes later.
python3 /home/ryushe/projects/bug_bounty_harness/agents/manual_hunter.py {program} --hunt --fresh

# Web/API lane examples.
python3 /home/ryushe/projects/bug_bounty_harness/agents/manual_hunter.py {program} --hunt --hunt-type web --lane web
python3 /home/ryushe/projects/bug_bounty_harness/agents/manual_hunter.py {program} --hunt --hunt-type web --lane api

# Explicit source or storage roots for local/test runs.
python3 /home/ryushe/projects/bug_bounty_harness/agents/manual_hunter.py {program} --hunt --source-root /path/to/source --root /path/to/storage
```

The hunt command writes context files under the resolved `context/` directory and prints a handoff bundle. If spawning a child agent, forward that bundle unchanged so children inherit the same family, lane, roots, and context files.

## Context modes

Default `/me`: load current ledger, coverage, shared_brain, resolved target root, and unexplored surfaces. Prefer unexplored areas and avoid duplicating known findings.

`/me --fresh`: skip prior findings/coverage in the prompt. Hunt freely, but still use the ledger before writing; duplicates are expected to be caught by the pipeline.

## Manual finding ingestion

Prefer `manual_hunter.py` for complete findings because it parses, dedupes, updates the ledger, writes canonical report pages, refreshes navigation, and marks coverage when possible.

```bash
# Paste one finding.
python3 /home/ryushe/projects/bug_bounty_harness/agents/manual_hunter.py {program} --add "Title: ...\nClass: ...\nSeverity: HIGH\nFile: path/to/file.js:123\nDescription: ..."

# Import a markdown/text finding.
python3 /home/ryushe/projects/bug_bounty_harness/agents/manual_hunter.py {program} --from-file /path/to/finding.md

# Interactive entry.
python3 /home/ryushe/projects/bug_bounty_harness/agents/manual_hunter.py {program} --interactive
```

Use `--hunt-type`, `--lane`, `--source-root`, and `--root` when the target is not the default source/APK lane.

## Low-level ledger coordination

Use `me_ledger.py` only when an agent needs to coordinate during active manual analysis without importing a full report yet.

```bash
# Check for duplicates first.
python3 /home/ryushe/projects/bug_bounty_harness/agents/me_ledger.py check \
  --program {program} \
  --family binaries \
  --lane apk \
  --file <relative/file/path> \
  --class-name <vuln-class>

# Reserve/add a minimal finding if not duplicate.
python3 /home/ryushe/projects/bug_bounty_harness/agents/me_ledger.py add \
  --program {program} \
  --family binaries \
  --lane apk \
  --file <relative/file/path> \
  --class-name <vuln-class> \
  --type "<finding type>" \
  --severity HIGH \
  --agent codex

# Mark reviewed coverage.
python3 /home/ryushe/projects/bug_bounty_harness/agents/me_ledger.py cover \
  --program {program} \
  --family binaries \
  --lane apk \
  --file <relative/file/path> \
  --class-name <vuln-class> \
  --agent codex

# Inspect current state.
python3 /home/ryushe/projects/bug_bounty_harness/agents/me_ledger.py list --program {program} --family binaries --lane apk
python3 /home/ryushe/projects/bug_bounty_harness/agents/me_ledger.py unexplored --program {program} --family binaries --lane apk --class-name <vuln-class>
```

For web/API work, change `--family web_bounty --lane web` or `--family web_bounty --lane api`.

## Report writing rules

- Do not write final reports to `./reports` by default.
- Use the resolved canonical `reports/` root from `context/target_profile.json` or `context/me_context.md`.
- Raw manual notes belong in `reports/raw/`.
- Editable generated finding pages belong under `reports/findings/{confirmed|dormant|novel|raw|complete|archive}/`.
- Navigation and indexes are generated by Bounty Core; do not hand-edit generated index stubs unless explicitly asked.
- Keep file paths relative to the resolved target/source root when adding ledger entries.

## Safety and quality rules

- Never edit `ledger.json`, `coverage.json`, or generated indexes by hand; use the CLIs/helpers.
- Before posting or reporting, check for PII, API keys, and accidental secrets.
- Prefer non-disruptive validation. Ask Ryushe before live exploitation, purchases, invitations, messaging, spammy requests, or actions that affect vendor/customer data.
- If the target/lane is ambiguous, ask for the lane instead of guessing between web/api/apk/exe/mac.

## Current caveat

A future Bounty Core CLI is planned (`bounty-core ledger ...`), but the installed console command is not the current reliable interface. Until that exists, use the absolute `manual_hunter.py` and `me_ledger.py` harness paths above.
