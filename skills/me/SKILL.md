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
│   ├── raw/{type}/          # raw/manual input reports and raw navigation
│   ├── findings/{lifecycle}/ # canonical finding reports: active, confirmed, dormant, completed
│   ├── daily/               # date-scoped navigation views
│   ├── categories/          # vuln-class navigation and per-FID links/stubs
│   ├── severity/            # severity navigation
│   └── index/               # summary indexes
├── ledgers/
│   ├── ledger.json          # canonical v2 dedupe ledger
│   ├── findings.jsonl       # append-only finding stream when present
│   ├── coverage.json        # explored surface coverage
│   ├── shared_brain/        # indexed target/surface context, usually index.json
│   ├── indexes/             # agent-readable indexes by status/type
│   └── traces/              # run traces and audit trail
├── context/
│   ├── target_profile.json  # machine-readable roots/family/lane
│   ├── me_context.md        # human-readable current roots/rules
│   └── session_handoff.md   # cross-agent handoff summary
├── notes/
│   ├── faq/                 # solved recurring target questions
│   ├── hypotheses/          # test ideas and assumption chains
│   ├── handoffs/            # agent-to-agent summaries
│   ├── timeline/            # dated activity notes
│   └── index.md             # reusable memory map
├── working/scratch/         # temporary/generated analysis artifacts
└── recon/{urls,params,js,maps,artifacts}/
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

## Agent note-taking and reusable memory

When `/me` is used to brief Codex, Claude, or another child agent, require the agent to leave notes in the resolved lane, not in cwd. The agent should read `context/target_profile.json` first, then use these buckets:

- `notes/timeline/YYYY-MM-DD.md` — chronological activity log: what was checked, commands run, files reviewed, outcomes, and open questions.
- `notes/hypotheses/<slug>.md` — reusable attack ideas or assumption chains. Include status (`untested`, `testing`, `confirmed`, `rejected`, `blocked`), evidence, linked files/endpoints, and next validation step.
- `notes/handoffs/<run-id>.md` — concise handoff for the next agent: scope, lane, roots, findings touched, coverage marked, promising leads, blockers.
- `notes/faq/<slug>.md` — solved target-specific answers that future agents are likely to need again.
- `working/scratch/<run-id>/` — generated scratch files, extracted snippets, temporary JSON, prompt bundles, and other artifacts that are not durable notes.

Minimum child-agent exit checklist:

1. Submit or import any real finding through `manual_hunter.py`; do not hand-edit `ledger.json`.
2. Mark coverage through `me_ledger.py cover` when a file/class was actually reviewed.
3. Append a dated timeline note with enough detail for another agent to continue.
4. Write/update a hypothesis note for each promising chain, even if unconfirmed.
5. Write a handoff note and update `context/session_handoff.md` only with the current summarized state.

Reusable note format:

```markdown
# <Short title>

Status: untested|testing|confirmed|rejected|blocked
Program: <program>
Family/Lane: <family>/<lane>
Agent/Run: <agent> / <run-id>
Updated: <ISO timestamp>

## Context
- Source files/endpoints reviewed:
- Related FIDs / coverage classes:

## Evidence
- What was observed:
- Commands or references:

## Next step
- One concrete action the next agent should take.
```

For briefed agents, prefer a handoff prompt that says: "Use `context/target_profile.json` as the source of truth for storage roots. Resolve the current source/version root, write collaboration notes under that source root's `.ghost/notes/`, findings through `manual_hunter.py`, and coverage through `me_ledger.py`."

## Memory routing: source-version notes + canonical ledger

When Ryushe says "remember this for this project," "note this," "this script is okay," "browser/CDP info," or gives target-specific workflow facts, put the reusable working memory next to the source version being tested.

Primary collaboration notes live under the current source/version root:

```text
<source-version-root>/.ghost/
├── INDEX.md                  # start here: current state, active runs, important links
├── notes/
│   ├── faq/                  # stable facts: browser/CDP, scripts, source roots, gotchas
│   ├── timeline/             # dated events and decisions
│   ├── hypotheses/           # attack ideas and validation status
│   └── handoffs/             # takeover summaries
├── agents/
│   ├── codex/<run-id>/       # Codex run notes/artifacts
│   ├── claude/<run-id>/      # Claude run notes/artifacts
│   └── <model>/<run-id>/     # other model run notes/artifacts
└── locks/                    # optional lightweight coordination markers
```

Use the canonical lane ledger for durable finding/coverage state:

- `ledgers/ledger.json` and `findings.jsonl` — finding identities and evidence lifecycle.
- `ledgers/coverage.json` — reviewed file/class coverage.
- `ledgers/shared_brain/index.json` — indexed target/source context and surface metadata.
- `reports/` — raw finding inputs, canonical finding reports, and generated navigation.

Do not use ledger/shared_brain/report files for general human instructions. Human instructions, browser details, approved scripts, and cross-agent decisions belong in `<source-version-root>/.ghost/notes/`.

Examples:

- "The Canva Electron CDP is on port 9222" → `.ghost/notes/faq/cdp-debugging.md` plus `.ghost/notes/timeline/YYYY-MM-DD.md`.
- "This helper script is approved/safe to use" → `.ghost/notes/faq/approved-scripts.md` with path, purpose, constraints, and who approved it.
- "This browser profile is logged in for testing" → `.ghost/notes/faq/browser-profiles.md` with non-secret details only.
- "We learned this source root/version is the right one" → `.ghost/notes/faq/source-roots.md`, `.ghost/INDEX.md`, and current handoff if relevant.

Minimum `.ghost/INDEX.md` contents:

```markdown
# Ghost Notes Index

Program:
Source/version root:
Current version:
Last updated:

## Start here
- Current handoff: notes/handoffs/<latest>.md
- Active/blocked agents:
- Important FAQ:
- Promising hypotheses:
- Canonical ledger/report root:

## Agent runs
- <model>/<run-id>: status, focus, link to handoff
```

Each agent should create a unique run directory under `.ghost/agents/<model>/<run-id>/`. Use a timestamped run id such as `20260518T130500Z-codex-ipc-bridge`. Store run-local scratch, extracted snippets, prompt bundles, and working notes there. If the run discovers reusable project memory, summarize it back into `.ghost/notes/` and update `.ghost/INDEX.md` before finishing.

## Team-member workflow

A `/me`-briefed agent should act like one participant in Ghost's team pipeline, not like an isolated scanner.

Before testing:

1. Read `context/target_profile.json` and `context/me_context.md` for program, family, lane, canonical roots, and report states.
2. Resolve the current source/version root, then read or create `<source-version-root>/.ghost/INDEX.md`.
3. Read the latest `.ghost/notes/handoffs/` entry and relevant `.ghost/notes/faq/` / `.ghost/notes/hypotheses/` entries.
4. Use `ledgers/coverage.json`, `ledgers/shared_brain/index.json`, and
   `ledgers/indexes/` only for targeted coordination: active claims, tested
   state for the exact surface, and unexplored candidates.
5. Do not broadly skim confirmed reports or current findings before live
   testing unless the task explicitly asks for status, duplicate triage, report
   cleanup, revalidation, or extending a known FID.
6. Pick work from the user goal, live surface, and uncovered areas; prior notes
   should not choose the vulnerability class.
7. Query `/map-store` only after you have a concrete URL, endpoint, surface,
   parameter, role boundary, or vuln class and need targeted tested-state,
   duplicate avoidance, or reusable app facts.

During testing:

- Use `/map-store` as a targeted check-in after selecting or observing a
  concrete live surface. Surface observations from JS, recon, mental-map, or
  auth agents may help avoid duplicate retests, but they must not become the
  default vuln-class lane for the run. Write your own observations back when you
  discover something new at a URL.
- Treat `ledgers/shared_brain/index.json` and `coverage.json` as the shared team memory of files/classes/surfaces.
- Use existing findings and notes to extend or disprove hypotheses instead of duplicating them.
- If new evidence strengthens an existing FID, update notes/handoff and mention the FID; do not create a competing duplicate report.
- If a finding is real enough to track, submit/import it with `manual_hunter.py` so it enters the same ledger/report lifecycle as team findings.

Prior-finding boundary:

- Historical confirmed findings, reports, and MapStore `#do-not-retest` notes are coordination inputs only.
- They can justify skipping an exact duplicate PoC, selecting adjacent untested work, or extending an existing FID with fresh evidence.
- They must not satisfy a new hunt/testing goal by themselves unless Ryushe explicitly asked for status, portfolio review, report cleanup, duplicate triage, or revalidation of an existing finding.
- A hunt goal is complete only when the current run produces new evidence for the requested target/surface, documents that the requested lanes are exhausted or blocked, or reaches a current-run proof/report threshold.

After testing:

- Mark reviewed file/class coverage with `me_ledger.py cover`.
- Leave run notes under `.ghost/agents/<model>/<run-id>/`.
- Summarize reusable facts into `.ghost/notes/` and update `.ghost/INDEX.md`.
- Write a takeover-ready handoff in `.ghost/notes/handoffs/<run-id>.md`.
- If no finding was produced, still record what was ruled out so future agents do not repeat it.

## Report participation

Manual or agent reports should feed the canonical report pipeline rather than being hand-written into final locations.

Preferred flow for a real finding:

1. Draft a raw report or finding note in `working/scratch/<run-id>/` or `reports/raw/{type}/`.
2. Include the core fields: title, class/type, severity, affected file or full URL, evidence, impact, reproduction/validation steps, safety notes, and suggested next step.
3. Import it with:

```bash
python3 /home/ryushe/projects/bug_bounty_harness/agents/manual_hunter.py {program} --from-file /path/to/finding.md --hunt-type <source|web> --lane <lane>
```

4. Let the pipeline update `ledgers/ledger.json`, generated finding pages, and navigation/indexes.
5. If review is still pending, leave it as pending/active and explain the missing proof in `notes/hypotheses/` or `notes/handoffs/`.

Do not manually create final canonical files in `reports/findings/{active|confirmed|dormant|completed}/` unless Ryushe explicitly asks. Those are owned by Bounty Core/report helpers.

## Profile/run coordination and backoff

Agents must avoid trampling active team members.

Before taking a profile, surface, or vuln class:

- Check for durable hunt-pipeline state under the current lane, especially `working/**/pipeline_plan.json`, `working/**/run_state.json`, and `working/**/run_control.json` if present.
- Treat statuses `running`, `queued`, `selected`, or a live runtime lock such as `.hunt_pipeline_runtime.lock` as a reason to avoid that exact agent/profile unless it is stale and Ryushe asked you to recover it.
- Treat `deferred`, `skipped`, `covered`, and `completed` as coordination signals: prefer untested/deferred work over repeating completed coverage.
- If the desired profile appears active or locked, back off: choose another uncovered surface, write a handoff note explaining the conflict, or ask Ryushe before overriding.
- Never delete lock/state files to force progress. Use official pipeline controls or ask Ryushe.

Useful state summary command when a pipeline plan is known:

```bash
PYTHONPATH=/home/ryushe/projects/bug_bounty_harness python3 - <<'PY'
from agents.hunt_pipeline.run_state import summarize_run
print(summarize_run('/path/to/pipeline_plan.json'))
PY
```

## Model-specific source workspaces

Each agent should keep its own generated artifacts organized by model/provider under the current source/version root:

```text
<source-version-root>/.ghost/agents/codex/<run-id>/
<source-version-root>/.ghost/agents/claude/<run-id>/
<source-version-root>/.ghost/agents/gemini/<run-id>/
<source-version-root>/.ghost/agents/<model>/<run-id>/
```

Run directory minimum files:

```text
README.md       # focus, status, source/version, canonical ledger root
notes.md        # detailed working notes
artifacts/      # extracted snippets, screenshots, generated JSON, prompt bundles
handoff.md      # concise takeover summary copied/summarized into .ghost/notes/handoffs/
```

Multiple agents can run safely because each has its own run directory. Agents should reference each other's notes through `.ghost/INDEX.md` and `.ghost/notes/handoffs/`, not by editing another active run directory.

## Source, version, and dynamic app access

Source roots usually live under:

```text
~/source/{program}/{source-or-version...}
```

Examples may vary by casing or suffix, e.g. `~/source/canva/Canva...` or `~/source/canva/canva...`. When the exact path is not provided:

1. Start with `~/source/{program}/`.
2. Prefer the newest version/source directory by version number, mtime, or explicit `target_profile.json` / `shared_brain/index.json` metadata.
3. Put current collaboration notes in that newest/current version directory under `.ghost/`.
4. Agents may read older sibling version directories' `.ghost/` notes for history, but should not update old-version notes unless explicitly working on that version.
5. If there are multiple plausible newest roots, ask Ryushe instead of guessing.
6. Keep ledger file paths relative to the resolved target/source root.

When Ryushe has an interactable browser/Electron app running, assume Chrome DevTools Protocol is commonly available at:

```text
http://127.0.0.1:9222/json/list
```

Use CDP only for observation, navigation, screenshots, and source-backed validation unless Ryushe approves a state-changing action. Do not publish, message, purchase, invite, spam, mutate vendor/customer data, or make arbitrary IPC/debug-port calls without exact approval.

## Context modes

Default `/me`: load resolved target root, coverage/shared_brain coordination, and unexplored surfaces. Do not inject prior confirmed findings into the opening hunt prompt unless the task asks for status, duplicate triage, report cleanup, revalidation, or extending a known FID. Treat prior findings as advisory coordination only; prefer unexplored areas and avoid duplicating known findings.

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
- Raw manual report inputs belong in `reports/raw/{type}/` or should be imported with `manual_hunter.py --from-file`.
- Durable agent notes belong in `notes/`, not `reports/`, unless they are actual findings or generated report inputs.
- Canonical finding pages are written under `reports/findings/{active|confirmed|dormant|completed}/` by Bounty Core/report helpers.
- Navigation and indexes are generated by Bounty Core; do not hand-edit generated files marked `<!-- generated: bounty-core-report-navigation -->` unless explicitly asked.
- Keep file paths relative to the resolved target/source root when adding ledger entries.

## Safety and quality rules

- Never edit `ledger.json`, `coverage.json`, or generated indexes by hand; use the CLIs/helpers.
- Before posting or reporting, check for PII, API keys, and accidental secrets.
- Prefer non-disruptive validation. Ask Ryushe before live exploitation, purchases, invitations, messaging, spammy requests, or actions that affect vendor/customer data.
- If the target/lane is ambiguous, ask for the lane instead of guessing between web/api/apk/exe/mac.

## Current caveat

A future Bounty Core CLI is planned (`bounty-core ledger ...`), but the installed console command is not the current reliable interface. Until that exists, use the absolute `manual_hunter.py` and `me_ledger.py` harness paths above.
