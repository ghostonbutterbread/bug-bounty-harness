# Harness Scripts

Cross-skill BBH command-line helpers live here. Before adding another script,
search this index, `skills/<skill>/scripts/`, and established `agents/` modules.
One-skill helpers belong with that skill; runtime modules stay under `agents/`.
Invoke repository helpers through `bbh <repository-relative-path> ...`.

Script output follows
[`../docs/executable-harness-template.md`](../docs/executable-harness-template.md):
deterministic mechanics are reusable, but regexes, signatures, classifiers, and
hardcoded lists are non-exhaustive seeds unless a closed input universe and
complete parser are proven. Agents inspect cited evidence and keep unknowns
open.

## `bbh.py`

- **Purpose:** Dispatch a repository-owned helper from the same selected checkout
  and Python environment as the `bbh` launcher.
- **Inputs:** Repository-relative helper path and its arguments; `--root` and
  `--print-command` provide diagnostics.
- **Outputs:** Executes the selected helper or prints a resolved path/root.
- **Mutates:** Only through the selected helper; diagnostic modes are read-only.
- **Example:** `bbh --print-command agents/js_analyzer.py`
- **Verification:** `pytest tests/test_bbh_launcher.py -q`
- **Owner/scope:** Bug Bounty Harness / cross-skill lane-safe dispatch.
- **Last verified:** 2026-09-10.

## `goal_router.py`

- **Purpose:** Classify an explicit `/goal` objective and create a small,
  policy-neutral routing brief.
- **Inputs:** Program, objective, and optional URL, class, mode, or run directory.
- **Outputs:** JSON planning output or explicit run-state files.
- **Mutates:** `init` writes only the declared run directory; no target traffic.
- **Example:** `bbh scripts/goal_router.py plan --program example --objective "Find a new vulnerability"`
- **Verification:** `pytest tests/test_goal_router.py -q`
- **Owner/scope:** Bug Bounty Harness / goal routing mechanics.
- **Last verified:** 2026-09-10.

## `preview_mcp.py`

- **Purpose:** Query Preview's curated security-write-up retrieval API without
  placing its API key in artifacts.
- **Inputs:** Search query, retrieval controls, and external credential source.
- **Outputs:** Cited JSON search results on stdout.
- **Mutates:** No repository or target state; performs the requested API search.
- **Example:** `bbh scripts/preview_mcp.py search --query "DOM clobbering"`
- **Verification:** `pytest tests/test_preview_mcp.py -q`
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
- **Example:** `bbh scripts/program_init.py example --platform bugcrowd --lane web --lane apk`
- **Preview:** `bbh scripts/program_init.py example --skip-scope --dry-run --json`
- **Verification:** `pytest tests/test_program_init.py -q`
- **Owner/scope:** Bug Bounty Harness / cross-program bootstrap.
- **Last verified:** 2026-09-10.

## `recon_bus.py`

- **Purpose:** Expose Recon Bus append, query, run promotion, repair, mirror,
  verification, and one-shot watcher commands through the selected BBH lane.
- **Inputs:** Program and subcommand-specific artifact, run, and output controls.
- **Outputs:** Structured receipts and canonical artifact paths.
- **Mutates:** `query` and `verify` are read-only; write subcommands mutate only
  their declared Recon Bus stores and projections.
- **Example:** `bbh scripts/recon_bus.py query example --artifact urls --format path`
- **Verification:** `pytest tests/test_recon_bus.py -q`
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
- **Example:** `bbh scripts/research_map.py query --terms "custom protocol parser" --class xss`
- **Verification:** `pytest tests/test_research_map.py -q`
- **Owner/scope:** Bug Bounty Harness / portable AppSec research cards.
- **Last verified:** 2026-09-10.

## `tool_run.py`

- **Purpose:** Run a recon tool into a canonical per-tool run directory and
  preserve command, stdout, stderr, manifest, and optional promotion evidence.
- **Inputs:** Program, wrapper controls, `--`, and the exact tool command.
- **Outputs:** Run directory, immutable execution artifacts, JSON receipt, and
  optional Recon Bus promotion.
- **Mutates:** Creates the declared tool run and may promote successful output;
  use `--no-promote` for collection-only behavior.
- **Example:** `bbh scripts/tool_run.py example --no-promote -- printf https://app.example/`
- **Verification:** `pytest tests/test_recon_tool_run.py -q`
- **Owner/scope:** Bug Bounty Harness / provenance-preserving recon tool runs.
- **Last verified:** 2026-09-10.
