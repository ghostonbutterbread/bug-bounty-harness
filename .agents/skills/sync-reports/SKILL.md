---
name: sync-reports
description: Import vulnerabilities from ~/source/{program}/reports into the Ghost pipeline. Use /sync-reports <program> [--source-dir ...] [--write-reports-from-memory] [--verbose].
---
# /sync-reports skill

Import vulnerabilities from Ryushe's working reports into the Ghost pipeline.

## Usage

```bash
/sync-reports <program>
```

Example:

```bash
/sync-reports notion
```

Harness CLI:

```bash
python3 ~/projects/bug_bounty_harness/agents/sync_reports.py notion --verbose
```

## What it does

1. Scans `~/source/{program}/reports/`, then `report/`, then any `*reports*` directory for markdown report files.
2. Parses each file for vulnerabilities.
3. Deduplicates against the ledger.
4. Imports new findings into the shared pipeline.
5. If no reports exist and `--write-reports-from-memory` is set, asks Codex to write reports from memory first.

## Options

- `--source-dir` - Override the reports directory.
- `--write-reports-from-memory` - If no reports exist, use Codex to write them from memory first.
- `--verbose` - Show detailed output.

## Harness

```text
~/projects/bug_bounty_harness/agents/sync_reports.py
```
