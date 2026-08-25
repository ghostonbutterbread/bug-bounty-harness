---
name: manual_hunter
description: Use when adding manual security findings to the Ghost pipeline, importing findings from files, watching report directories, or running /manual_hunter workflows.
---
# manual_hunter skill

Add your own manual security findings to the Ghost pipeline.

## Required destination lane

Every invocation must declare the **canonical destination lane**. The tool will refuse to write without `--lane`; it never derives a lane from note contents or the report path.

```bash
/manual_hunter <program> --lane web --interactive
/manual_hunter <program> --lane web --add "finding text..."
/manual_hunter <program> --lane web --from-file path.md
/manual_hunter <program> --lane web --watch
```

Use `--lane api` for an API surface, or `--lane apk|exe|mac` for binary work. `--family` is optional when the lane implies it; `--hunt-type` is legacy metadata only and cannot override `--lane`.

## Submission updates (one sentence)

When an operator says a finding was submitted or marked duplicate, update it immediately instead of opening a separate workflow:

```bash
python3 /home/ryushe/projects/bug_bounty_harness/agents/manual_hunter.py <program> --lane <lane> \\
  --set-submission D02 --submission-state submitted --submission-report "HackerOne #123"
# or
python3 /home/ryushe/projects/bug_bounty_harness/agents/manual_hunter.py <program> --lane <lane> \\
  --set-submission D02 --submission-state duplicate --duplicate-of "HackerOne #99"
```

The compact `submission` record is only `state`, `report`, and optional
`duplicate_of`. A confirmed, submitted, or duplicate finding is closed to the
default next-work queue; it remains available for dedupe, exact-FID lookup, an
explicit `--include-closed`/retest request, or an explicit request to use past
reports as inspiration.

## Input drop folder

`~/Shared/bounty_recon/{program}/manual/`

Drop markdown notes here. They will be ingested on the next run.

## How it works

1. Parses the finding from your input.
2. Deduplicates against the ledger.
3. If new: adds to the ledger, updates the right report, and marks coverage when possible.
4. If duplicate: shows the overlapping finding and can link your note as a comment.
