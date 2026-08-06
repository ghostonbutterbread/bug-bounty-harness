---
name: manual_hunter
description: Add your own manual security findings to the Ghost pipeline. Use /manual_hunter <program> --interactive, --add, --from-file, or --watch.
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

## Input drop folder

`~/Shared/bounty_recon/{program}/manual/`

Drop markdown notes here. They will be ingested on the next run.

## How it works

1. Parses the finding from your input.
2. Deduplicates against the ledger.
3. If new: adds to the ledger, updates the right report, and marks coverage when possible.
4. If duplicate: shows the overlapping finding and can link your note as a comment.
