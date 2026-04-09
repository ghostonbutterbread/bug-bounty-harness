---
name: manual_hunter
description: Add your own manual security findings to the Ghost pipeline. Use /manual_hunter <program> --interactive, --add, --from-file, or --watch.
---
# manual_hunter skill

Add your own manual security findings to the Ghost pipeline.

## Commands

```bash
/manual_hunter <program> --interactive
/manual_hunter <program> --add "finding text..."
/manual_hunter <program> --from-file path.md
/manual_hunter <program> --watch
```

## Input drop folder

`~/Shared/bounty_recon/{program}/manual/`

Drop markdown notes here. They will be ingested on the next run.

## How it works

1. Parses the finding from your input.
2. Deduplicates against the ledger.
3. If new: adds to the ledger, updates the right report, and marks coverage when possible.
4. If duplicate: shows the overlapping finding and can link your note as a comment.
