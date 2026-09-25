---
name: manual-hunter
description: Use when adding manual security findings to the Ghost pipeline, importing findings from files, watching report directories, or running /manual_hunter workflows.
---
# manual-hunter skill

Add your own manual security findings to the Ghost pipeline.

## Evidence gate before ingest

Before any ingest, the finding must pass the claim-time classification gate:
name the protected resource or capability obtained and the observation that
demonstrates it; a status code or error string alone is a signal, not a
finding — label it Informational and keep testing. When the finding passes,
load `evidence-first-vulnerability-reporting` and write or finalize the
Evidence Report first — the ledger entry records the finding, the report
carries the evidence. If only the ledger entry can be produced now, note
`report: pending` and write the Evidence Report before any submission step.
The named capability and observation feed the note's `Impact` and
`Severity Rationale` fields; a rationale without a demonstrated capability
behind it does not pass the gate.

If the item fails the gate, it does not go in the ledger. Route it to its
proper store instead: reusable app/endpoint/auth/defense facts and
vulnerability leads to `/map-store`; untested continuations and private
hypotheses to `/hypothesis-ledger`; a reusable fact plus one bounded
unresolved question to `/leads`. Nothing fails silently — say which store
it went to and why.

## Required destination lane

Every invocation must declare the **canonical destination lane**. The tool will refuse to write without `--lane`; it never derives a lane from note contents or the report path.

```bash
/manual_hunter <program> --lane web --interactive
/manual_hunter <program> --lane web --add "finding text..."
/manual_hunter <program> --lane web --from-file path.md
/manual_hunter <program> --lane web --watch
```

Use `--lane api` for an API surface, or `--lane apk|exe|mac` for binary work. `--family` is optional when the lane implies it; `--hunt-type` is legacy metadata only and cannot override `--lane`.

## Report handoff meaning

When Ryushe says a finding is **confirmed**, it means the evidence has met the
report threshold: write or finalize the canonical report for that FID. It does
**not** mean the report was sent.

Only record `submission.state=submitted` after Ryushe explicitly says it was
submitted. Record `submission.result=valid|duplicate` only after Ryushe relays
the platform outcome. Agents must not infer either from a confirmed finding or
from a report draft.

## Submission updates (one sentence)

When an operator says a finding was submitted or marked duplicate, update it immediately instead of opening a separate workflow:

```bash
bbh agents/manual_hunter.py <program> --lane <lane> \\
  --set-submission D02 --submission-state submitted --submission-report "HackerOne #123"
# later, if the platform decides it is a valid report or duplicate:
bbh agents/manual_hunter.py <program> --lane <lane> \\
  --set-submission D02 --submission-result valid
# or: --submission-result duplicate
# if the report was abandoned instead:
bbh agents/manual_hunter.py <program> --lane <lane> \\
  --set-submission D02 --submission-state dropped
```

The compact `submission` record is only `state` (`submitted` or `dropped`),
optional `report`, and optional `result` (`valid` or `duplicate`). A confirmed,
submitted, or dropped finding is closed to the
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
4. If duplicate: shows the overlapping finding; with `--link-duplicate-comment`, appends the note to that finding's comment ledger.

## Add evidence to an existing finding

Agents may attach a **new, relevant observation** to an existing finding. Before ingest, compare the note's class, file, and sink with the intended ledger finding: dedupe matches those fields, not an explicitly selected FID. If the match could be ambiguous, do not use the flag; resolve the finding identity first. The comment ledger stores the raw note, so omit credentials, tokens, and unrelated sensitive data.

```bash
bbh agents/manual_hunter.py <program> --lane <lane> \
  --from-file <new-evidence-note.md> --link-duplicate-comment
```

Verify the output names the intended FID and says `Linked duplicate note to <FID>`. A successfully linked duplicate still exits with status 1; do not retry on exit status alone. The flag cannot force a note onto an FID, and a non-duplicate may create a new finding. If the output names the wrong FID or a new finding, reconcile that result instead of claiming an update.

This attaches evidence; it does **not** rewrite canonical finding fields or the report. For a material report or severity change, update the canonical report through its owner and keep the claim aligned. Do not invent a `manual_hunter` edit mode, or confuse finding dedupe with the platform's `submission.result=duplicate`, which only Ryushe can relay.
