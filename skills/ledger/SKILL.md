---
name: ledger
description: Coordinate BBH findings, coverage, and durable hunt context.
---

# BBH Ledger

Use this skill for the Bug Bounty Harness ledger and its adjacent durable hunt
records. It owns finding deduplication, coverage coordination, and the
canonical artifact locations. It does not provide a general session briefing;
use the shared `atme` skill for a concise “what are we working on?” summary.

## When to Use

- A manual hunt needs its program/lane storage context.
- Before recording a candidate finding or marking a surface reviewed.
- When importing a real finding into BBH's report pipeline.
- When writing target-specific handoff, hypothesis, or timeline context.

Do not use this for a general conversational status update, non-BBH project
status, or to hand-edit generated ledgers.

## Resolve Context First

1. Start a hunt with the lane explicit:

   ```bash
   bbh agents/manual_hunter.py {program} --hunt --lane <web|api|apk|exe|mac>
   ```

   Completion: the command prints the resolved target context and writes the
   current lane's `context/` files.

2. Treat `context/target_profile.json` as the source of truth for the selected
   family, lane, and canonical roots. Read `context/me_context.md` for the
   human-oriented handoff.

3. Before taking a surface or class, inspect only the relevant coverage, shared
   brain, active claim, and run-control state. Do not select work merely because
   prior findings exist. If a finding list is needed for work selection, use the
   filtered query below rather than reading the raw ledger or report directory.

## Finding visibility

Default work selection sees only open findings:

```bash
bbh agents/me_ledger.py list --program {program} \
  --family <web_bounty|binaries> --lane <web|api|apk|exe|mac>
```

After choosing a current surface and vulnerability class, ask whether that
**exact file/class pair** already has confirmed or submitted work, without
loading its report:

```bash
bbh agents/me_ledger.py prior-work --program {program} \
  --family <web_bounty|binaries> --lane <web|api|apk|exe|mac> \
  --file <exact-ledger-file-or-URL> --class-name <vuln-class>
```

The reply is a yes/no for recorded prior work plus confirmed/submitted/duplicate
flags—no FID, report, proof, or vulnerability narrative. In an ordinary new-
finding hunt, a positive answer is a **stop sign for that file/class line of
investigation**: do not repeat or deepen the known vulnerability, and choose
fresh work from current app observations instead. Do not use the result as a
springboard for chaining or adjacent variants of that finding. It does not
establish that unrelated vulnerability classes or independently observed
surfaces are closed. A miss means only that this exact file/class pair has no
recorded prior proof, not that the idea is globally novel. Review a full FID
only for an explicitly requested retest, extension, status, or report task.

The default `list` response excludes confirmed, submitted, and dropped findings
(including platform duplicates). Do not preload raw `ledger.json`, historical
reports, or an all-findings view into an agent's next-work context. For an
explicit exact-FID request, use `bbh agents/me_ledger.py get --program {program}
--family <web_bounty|binaries> --lane <web|api|apk|exe|mac> --fid <FID>`;
`check` below is instead a targeted file/class dedupe lookup. For an explicit
status, retest, portfolio, or past-report request, add `--include-closed` to the
list command. Submission status is operator-reported via
`manual_hunter.py --set-submission`; do not infer it from a draft or a confirmed
finding.

## Canonical Locations

```text
~/Shared/{family}/{program}/{lane}/
├── ledgers/ledger.json          # canonical v2 dedupe ledger
├── ledgers/findings.jsonl       # append-only finding stream, when present
├── ledgers/coverage.json        # indexed source-file/class snapshot state
├── ledgers/surface_coverage.sqlite # live surface/class inventory and review state
├── ledgers/shared_brain/        # indexed target context
├── context/                     # target profile and handoff
├── notes/                       # timeline, hypotheses, handoffs, FAQ
└── reports/                     # raw inputs and generated canonical reports
```

Use the resolved root rather than constructing a legacy path. Web/API lanes use
`family=web_bounty` with `--lane web` or `--lane api`; binary lanes use
`family=binaries` with `--lane apk|exe|mac`.

## Record Findings and Coverage

Score before recording: load the `program-severity-scoring` skill when a
finding is confirmed and before writing its severity. Derive the rating from
the target program's controlling authority (brief, VRT/rubric overrides, or
CVSS when the program requires it), score the demonstrated consequence rather
than the bug label, and note any program cap. Carry the scoring fields into
the finding note or command:

- `Scoring Authority`: program rule, platform rubric, or CVSS
- `Severity Rationale`: one evidence-based line naming the demonstrated impact
- `Program Constraint`: only when a scope rule or cap changed the rating
- If a higher consequence is plausible but unproven, keep the rating supported
  by current evidence and record the missing proof in the rationale.

Severity is normalized at write time: pass the platform's own label (`P0`,
`P1`, `P2`, `critical`, `high`, ...) and it is stored as the canonical
`EXCEPTIONAL`/`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO` value (`P0` is the
exceptional top tier, above CRITICAL); unrecognized input becomes
`UNKNOWN`. Do not pre-convert platform ratings by hand.

Use the report pipeline for a real finding:

```bash
bbh agents/manual_hunter.py {program} --lane <web|api|apk|exe|mac> \
  --from-file /path/to/finding.md
```

For bounded coordination before a full report, use the ledger CLI:

```bash
bbh agents/me_ledger.py check \
  --program {program} --family <web_bounty|binaries> \
  --lane <web|api|apk|exe|mac> --file <relative/path> \
  --class-name <vuln-class>

bbh agents/me_ledger.py add \
  --program {program} --family <web_bounty|binaries> \
  --lane <web|api|apk|exe|mac> --file <relative/path> \
  --class-name <vuln-class> --type "<type>" --severity <SEVERITY> \
  --scoring-authority "<authority>" --severity-rationale "<demonstrated impact>" \
  [--program-constraint "<cap or rule>"]

bbh agents/me_ledger.py cover \
  --program {program} --family <web_bounty|binaries> \
  --lane <web|api|apk|exe|mac> --file <relative/path> \
  --class-name <vuln-class> --agent <agent>
```

Completion: the relevant command reports the selected lane and updates the
pipeline; never edit canonical ledgers or generated indexes by hand.

### Live application coverage (all vulnerability classes)

`coverage.json` and `me_ledger.py cover` require a shared-brain source-file
snapshot. They cannot track a live WCS action, GraphQL argument, role/object
comparison, fetcher input, or workflow transition without an indexed file. For
those, use the separate lane-local `ledgers/surface_coverage.sqlite` through
`me_ledger.py surface-*`. Do not call `cover` with a URL that is not in the
shared-brain file index.

After choosing a current surface or a bounded mapping run, query the matching
class/host rather than broadly preloading historical findings:

```bash
bbh agents/me_ledger.py surface-brief --program {program} \
  --family web_bounty --lane web --class-name xss --host app.example
```

Register discovered inventory with a stable semantic surface key, optional
input/consumer, source reference, and mapper run ID. Supply `--class-name` only
when that class is a relevant question; an unclassified surface stays visible
in the brief's inventory count, not spuriously untested for every class.

```bash
bbh agents/me_ledger.py surface-discover --program {program} \
  --family web_bounty --lane web --kind graphql_argument --host api.example \
  --surface-key Checkout.placeOrder --input-key comment --consumer order-preview \
  --class-name xss --source-ref recon/api/operations.jsonl --run-id <mapper-run> \
  --fingerprint <source-or-bundle-version>
```

For bulk mapper output, use `--input-jsonl <file>` with one JSON object per
surface, e.g. `{"kind":"graphql_argument","host":"api.example",
"surface_key":"Checkout.placeOrder","input_key":"comment",
"class_names":["xss"],"source_ref":"recon/api/operations.jsonl",
"run_id":"map-1","fingerprint":"schema-v1"}`. Source-derived discovery is
*untested*, never application-behavior proof. The mapper must still name its
discovery method and limits in its run artifact: an absent row does not prove a
surface absent. Repeated imports preserve reviewed state; a changed nonempty
fingerprint displays old assessments as `stale` without deleting evidence.
Known older fingerprints cannot reverse a newer observed fingerprint. A novel
fingerprint has no inherent order, so mapper owners must import current runs;
an unseen obsolete artifact cannot be recognized from its hash alone.

After deliberate review, the agent explicitly assesses the exact returned
surface ID/class and links non-secret Attempt or MapStore IDs:

```bash
bbh agents/me_ledger.py surface-assess --program {program} \
  --family web_bounty --lane web --surface-id S-... --class-name xss \
  --status blocked --reason 'owned order fixture missing' \
  --reopen-when 'owned fixture available' --evidence-ref A-...
```

Statuses are `untested` (discovery), `in_progress`, `blocked`, and `exhausted`;
`stale` is a read-time version mismatch. Class-specific pressure such as XSS
`warm` can be attached with `--pressure`, but is not a universal status. For
`exhausted`, pass `--boundary` (the exact tested path/consumer) and at least
one `--axis` (repeatable) plus evidence; sibling inputs and other classes stay
open. An Attempt or finding does **not** automatically close coverage. Attempts
retain payload history, MapStore facts, Hypotheses private reasoning, Leads open
public questions, URL Ingest URL queues, and Findings proof/dedupe; this index
holds only mapped-vs-tested state and pointers.
Follow `next_offset` in `surface-brief` with `--offset <next_offset>` until it
is null; `--limit` (1–200) bounds each page, while `total` and `counts` describe
all matching class questions. Bulk JSONL imports are atomic: a malformed row
leaves no partial discovery. Use opaque, non-secret IDs and sanitized short
explanations only; the writer rejects common authentication material patterns,
but cannot prove arbitrary prose is secret-free.

## Durable Hunt Notes

Keep reusable target knowledge in the resolved source/version root:

```text
<source-root>/.ghost/
├── INDEX.md
├── notes/{faq,timeline,hypotheses,handoffs}/
└── agents/<model>/<run-id>/
```

- Timeline: current-run checks and outcomes.
- Hypotheses: chain, status, evidence, and one next validation step.
- Handoffs: takeover-ready scope, lane, evidence, and blocker.
- FAQ: solved target-specific workflow facts, never secrets.

Submit findings through `manual_hunter.py`; use `me_ledger.py cover` only after
actual review; leave a handoff even when no finding was produced.

## Safety and Verification

- Always specify `--lane`; do not guess between web, API, and binary lanes.
- Prefer non-disruptive validation and ask before state-changing vendor actions.
- Keep credentials, cookies, tokens, and raw request/response dumps out of
  notes and reports.
- Before declaring completion, verify the lane-resolved command output and that
  the updated note/report is in the canonical root.
