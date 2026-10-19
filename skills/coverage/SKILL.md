---
name: coverage
description: Use when registering mapped surfaces or assessing scoped review.
---

# BBH Coverage

Coverage answers: **what was mapped, what has no assessment, and what exact
surface/class was reviewed?** It is not the findings ledger. Load this skill
when a bounded mapping run produces inventory, when selecting a current mapped
surface/class, or when recording a scoped review at a pivot or handoff. Do not
load it for every payload; deliberate tests go to `attempt-recording-policy`,
and reusable observed behavior goes to `/map-store` as it is established.

## Two distinct coverage stores

- **Live application inventory:** the lane-local `ledgers/surface_coverage.sqlite`
  indexes semantic route/action/input/consumer × relevant vulnerability class.
  Discovery creates `no_assessment` questions, not test results. Assessments are
  explicit, evidence-linked, and limited to the reviewed path/class/fingerprint.
- **Static source-file review:** `ledgers/coverage.json` is tied to an indexed
  `shared_brain/index.json` source snapshot and file/class pair. It cannot
  represent a live URL, GraphQL argument, browser action, or workflow state.

Neither URL Ingest's URL/parameter review status nor MapStore's tested-state
facts are the live denominator. Never edit either coverage store by hand. An
empty live brief can mean mapping/import is incomplete, not that the app was
exhaustively reviewed.

## Uptake watch and historical backfill

Use `bbh agents/coverage.py watch --program <program> --family <family>
--lane <lane> [--attempt-run-id <exact-stream-id>]` as a **read-only watcher**.
It reports the Coverage question/status/history counts, a bounded sample of canonical Attempt
streams with `linked`, `needs_reconciliation`, `missing_stream`, or `incomplete` signals, and
availability pointers for URL Ingest and aggregated URL, parameter, and JS
corpora. It never creates a ledger, writes an assessment, infers a negative test,
or claims that a URL/JS file was reviewed. `needs_reconciliation` only means no
typed Attempt pointer from that run was found in Coverage history; older or
untyped evidence, unassessed mapping, and other lanes may still hold the work.
The default is at most 50 directory entries, 5,000 rows per stream, and 5,000
newest history events; `more_runs`, `truncated`, and `history_incomplete` are
explicit. Enumeration is a bounded sample, **not** necessarily the most recent
streams or a full census. Use an exact `--attempt-run-id` for a worker
handoff. A historical census across all programs is an operator task, not a
per-payload query or automatic scanner.

At the first mapping checkpoint of a long run, and at a meaningful worker
handoff or proposed negative stop, the parent checks the selected lane's watch
receipt plus `brief`. If Coverage is absent/thin relative to *current observed*
work, or the worker's Attempt stream says `needs_reconciliation`, assign one
**bounded, offline backfill worker** when doing so will answer a concrete
frontier question. Do not interrupt a hot chain for bookkeeping. Packet:
resolved program/family/lane; one run/feature/class or small surface cluster;
exact retained source artifacts and Attempt stream IDs; current `brief` and
relevant URL/JS/parameter store pointers; read-only access to original evidence,
Coverage-only writes, no target traffic; count/stop limit; expected returned surface IDs, status, event IDs,
unresolved edges, and verification result. Do not hand it an entire program
history or a private credential/proxy export.

Backfill proceeds **source → relevant semantic question → scoped evidence**:

1. Reconcile the source's actual route/action/input/consumer and class; use
   `/url-ingest` for queued URLs/parameters, `/js` for JS inventory and review
   depth, Recon Bus for named aggregate corpora, and `/live-map` or `/map-store`
   for observed application behavior. A URL/parameter string or JS filename is
   a lead, not a reviewed Coverage question by itself. Preserve the retained
   source reference and source run ID. Respect the original program/lane and
   published scope; no inferred cross-program joins.
2. Register only relevant **previously unmapped** questions through `discover`.
   This creates `no_assessment` (legacy `untested` reads the same). If the exact
   surface/input/consumer/class already exists, **skip rediscovery and retain
   its current mapper run/fingerprint**, even when your historical source is a
   different run. Check `brief`/`history` first: rediscovering an older run can
   make a current bounded assessment appear `stale`.
3. `assess` an existing or newly mapped question only if the retained Attempts
   or MapStore record proves a deliberate **scoped review** of that exact
   version/input/consumer/class. Use typed, lane-resolving evidence references.
   Prefer `in_progress` if the chain remains open; use `blocked` only for a
   concrete prerequisite and `reopen_when`; use `bounded_review` only for a
   justified boundary and axes. Do not promote an Attempt, finding, URL mark,
   or broad negative prose to blanket coverage. If evidence is ambiguous, leave
   `no_assessment` and name the missing discriminator.
4. Read back returned IDs, `history --event-id` and `verify --event-id` for
   every assessment. Return compact counts, source pointers, open siblings and
   next action to the parent. The parent reruns `watch` and `brief` to reconcile
   the frontier; the historical worker does not declare goal completion.

This is an **event-driven watcher**, not a persistent timer or a second writer.
Do not install a daemon/cron just to make counts look healthy. A later scheduled
report-only monitor requires an explicit owner, bounded list of lanes, cadence,
resource budget, and scheduler preflight under `service-lifecycle-policy`.

For **explicit goal runs only**, `/bug-goals` owns the parent continuation
checkpoint. Give it the current class/lane `brief` plus source-attributed
inventory pointers where available. This store describes mapped questions and
scoped assessments; it cannot establish that all services, parameters,
consumers, native entry points, or archived URLs were mapped. A missing/empty
ledger calls for mapping reconciliation, not a negative goal decision.

## Live surface workflow

Use the installed `bbh` launcher with the resolved program/family/lane.
`agents/coverage.py` owns these commands; the former
`me_ledger.py surface-*` commands remain compatibility aliases for older runs,
not a reason to load the findings `/ledger` skill.

1. **Discover** a mapped path with a stable semantic key, source reference and
   mapper run ID. Add a class only when it is a relevant question. Supply an
   input key and consumer when known, so sibling paths are not collapsed.

   ```bash
   bbh agents/coverage.py discover --program {program} --family web_bounty \
     --lane web --kind graphql_argument --host api.example \
     --surface-key Checkout.placeOrder --input-key comment \
     --consumer order-preview --class-name xss \
     --source-ref recon/api/operations.jsonl --run-id <mapper-run> \
     --fingerprint <source-version>
   ```

   For bounded mapper output use `--input-jsonl <file>` with one object per
   mapped surface (`kind`, `host`, `surface_key`, optional `input_key` and
   `consumer`, `class_names`, `source_ref`, `run_id`, optional `fingerprint`).
   For the **actual XSS canary mapper** `plan` output, use its `sources.jsonl`
   through the explicit adapter, not as generic inventory:

   ```bash
   bbh agents/coverage.py discover --program {program} --family web_bounty \
     --lane web --xss-canary-sources <plan-dir>/sources.jsonl \
     --source-ref recon/xss/<mapper-run>/sources.jsonl
   ```

   Keep `--source-ref` a sanitized lane-relative provenance reference to the
   retained producer artifact, not the absolute local/scratch `sources.jsonl`
   path; the latter is not portable to a later reviewer.

   It creates one `no_assessment` XSS question per literal method/route/input,
   retaining each source ID when multiple mapper rows name that same question
   (`brief` displays up to 20 with `source_count`/`sources_truncated`). It does
   not copy the mapper's canary/nonce columns or query values. A planned input
   has **no verified consumer or source fingerprint**.
   Route paths are stored literally (not normalized or secret-scanned beyond
   common key/value patterns): inspect sensitive or dynamic path components and
   approved scope before import. Do not infer a browser result from `plan`, or
   treat `edges.jsonl` as a complete inventory.
   The import is atomic. Retain mapper method/limits in its run artifact:
   missing inventory is not evidence of absence. Reimport of the same mapper
   run preserves reviewed state; a changed fingerprint or a new mapper run for
   unversioned inventory makes old assessments `stale` (history remains intact).
   A previously seen older unversioned mapper run cannot replace the current run.

2. **Brief** after observing/selecting a current path, not as a broad historical
   opening move. Filter by class/host, and follow `next_offset` to enumerate
   additional pages (each `--limit` is 1–200).

   ```bash
   bbh agents/coverage.py brief --program {program} --family web_bounty \
     --lane web --class-name xss --host api.example
   ```

3. **Assess** only after a deliberate review. Use the returned surface ID and
   fingerprint **actually reviewed**, plus opaque non-secret Attempt/MapStore
   pointers. `in_progress` means work remains; `blocked` requires a concrete
   prerequisite and `--reopen-when`; `bounded_review` requires the exact tested
   `--boundary`, at least one `--axis`, and supporting evidence. It describes
   only that path/class/version, **not** a negative vulnerability verdict or
   permission to stop XSS specialist work. An inert HTTP reflection is not a
   bounded XSS review or a generic blocker.

   ```bash
   bbh agents/coverage.py assess --program {program} --family web_bounty \
     --lane web --surface-id S-... --class-name xss \
     --expected-fingerprint '<version from brief>' --status in_progress \
     --reason 'raw response reflection; browser consumer remains open' \
     --evidence-ref attempt:<probe-run>:A-...
   ```

   `no_assessment` is created by discovery; `stale` is a read-time version or
   unversioned mapper-run mismatch. Use a new mapper run ID for a fresh mapping.
   A finding or Attempt never closes a class, sibling input, role, or consumer
   automatically. Class-specific pressure such as XSS `warm` is optional via
   `--pressure` and does not replace review status. Use `history` with the
   surface ID/class when assessing a previously reviewed path.
   Existing SQLite `untested`/`exhausted` values are shown as
   `no_assessment`/`bounded_review` in brief, history, and stale prior status
   without rewriting stored rows. The old `--status exhausted` writer spelling
   remains accepted as a deprecated input alias and writes `bounded_review`;
   new commands should use the new spelling. XSS pressure `exhausted` remains
   a separate specialist state and is not translated.

   Prefer typed pointers that resolve within the selected family/lane:
   `--evidence-ref attempt:<attempt-run-id>:<attempt_id>` (use the returned
   `A-...`, not an invented ID) and `--evidence-ref map:<maps-relative-path>`
   (the observation path relative to `recon/maps/`). Keep detailed probes in
   Attempts and reusable app facts in MapStore; coverage stores only the scoped
   decision and pointers. Legacy bare `A-...` refs remain readable but lack a
   run path for reliable verification. After the write, run
   `bbh agents/coverage.py verify --program {program} --family <family>
   --lane <lane> --surface-id S-... --class-name <class> --event-id <returned-event-id>`
   to audit the **exact assessment event** returned by `assess`, even if another
   worker has since updated the same surface/class. Without `--event-id`, `verify`
   audits the current/latest assessment as before. `history --event-id <id>`
   reads that single event; save the returned `event_id` in handoff receipts.
   `resolved` means the ID/path exists in that lane;
   `missing` means a fully specified pointer was not found; `unverified` means
   a legacy/unsupported ref or incomplete evidence stream. This read-only
   audit does not copy evidence bodies or block historic assessments. Fix any
   missing pointer before using it to substantiate exhaustion.

Use sanitized IDs and short explanations; never put payloads, tokens, raw
requests, or sensitive responses in coverage fields. The writer rejects common
secret patterns but cannot prove arbitrary prose safe. Verify the command's
lane-resolved `coverage_path`, `brief` counts, and scoped `history` read-back.

## Static source-file review

For deliberate source-file/class review in the matching shared-brain snapshot,
the existing compatibility command is `bbh agents/me_ledger.py cover --program
{program} --family <family> --lane <lane> --file <indexed-relative-path>
--class-name <class> --agent <agent>`. It writes `coverage.json`; do not pass a
URL or use it for live app behavior. Finding import through `manual_hunter.py`
or `sync_reports.py` does **not** complete a static file/class review: a
single vulnerability proves a finding, not that the entire class was examined.
Legacy entries with `method=manual-hunter` or `method=sync-reports` may still
say `done` from earlier runs; do **not** count them as reviewed without
independent review evidence. They require a separately reviewed data
reconciliation before claiming historical coverage. The static CLI location is
legacy implementation coupling, not ownership by the findings ledger.
