# Attempt Recording Contract

## Purpose

**Attempts are the append-only record of what an agent deliberately sent to an
target or exercised against a target.** They answer:

> What exact techniques, payload families, representations, comparisons, and
> request outcomes have we tried on this application surface?

They are not a general stream of every live observation. Do not turn Attempts
into an application-facts store, a private reasoning log, a finding queue, or a
human handoff journal.

The practical future question is:

```text
How deep did we test this endpoint/input/flow, what did we send, what changed
between variants, and what happened?
```

## Ownership and routing

| Record type | Canonical destination | What belongs there |
| --- | --- | --- |
| Deliberately sent payload, representation, parameter mutation, method/body/header variation, browser action, or controlled request comparison | **Attempts** | Exact attempt, target/input, payload family, meaningful changed dimension, response/outcome, and stop/pivot reason. |
| Agent's plausible but untested branch, next discriminator, ownership/continuation state | **Hypothesis Ledger** | Private candidate reasoning, anticipated chain, future test, blocker, and attempt/artifact reference. |
| Durable target fact or reusable tested-state conclusion | **MapStore** | Concise observed behavior, defense/parser/auth boundary, representative families, pressure state, and Attempts pointer. |
| Human-facing chronology, decision, handoff, or blocker | **Bounty Notes** | Why the hunt prioritized, pivoted, paused, or handed off work; link MapStore and Attempts. |
| Evidence-backed reportable impact/proof | **Findings** | Report lifecycle, reproducible proof, impact, and links to the supporting Attempts/MapStore artifacts. |

An attempt may cause a MapStore fact or generate a Hypothesis, but it does not
replace either. Link records with a redacted `attempt_id` or sanitized artifact
path; do not duplicate every payload into MapStore, Notes, or the Hypothesis
Ledger.

## When an agent must write an Attempt

Write one Attempt for every **deliberate target-directed test**, including:

- each LFI/SSRF/SQLi/XSS/path-traversal/deserialization/etc. payload;
- each meaningful encoding, parser, transport, context, method, parameter,
  body, header, role, object, timing, or browser-state variation;
- baseline/canary requests that establish the comparison;
- blocked, challenged, rate-limited, request-error, reflected-but-inert, and
  not-reflected outcomes when they result from a deliberate attempt;
- a deliberate retest of a named historical attempt or family.

Do **not** write an Attempt for passive reconnaissance, a static inference, an
untested idea, routine UI navigation with no target-directed test, or a general
observation that does not identify what was attempted. Route those records using
the table above.

A sequence is encouraged when each next request tests a named uncertainty or
changes a meaningful dimension. Stop/pivot when variants are materially
equivalent or no longer provide information.

## Required writer and stable fields

BBH agents must use the compatibility writer rather than appending JSONL
manually:

```python
from agents.attempts import append_attempt, utc_timestamp

stored = append_attempt(attempts_path, {
    # Stable BBH contract
    "timestamp": utc_timestamp(),
    "tool": "lfi-tester",
    "target": "https://app.example/download?file=REDACTED",
    "outcome": "blocked",
    "stop_reason": "normalizer removed traversal separators",

    # Shared Core enrichment
    "run_id": "run-...",
    "vuln_class": "lfi",
    "event_type": "probe",
    "payload": "../.../REDACTED",
    "payload_family": "traversal-encoding",
    "input_location": "query:file",
    "variable_changed": "double URL encoding",
    "comparison_to": "A-previous-attempt-id",
    "expected_information": "distinguish pre-routing decode from backend path validation",
    "http_status": 403,
})
```

The writer validates legacy compatibility fields, normalizes generic Core fields,
assigns a schema version and `attempt_id`, locks the append, and redacts common
secret-bearing material before persistence. Use the returned `stored` row's
`attempt_id` when linking another record.

Hybrid workers that cannot import BBH must still produce one valid JSON object
per line with the five stable BBH fields above. Add the Core enrichment fields
when available. Never hand-write a generated index or projection.

## Minimum useful attempt content

Every record must identify:

1. **Target and input:** target URL/operation plus parameter, body field,
   header, object, browser action, or other input location.
2. **What was sent:** payload/canary or safe representation, payload family, and
   request/browser mechanism.
3. **Why this variant:** baseline, changed dimension, comparison target, or
   question it was intended to distinguish.
4. **What happened:** outcome, status/error class, observed transform/context,
   and stop or pivot reason.
5. **Attribution:** tool/agent, timestamp, and run when available.

Use open-world top-level fields or `details` for class-specific information; a
new class never needs an adapter before it can record attempts.

## Reading without noise

A run file is the forensic view for one execution. Agents do **not** need to
know an exact run ID to review a program/lane broadly. In BBH, use
`read_attempt_bucket(program, where=..., limit=...)` for a bounded newest-first
query across run files, then use `read_attempts(exact_path, ...)` only when a
specific run needs inspection. The bucket is a read-time view of canonical run
JSONL—not a second writable evidence store.

Filter with generic event fields such as `vuln_class`, `producer`/`tool`,
`subject`/`target`, `outcome`, `run_id`, or class-specific top-level metadata
when present. MapStore keeps concise promoted facts and representative Attempt
references; it is not an exhaustive payload index.

## Safety and redaction

Never put raw cookies, bearer values, CSRF/nonce/state values, passwords, API
keys, reset links, private headers, or unredacted private request/response bodies
in an Attempt. Use opaque references or `[REDACTED]` values. The writer redacts
known forms, but agents must not rely on redaction as permission to submit
secrets into their inputs.

## Promotion rule

At a natural test/pivot/completion checkpoint:

- promote a concise reusable target conclusion to **MapStore**, with the
  Attempts path/ID and representative payload families;
- preserve untested but plausible next branches in the private **Hypothesis
  Ledger**, with Attempt/MapStore references;
- write **Bounty Notes** only when a human-facing decision or handoff is needed;
- promote reportable proof through **Findings**.

Raw attempt history remains canonical in Attempts.