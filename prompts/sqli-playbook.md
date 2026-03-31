# SQL Injection Testing Playbook

## Overview

Use this as a decision tree: probe the input, fingerprint the query behavior, choose the lowest-noise confirmation lane, verify the injection without extracting data, then report the sink, database clues, and constraints.

See `prompts/sqli-payloads.md` for lane-specific examples, DB-specific timing primitives, and WAF-aware mutations.

## Decision Tree

1. Probe the input.
2. If syntax changes or stack traces appear, go down the error lane.
3. If content changes without explicit errors, go down the boolean lane.
4. If output is blind but timing is stable, go down the time lane.
5. If the response appears to render query results inline, test the union lane without extracting sensitive data.
6. Verify with the smallest payload that proves code path control, then report the result.

## 1. Probe

Start by mapping every user-controlled sink that can alter query shape.

### Coverage Checklist

- Query parameters
- Form fields and other `POST` bodies
- JSON keys and values in API requests
- Headers reflected into backend search, filtering, or audit queries
- Cookies used for search, sort, locale, or tenant lookups
- Path segments, slugs, and export filters

### Probe Method

1. Send a benign marker and capture the baseline status, body length, and response time.
2. Add a low-noise syntax nudge such as a quote, parenthesis, or delimiter.
3. Note how the application changes:
   - parser error
   - response body difference
   - redirect or login failure
   - row-count or pagination drift
   - stable time delay
4. Record any filtering behavior early:
   - quote stripping
   - keyword blocking
   - numeric coercion
   - WAF block

## 2. Fingerprint Behavior

Choose the lane based on observable behavior, not on payload popularity.

| Signal | What To Confirm | Next Lane |
|--------|------------------|-----------|
| Syntax error or stack trace | Query parser changed | Error |
| Page content differs between true and false predicates | Logic changed | Boolean |
| Response time shifts only when the condition is true | Blind execution | Time |
| Additional columns or inline values seem reflected | Result shape can be influenced | Union |
| Nothing visible changes | Input may be sanitized or sink may be elsewhere | Re-probe or stop |

Fingerprint any backend clues that help you choose safe syntax:

- MySQL or MariaDB markers
- PostgreSQL markers
- MSSQL markers
- Oracle markers
- SQLite markers

## 3. Choose Lane

### Error Lane

Use when the application leaks database or parser feedback.

1. Confirm the syntax change is tied to your input and not a generic failure page.
2. Capture the narrowest payload that triggers the database-specific error.
3. Use the error to infer quoting style, column count hints, or function availability.
4. Stop before any extraction primitive. Error-based confirmation is enough.

### Boolean Lane

Use when content or behavior differs between logically true and false conditions.

1. Compare a paired true and false predicate against the same baseline.
2. Watch for differences in:
   - record counts
   - sort order
   - section visibility
   - redirect destinations
   - authorization decisions
3. Repeat with a second predicate pair so the result is not accidental caching or business logic noise.

### Time Lane

Use when the sink is blind but timing is stable enough for confirmation.

1. Establish the normal response-time range first.
2. Use the smallest safe delay primitive that fits the suspected backend.
3. Compare true and false timing conditions more than once.
4. Keep delays conservative and avoid stacking expensive functions.

### Union Lane

Use only when the application appears to render query results inline.

1. Determine whether the response changes when the projected column count changes.
2. Use harmless constants or `NULL` placeholders only.
3. Confirm that the response incorporates the injected projection.
4. Do not pull table names, credentials, or user data.

## 4. Verify

Verification should prove query control with minimal noise and no extraction.

### Verification Standard

1. Reproduce the finding with the minimum lane-specific payload.
2. Capture the exact request and the corresponding response delta:
   - error snippet
   - true/false content drift
   - timing evidence
   - union-rendered constant
3. Record the most likely database family as an inference, not a certainty, unless the error explicitly names it.
4. Treat WAF-only blocking as inconclusive until you confirm the backend behavior behind the block.

### Status Rules

- `Confirmed`: the query behavior changes in a repeatable way that matches the chosen lane.
- `Potential`: filtering, timing jitter, or partial parser clues suggest SQLi but do not prove it yet.
- `False Positive`: the behavior is explained by validation, business logic, caching, or generic error handling.

## 5. Report

Write the result to:

`$HARNESS_SHARED_BASE/{program}/agent_shared/findings/sqli/findings.md`

Include:

- SQLi type: error, boolean, time, or union
- Exact input vector: query, `POST`, JSON, header, cookie, or path segment
- Suspected database family and why
- Payload used for confirmation
- Observable evidence
- WAF or filter behavior
- Confirmation status
- Safety note confirming that no data extraction was performed
