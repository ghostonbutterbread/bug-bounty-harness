---
name: sqli
description: "Use when testing SQL injection, SQLi, database query injection, parameter tampering against SQL-backed endpoints, error-based injection, boolean/time-based injection, or stacked query behavior."
---

# SQL Injection Testing

Use for SQL injection: attacker-controlled input that may change SQL query
structure, query logic, result shape, database errors, timing, OAST behavior, or
stored second-order query behavior.

This is a RAG-style skill. Load a small "where to look" reference first, then a
small PortSwigger-derived "what to try" seed reference once a likely SQL-backed
surface exists. Treat references as idea seeds, not lab walkthroughs or a
complete ceiling.

## Load Order

1. Read scope, owned-account context, and active live-testing policy.
2. Resolve `$HARNESS_ROOT`; default is `/home/ryushe/projects/bug_bounty_harness`.
3. After selecting a likely SQL-backed URL/parameter, read relevant shared
   state in this order when it helps understand the surface:
   - `notes/summary.md`
   - `notes/observations.md`
   - `checklist.md` (SQLi items only)
   - `todo.md` (SQLi items only)
4. Load:
   - `general-security-testing-policy`
   - `live-testing-policy`
   - `injection-testing-policy`
5. Read `references/common-locations.md` to decide where to hunt.
6. After finding a likely SQL-backed surface, read `references/portswigger-lab-seeds.md` for PortSwigger Academy SQLi lane prompts and source links.
7. Use `$HARNESS_ROOT/prompts/sqli-payloads.md` only after choosing a lane.
8. Read `$HARNESS_ROOT/prompts/sqli-playbook.md` only for deep review, stuck
   analysis, or report writing.
9. Route instead of duplicating:
   - encoding, parser, WAF, or filter mutations -> `/bypass` or `/waf`
   - auth, tenant, or object-boundary impact -> `/access-control` or `/idor`
   - one live proxy request capture/replay -> `/single-request-grabber`

No visible error or response delta from the first SQLi probe is not a stop
reason by itself. Classify the likely query context and control first, then run
paired error, boolean, timing, result-shaping, or OAST probes as allowed.

## Workflow

1. Identify the entry point, request shape, and likely query role.
2. Establish a benign baseline and one paired control before escalating payload complexity.
3. Classify the lane: error, boolean, time, union/result-shaping, OAST, second-order, or structured-format SQLi.
4. Run the smallest bounded probe that can prove query influence.
5. Prefer proof of query control or authorization impact over data extraction.
6. Stop after proving the boundary reached.

## Primary Harness

There is no dedicated `agents/sqli_hunter.py` in this repo. Treat your
browser/proxy request replay workflow as the primary execution surface and use
`agents/payload_mutator.py` to generate context-aware SQLi variants after you
have classified the sink.

Use the mutator only after you know which lane you are in.

```bash
python agents/payload_mutator.py "' OR 1=1--" --type sqli --count 12
```

## Mode Matrix

| Mode | Use When | What It Confirms |
|------|----------|------------------|
| `error` | Input causes syntax changes or stack traces | Whether the backend leaks parser or database fingerprints |
| `boolean` | Response changes without explicit errors | Whether the query logic is injectable without noisy output |
| `time` | Output is blind but the request timing is observable | Whether a delay primitive is reachable safely |
| `union` | The sink appears to return query results inline | Whether result-shaping and column control are possible |
| `oast` | No response/timing channel is reliable | Whether database-triggered outbound interaction is possible |
| `second-order` | Input is stored then later used by another flow | Whether stored data becomes query structure later |

## Proof Standard

Promote only when evidence shows controlled SQL query influence plus a security
impact: unauthorized read/list, auth bypass, hidden-data exposure, cross-object
or cross-tenant access, meaningful state change, or database fingerprinting that
materially supports exploitation.

Do not promote generic errors, soft redirects, response-size speculation,
WAF-only behavior, or data returned only from caller-owned scope.

## Stop Conditions

Stop before extracting secrets, dumping tables, testing destructive stacked
queries, modifying non-owned state, inducing heavy database load, or using OAST
payloads against unclear scope without approval.

## Evidence

Write findings to `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/sqli/findings.md`.

Record full URL, parameter/body field/header/cookie, request context, loaded
reference pack, SQLi lane, baseline and control responses, timing samples if
used, database fingerprint if known, affected boundary, stop condition, and
confirmation status.
