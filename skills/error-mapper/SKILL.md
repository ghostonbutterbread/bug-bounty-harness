---
name: error-mapper
description: "Use when gently mapping parser, validation, SQL-like, template-like, path, and encoding error behavior for one URL or small route cluster with low-rate comparison probes."
---

# Error Mapper

Use this when an agent is already reviewing one URL or a tight route cluster and
needs a small, safe probe set to learn how parameters, paths, or headers react to
common parser/error characters.

This is not a fuzzing skill. It is a bounded comparison method for deep URL
review and surface mapping.

## Load Order

1. Read scope, ownership/account context, and live-testing policy.
2. Read `$HARNESS_ROOT/prompts/error-mapper-playbook.md`.
3. Check `/url-ingest history` for the URL and lane before probing.
4. If the URL belongs to a section deep dive, keep the `/deep-hunt` hypothesis
   ID in every note and handoff.

## Commands

```text
/error-mapper <program> --url <full-url>
/error-mapper <program> --url <full-url> --params <comma-separated-param-list>
/error-mapper <program> --route-cluster <host-or-path-filter>
```

## Probe Boundaries

Default probe style:

- baseline request first
- one changed value at a time
- tiny character pack only
- low rate, with pauses between requests
- stop on WAF, CAPTCHA, rate limit, account risk, destructive ambiguity, or
  non-owned/private resource evidence

Default character families:

- quotes: `'`, `"`
- SQL-ish: `--`, `;`
- bracket/parser: `(`, `)`, `[`, `]`, `{`, `}`
- path-ish: `../`, `%2e%2e%2f`
- encoded/control-ish: `%00`, `%27`, `%22`

Use the playbook to choose the smallest relevant subset. Do not spray every
family into every field.

## Output

Record results through `/url-ingest mark` with:

- lane: `recon` or the owning lane such as `sqli`, `ssti`, `lfi`, `xss`
- skill: `error-mapper`
- test family: `parser-error-map`
- status: usually `surface_reviewed`; use `validated_signal` only for a
  concrete differential worth routing

Keep evidence compact: baseline status/length, changed status/length, visible
error class, response-shape delta, and the exact parameter/header/path segment
tested. Do not store secrets, cookies, tokens, private headers, or full raw
responses containing sensitive material.
