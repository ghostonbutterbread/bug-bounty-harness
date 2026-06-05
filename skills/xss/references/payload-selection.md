# XSS Payload Selection

Payload quality is context matching, not memorizing one magic string.

Use Ryushe's existing payload sources as examples of good shapes:

- `/home/ryushe/projects/bug_bounty_harness/prompts/xss-payloads.md`
- `/home/ryushe/Shared/word_lists/xss/payloads.txt`

If `/home/ryushe/.axss/knowledge.db` has curated rows, query it by
`context_type`, `sink_type`, `bypass_family`, `delivery_mode`, and `frameworks`
instead of reading unrelated payloads.

Example query:

```bash
sqlite3 /home/ryushe/.axss/knowledge.db \
  "select context_type,sink_type,bypass_family,payload,explanation from curated_findings where context_type like '%attribute%' limit 20;"
```

## Selection Rules

1. Classify the context first.
2. Pick the smallest payload that exercises that context.
3. Preserve the parser behavior that made the lead interesting.
4. Mutate aggressively when filtering, encoding, sanitizer, WAF, framework, or
   browser/server desync behavior appears.
5. Verify in a browser or target-owned checker before calling it confirmed.

## Context Families

HTML body:

- tag creation
- tag close/open
- SVG/MathML events
- inert marker to dangerous-tag transition

Quoted attribute:

- quote breakout
- event-handler injection
- autofocus/focus/animation triggers
- malformed quote recovery

Unquoted attribute:

- whitespace separators
- slash separators
- event-handler insertion
- `>` tag breakouts

JavaScript string:

- string close and statement terminate
- `</script>` parser breakouts
- escaped quote and backslash behavior
- JSON/bootstrap parser differences

Template literal:

- `${...}` expression injection
- backtick close
- tagged-template or framework compiler behavior

URL-bearing context:

- `javascript:` handling
- `data:` and `blob:` handling
- same-origin redirector chains
- scheme-relative and encoded scheme confusion
- browser navigation vs server-side allowlist differences

DOM source-to-sink:

- URL/query/hash to `innerHTML`, `document.write`, `insertAdjacentHTML`,
  `outerHTML`
- storage/cookie to HTML sink
- `postMessage` to HTML/JS sink
- framework sanitizer bypass or explicit trust helpers

## Mutation Families

Use these as families, not ceilings:

- single, double, mixed, and partial encoding
- entity, Unicode, hex, percent, and backslash escapes
- case mutation
- quote minimization
- separator tricks: slash, newline, tab, form feed, comments
- duplicate/nested parameters
- content-type changes
- path/query/fragment relocation
- browser vs raw-client differences
- sanitizer differential probes
- framework-specific sink behavior

## Do Not

- spray every payload before classifying context
- stop because a payload is unusual
- report raw reflection as confirmed execution
- use stored payloads where cleanup or recipients are unclear
- involve real users, staff queues, or public surfaces without approval
