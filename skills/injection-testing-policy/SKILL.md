---
name: injection-testing-policy
description: "Use during SSRF, LFI/path traversal, XSS, SQLi, SSTI, command injection, XXE, open redirect, parser, sanitizer, allowlist, or WAF-filter testing when an input sink exists and agents need to decide whether and how to continue payload mutation without an immediate callback, reflection, or visible delta."
---

# Injection Testing Policy

Use this policy when an in-scope input can plausibly reach an interpreter,
parser, fetcher, renderer, filesystem, query builder, template engine, redirect
handler, sanitizer, validator, or WAF/filter.

Core posture: injection testing is controlled mutation. Once a plausible sink
exists, agents do not need confirmed reflection, callback, error output, or a
visible response delta before trying context-matched payload families. The
purpose of mutation is often to discover whether a validator, sanitizer,
allowlist, parser, WAF, or routing layer can be bypassed.

This policy inherits global live-testing limits from `live-testing-policy`.
It controls *why to continue* and *how to think about payloads*; it does not
override scope, rate, ownership, account, payment, cleanup, or stop boundaries.

## Load Order

1. Load `general-security-testing-policy` and `live-testing-policy`.
2. Confirm target scope, request-rate rules, auth state, and owned-resource
   boundaries.
3. Load the class skill: `ssrf`, `lfi`, `xss`, `sqli`, `ssti`,
   `prompt-injection`, `bypass`, `waf-live-policy`, or the closest specialist
   skill.
4. Load `request-exploration` when the interesting part is request shape,
   content type, headers, parser differentials, replay-vs-intercept, or state.
5. Load `waf-live-policy` when blocking, challenge pages, sanitizer behavior,
   payload stripping, or signature filtering appears.

## Continue Rule

Continue mutation when all of these are true:

- the target is in scope and the next request is rate-limited
- the input reaches or plausibly controls a relevant sink
- the next payload family is tied to an observed or plausible control
- the test does not seek real user data, secrets, persistence, service
  disruption, lateral movement, or non-owned resource impact

No immediate signal is not a stop reason by itself. For blind or filtered
classes such as SSRF, SQLi, SSTI, command injection, LFI, redirect, and XXE,
silence can mean the target accepted the input, blocked the input, followed an
unobservable path, normalized it, cached it, deferred it, or routed it through a
different parser. Mutation is how the agent distinguishes those cases.

## Control-First Payload Thinking

Before choosing payloads, identify what control might be in front of the sink:

- allowlist: domain, scheme, path, extension, MIME type, host, tenant, role,
  route, redirect destination, or file root
- blocklist: keywords, protocols, private IPs, traversal sequences, SQL tokens,
  HTML tags, event handlers, template markers, shell metacharacters
- sanitizer: HTML sanitizer, markdown renderer, filename scrubber, URL parser,
  JSON/XML parser, ORM query builder, template escaping, path normalizer
- WAF/CDN/filter: signature block, challenge page, body stripping, header
  normalization, method-specific filtering, content-type-specific filtering
- parser split: validator sees one value while backend/fetcher/browser/database
  sees another
- execution context: HTML text, attribute, script, URL, CSS, SQL string,
  numeric expression, shell argument, path, URL fetcher, XML entity, template

Payload choice should target the suspected control, not a generic checklist.
If the control is unknown, start with a small family that fingerprints it.

## Mutation Ladders

Use one ladder at a time. Stop a ladder when responses are redundant, the
control is understood, or a stronger lead appears. Pivot when the evidence
points to another control.

### SSRF

For a URL/fetch sink, lack of callback does not prove safety. Work through:

1. baseline public owned callback or harmless canary URL
2. scheme and parser variants: `http`, `https`, case, userinfo, fragments,
   encoded slashes/dots, backslash-vs-slash, absolute URL inside path
3. allowlist bypass: subdomain confusion, trailing dot, punycode/IDN when
   relevant, same-site redirect, CDN/storage redirect, open redirect chain
4. IP and DNS forms: loopback aliases, IPv6, IPv4-mapped IPv6, decimal/octal/
   hex/short IPv4, public host resolving to private IP
5. metadata/internal proof ladder only when program rules allow: root/status or
   non-secret key-name proof first; stop before credential use or enumeration

Think about what the validator likely blocks: private ranges, metadata host,
non-HTTP schemes, redirects, DNS resolution after validation, or host strings.

### LFI / Path Traversal

For file/path sinks, work through:

1. harmless file/path canary when available
2. traversal depth and separator variants
3. URL encoding, double encoding, mixed separators, dot normalization, null-byte
   style suffix behavior where stack-relevant
4. extension and directory allowlist bypass: suffixes, path truncation,
   wrapper-specific forms, archive/static-file resolver quirks
5. targeted low-risk stack files, then common sensitive paths only when needed
   for impact and allowed

Do not broad-enumerate files after proof.

### XSS / HTML Injection

For render sinks, work through:

1. inert marker and context classification
2. context-matched breakout: text, attribute, URL, script, CSS, SVG, markdown,
   HTML sanitizer, framework rendering, DOM source/sink
3. sanitizer fingerprinting: which tags, attributes, protocols, entities,
   casing, namespaces, and parser repairs survive
4. browser verification with the smallest execution proof
5. stored payload cleanup or restoration

Do not require generic reflection before DOM or stored-later investigation if
the workflow suggests a render point exists elsewhere.

### SQLi

For query-like sinks, work through:

1. baseline and type/context fingerprint: numeric, string, JSON, GraphQL,
   search, sort, filter, ORM object shape
2. syntax/error probes when low risk
3. boolean differentials with paired true/false payloads
4. timing checks only when bounded and program-safe
5. union/result-shaping only without data extraction

Do not extract data. Use differences, timing, and minimal proof.

### Template, Command, XXE, Redirect, Parser

Use the same pattern:

1. classify parser/context
2. send a small inert or arithmetic canary when safe
3. mutate delimiters, encodings, content type, structure, headers, and parser
   boundaries
4. prove the minimum boundary reached
5. stop before secret reads, destructive commands, internal scanning, or
   non-owned data exposure

## Stop And Ask

Stop or ask when:

- scope, rate rules, ownership, or program permission is unclear
- the next step requires internal scanning, metadata credential use, file
  enumeration, data extraction, shell expansion, persistence, or destructive
  behavior
- CAPTCHA/challenge escalation, hard 429, temporary ban, instability, or target
  stress appears
- the payload would affect non-owned users/resources, staff-visible workflows,
  public blast radius, payment/fulfillment, or hard-to-clean-up state
- the only remaining progress is broad brute force rather than a targeted
  mutation family

## Evidence

Record:

- full URL, method, auth state, account/resource ownership
- sink and parameter/header/body field/path
- baseline request/response summary
- suspected control: sanitizer, validator, allowlist, blocklist, WAF, parser,
  router, backend library, or unknown
- mutation family attempted and why it matched the suspected control
- response deltas, callback/browser/proxy evidence, or lack of signal
- stop reason and exact approval needed for the next higher-impact step

