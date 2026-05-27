# SSTI Basic Technique Pack

Use this pack for first-pass SSTI testing. Keep proofs low-noise and reversible.

## What To Look For

- User input becomes part of a server-rendered template string.
- The response contains evaluated template output, not just reflected text.
- Errors mention a template engine, template parser, template file, or expression language.
- A feature lets privileged users edit templates, notifications, documents, or page blocks.

## Low-Noise Probes

Use one probe family at a time and compare against a baseline:

- Curly expression: `{{7*7}}`
- Dollar expression: `${7*7}`
- Hash expression: `#{7*7}`
- ERB expression: `<%= 7*7 %>`
- Single-brace expression: `{7*7}`
- Razor-style expression: `@(7*7)`

Expected evidence: computed output such as `49`, an engine-specific type/string result, or a clear template parse error.

## Fingerprinting Tips

- Do not identify the engine from `{{7*7}}` alone. Several engines share that syntax.
- Compare nearby syntax families when safe: curly, dollar, ERB, hash, single-brace, and at-sign expressions.
- Use error text, template file extensions, stack traces, framework hints, and response headers as supporting clues.
- For Jinja-like contexts, harmless object/context checks may prove engine behavior, but do not dump secrets or full config on real targets.

## Common False Positives

- The value is reflected literally.
- The browser or frontend framework evaluates it client-side.
- The response contains `49` from unrelated content.
- A generic error page appears for many invalid inputs.
- A WAF blocks template-looking syntax before the backend sees it.
- The endpoint transforms text through markdown, formatting, or search highlighting without template execution.

## Safe Escalation

Escalate only as far as needed to prove the issue:

1. Marker reflection.
2. Arithmetic evaluation.
3. Engine fingerprint clue.
4. Owned test object/context proof if needed.

Stop before command execution, file reads, secret/config dumps, cloud metadata access, or callbacks unless Ryushe approves the exact action.

## Source Notes

- PortSwigger's Academy flow separates detection, engine identification, and exploitation, and calls out plaintext versus code context.
- PortSwigger Research emphasizes that SSTI is often mistaken for XSS but can affect server internals.
- PayloadsAllTheThings groups detection styles into rendered, error-based, boolean, time-based, out-of-band, and polyglot approaches.
- HackTricks' Jinja notes are useful for understanding context and available objects, but many examples go beyond safe proof for live bounty targets.
