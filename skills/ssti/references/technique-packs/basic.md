# SSTI Basic Technique Pack

Use this pack for first-pass SSTI testing. Keep proofs low-noise and reversible.

## What To Look For

- User input becomes part of a server-rendered template string.
- The response contains evaluated template output, not just reflected text.
- Errors mention a template engine, template parser, template file, or expression language.
- A feature lets privileged users edit templates, notifications, documents, or page blocks.

## Mechanism

A template engine decides which parts of a string are **data** and which are an
**expression** to evaluate. A bug exists when user input lands on the expression
side of that split. So the probe is never "does my payload work" — it is "does
this engine evaluate what I control", and then "which engine is it", because
every onward step is engine-specific.

An arithmetic probe is the cheapest test of that split: `7*7` is meaningless as
data and unambiguous as an expression, so `49` in the response can only come
from evaluation. Prefer arithmetic over anything with side effects.

## Low-Noise Probes

Use one probe family at a time and compare against a baseline:

- Curly expression: `{{7*7}}`
- Dollar expression: `${7*7}`
- Hash expression: `#{7*7}`
- ERB expression: `<%= 7*7 %>`
- Single-brace expression: `{7*7}`
- Razor-style expression: `@(7*7)`

Expected evidence: computed output such as `49`, an engine-specific type/string result, or a clear template parse error.

## Which syntax implies which engine

A hit narrows the engine; it does not name it. Use this to pick the next
discriminator rather than to conclude.

| Syntax that evaluated | Candidate engines |
|---|---|
| `{{7*7}}` | Jinja2, Django, Twig, Nunjucks, Handlebars, Liquid, Angular (client-side) |
| `${7*7}` | Freemarker, Velocity, JSP EL, Thymeleaf, JavaScript template literal |
| `#{7*7}` | Ruby interpolation, Thymeleaf, JSF EL |
| `<%= 7*7 %>` | ERB, EJS, JSP scriptlet, ASP |
| `{7*7}` | Smarty, some custom or string-format engines |
| `@(7*7)` | Razor |

Discriminate within a candidate set using syntax one engine accepts and another
rejects, and confirm with the supporting clues below. For example `{{7*'7'}}`
returning `7777777` indicates Jinja2-style string repetition while Twig returns
`49`; a family that errors rather than evaluating is also information.

Record the engine as a hypothesis with its evidence, not a conclusion, until two
independent signals agree. Onward escalation primitives differ per engine, so an
unidentified engine means the next step is identification, not a bigger payload.

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
