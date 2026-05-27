# SSTI Testing Playbook

## Overview

Use this as a small decision tree: find server-rendered user input, probe for template syntax evaluation, fingerprint the engine with minimal payloads, then report the safest proof.

Primary references:

- PortSwigger Web Security Academy: `https://portswigger.net/web-security/server-side-template-injection`
- PortSwigger Research: `https://portswigger.net/research/server-side-template-injection`
- PayloadsAllTheThings SSTI: `https://swisskyrepo.github.io/PayloadsAllTheThings/Server%20Side%20Template%20Injection/`
- HackTricks Jinja2 SSTI notes: `https://hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/jinja2-ssti.html`

## 1. Find Candidate Sinks

Prioritize places where the server likely renders text into a template:

- Search, profile, username, display name, organization name, and address fields
- Email templates, notification templates, invoice/export templates, and PDF generation
- CMS blocks, markdown previews, rich text previews, and custom theme/template editors
- Error pages, status pages, preview endpoints, and admin/content moderation views
- API parameters that later appear in server-generated HTML, email, or document output

Do not assume every reflection is SSTI. First separate server-rendered output from browser-only rendering.

## 2. Probe Lightly

Start with a unique marker and capture baseline status, body length, rendered location, and timing.

Then try safe expression probes in the exact rendered location:

- `{{7*7}}`
- `${7*7}`
- `#{7*7}`
- `<%= 7*7 %>`
- `{7*7}`
- `@(7*7)`

Expected signal: the response contains the computed result such as `49`, or the response changes in an engine-specific way.

Use syntax-error probes only when arithmetic is inconclusive and the program allows low-noise testing. Record the error family, not just that an error occurred.

## 3. Classify Context

Plaintext context:

- The payload is rendered as normal output.
- Arithmetic evaluation is usually the safest proof.
- Compare a true result against a control value so caching or business logic does not explain it.

Code context:

- The input appears to become part of an existing template expression or variable lookup.
- A direct arithmetic probe may fail.
- Try closing or breaking out of the surrounding expression only after capturing the baseline context.

Client-side template context:

- Angular, Vue, Handlebars, or other browser-side rendering may look similar.
- Keep it out of SSTI unless the server returns evaluated output before browser execution.
- Route browser-side execution to `/xss` or a frontend-specific lane.

## 4. Fingerprint Carefully

Use behavior, errors, and small expression differences:

- `{{7*7}}` works in multiple engines, so it is not enough to name one.
- `{{7*'7'}}` can help separate Jinja-style string multiplication from Twig-style numeric behavior.
- `${7*7}` may indicate Java, Mako, Groovy, or other dollar-expression engines.
- `<%= 7*7 %>` points toward ERB-style syntax if evaluated.
- Engine names, stack traces, template file extensions, and framework headers are supporting evidence.

State the engine as an inference unless the application explicitly reveals it.

## 5. Verify Safely

A good proof is repeatable and low impact:

1. Baseline marker shows where the input renders.
2. Arithmetic probe shows server-side evaluation.
3. Control probe does not produce the same output.
4. Engine fingerprint is supported by at least one extra clue.

Avoid file reads, command execution, environment dumps, secret/config dumps, network callbacks, and expensive loops unless Ryushe explicitly approves the exact test.

## 6. Report

Write the result to:

`$HARNESS_SHARED_BASE/{program}/agent_shared/findings/ssti/findings.md`

Include:

- Exact endpoint and full URL
- Input vector: query, form, JSON, header, cookie, path, template editor, email/document field
- Render location and auth state
- Baseline marker and response behavior
- Payloads used for proof
- Computed output or error evidence
- Suspected template engine and why
- Whether `/bypass` or `bypass_harness.py --type ssti` was used
- Safety note confirming no command execution, file read, or secret extraction was attempted

## 7. When To Hand Off

- `/bypass`: one target URL/parameter is ready for bounded payload variation.
- `/xss`: evidence is browser-side template execution or HTML/JS execution, not server-side evaluation.
- `/access-control`: template editing is restricted by role, workflow, tenant, or object ownership.
- `/waf`: a promising sink is blocked only by filtering or security middleware.
