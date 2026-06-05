---
name: xss
description: Use when testing Cross-Site Scripting or routing XSS work into reflected, stored, or DOM lanes. Load this first for XSS triage, then load reflected-xss, stored-xss, or dom-xss based on where attacker-controlled input lands.
---

# XSS Router

Use this as the XSS routing card. It should classify the XSS shape, load the
right lane skill, and keep payload choice tied to the actual render context.

Core posture: XSS testing is controlled rule-breaking. Be creative with payload
shape, encodings, parser confusion, sanitizer breakouts, framework quirks, and
browser/server differences. Be conservative with impact, ownership, rate,
cleanup, and human-visible side effects.

## Required Preflight

Read shared state in this order before testing when the files exist:

1. `notes/summary.md`
2. `notes/observations.md`
3. `checklist.md` (XSS items only)
4. `todo.md` (XSS items only)

Also load:

- `general-security-testing-policy`
- `live-testing-policy`
- `injection-testing-policy` once a render sink, stored render point, DOM sink,
  sanitizer, markdown/HTML parser, or browser/server parser boundary is
  plausible
- `waf-live-policy` when payloads are blocked, filtered, normalized, challenged,
  or mutated

## Route Selection

Load the smallest matching lane:

| Signal | Load | Why |
| --- | --- | --- |
| Marker appears in the immediate HTTP response | `reflected-xss` | Immediate render/context breakout and browser proof. |
| Marker is saved and appears later in another view, notification, admin page, email, export, or feed | `stored-xss` | Persistence, render-point discovery, cleanup, and blast-radius control. |
| Marker reaches client-side sources/sinks such as URL, hash, storage, `postMessage`, router state, or JS-generated HTML | `dom-xss` | Browser source-to-sink verification and framework behavior. |
| More than one is plausible | Load all relevant lanes, but keep notes separated by lane. |

Do not treat these lanes as mutually exclusive. A stored value can become DOM
XSS at render time; a reflected value can be inert in raw HTML but exploitable
after client-side parsing; a DOM route can also call server APIs.

## Shared Payload Sources

Use context-specific payloads, not generic spraying. Start with the shared
payload-selection reference:

- `skills/xss/references/payload-selection.md`

Useful local sources:

- `/home/ryushe/projects/bug_bounty_harness/prompts/xss-playbook.md`
- `/home/ryushe/projects/bug_bounty_harness/prompts/xss-payloads.md`
- `/home/ryushe/Shared/word_lists/xss/payloads.txt`
- `/home/ryushe/.axss/knowledge.db` when curated rows exist

## Harnesses

Use `agents/xss_framework.py` for broad XSS work. It handles discovery,
reflection screening, reflected/stored/DOM lanes, and optional browser
verification.

```bash
python /home/ryushe/projects/bug_bounty_harness/agents/xss_framework.py \
  --target https://target.example/search?q=test \
  --program target \
  --mode full \
  --rate-limit 2
```

Use `agents/xss_hunter.py` for narrower parameter-focused passes.

```bash
python /home/ryushe/projects/bug_bounty_harness/agents/xss_hunter.py \
  --target https://target.example/search?q=test \
  --program target \
  --depth deep \
  --rate-limit 5
```

## Working Loop

1. Identify the input vector: query, path, body, JSON, header, cookie, upload,
   stored object field, router state, storage, or message.
2. Send an inert marker and record where it lands.
3. Classify the render context before choosing payloads.
4. Load `reflected-xss`, `stored-xss`, or `dom-xss`.
5. Use the lane skill to pick payload families, browser proof, cleanup, and
   report shape.
6. Escalate to `waf-live-policy` and bypass/mutation work when filtering or
   parsing behavior becomes the interesting surface.

## Evidence Standard

Record:

- full URL and request method
- auth state and account/resource ownership
- exact vector and parameter/header/body field
- context where input landed
- payload family and why it matched that context
- browser verification status
- interaction needed, if any
- cleanup state for stored payloads
- stop reason or next lane

## Status Rules

- `Confirmed`: JavaScript execution occurred in a browser or equivalent checker.
- `Likely`: source, sink, and context are strong but browser execution is blocked.
- `Potential`: controllable reflection/storage/source-to-sink exists, but the
  exploit path is not proven.
- `False positive`: the value is inert, safely encoded, unreachable, or blocked
  in the tested context.
