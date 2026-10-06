---
name: xss
description: Use when testing Cross-Site Scripting or routing XSS work into reflected, stored, DOM, or blind lanes. Load this first for XSS triage, then load reflected-xss, stored-xss, dom-xss, or blind-xss based on where attacker-controlled input lands.
---

# XSS Router

Classify the controlled source and its render consumer, then load the matching
lane. Explore context-matched parser and sanitizer differentials while keeping
impact, ownership, rate, cleanup, and human-visible effects within the inherited
live-testing boundary. A blocked payload is evidence about a boundary, not a
verdict on a plausible XSS path.

## Entry and lane selection

Read `general-security-testing-policy` and `live-testing-policy` before live
action. For a new hunt, use the former's
`references/opening-and-knowledge.md` for scope and cold-start guidance rather
than repeating that procedure here. Observe the current input and render context
with an inert marker or an appropriate browser/source trace before querying
prior work; then retrieve only memory relevant to that observed surface. A
narrow or already warm vector need not produce a quota of unrelated findings.

Load `injection-testing-policy` when an input, parser, sanitizer, or render sink
is plausible. Load `waf-live-policy` when filtering, normalization, challenge,
or an edge/origin difference becomes the next question.

| Observed path | Lane |
| --- | --- |
| Input lands in the immediate response | `reflected-xss` |
| Stored input reaches a later view, message, email, export, or feed | `stored-xss` |
| Client-side source reaches a DOM sink or renderer | `dom-xss` |
| The likely consumer is an unobservable human/system view | `blind-xss` |

Load all relevant lanes when paths overlap: a stored value may become DOM XSS,
and a reflected value may become dangerous only after client-side parsing.

## Next-question overlays

| Evidence or decision | Load |
| --- | --- |
| Controlled value persists, transforms, or reaches a later consumer | `xss-lifecycle` |
| Plausible warm/hot vector needs payload selection, mutation, or reduction | `xss-payload-engineering` |
| Observed renderer, parser, sanitizer, framework, or defense may change the next hypothesis | `xss-technology-research` |
| Filtering, challenge, or edge/origin difference needs characterization | `waf-live-policy` |

### Defense signals deepen the same XSS lane

A sanitizer hit or WAF/filter block on an XSS vector is signal, not an independent failed XSS attempt. When a controllable value has a plausible executable consumer, keep pressure on that same vector:

- Sanitizer behavior: load `xss-technology-research` and `xss-payload-engineering` to map the observed transform and choose sanitizer-/parser-matched candidates.
- WAF/filter behavior: load `waf-live-policy` to classify the control, then return its evidence to the XSS candidate queue.

Continue with non-equivalent, context-matched families until the relevant defense/parser boundary is understood or an inherited safety or stop boundary applies.

The parent XSS agent owns synthesis, execution choices, and hypothesis closure.

## Investigate the path

1. Identify the controlled source, its consumer and render context. Compare raw
   response and browser behavior when client-side processing could change it.
2. Use an inert marker or source trace to distinguish reflection, persistence,
   DOM flow, a later consumer, and a defense transform. Query prior state for
   that concrete path; do not let an old lead choose the target by default.
3. Choose the next distinct context-matched discriminator. Use
   `xss-payload-engineering` for the payload family and
   `xss-technology-research` when a fingerprint could change that choice.
4. Load `attempt-recording-policy` for each deliberate target-directed probe,
   comparison, and retest. It owns the exact canonical writer, fields, redaction,
   and MapStore promotion; do not create an XSS-specific event shape.
5. Use the selected lane for browser proof, later-consumer checks, cleanup, and
   report shape. Preserve the residual question and exact stop boundary.

For a route cluster or `/hybrid`/`/hunter-loop` run, map the source-to-sink path
before increasing payload volume. An inventory or static sink label is a lead,
not a taint trace or browser proof. Do not mark a route complete from raw HTTP
when browser routing, challenge behavior, or framework rendering matters.

**Pressure state:** `cold` means a context-appropriate discovery pass has not
established a plausible XSS path; `warm` means controlled input reflects,
persists, reaches a relevant DOM/renderer, or meets a transform with a plausible
executable consumer; `hot` means controlled bytes influence a dangerous
context or executable consumer; `pending` means a correlated blind probe awaits
its external consumer; `exhausted` means representative families and the
relevant parser/consumer boundary are understood. A filter hit alone, without a
plausible path, is not automatically `warm`.

Pivot from `cold` only after a context-appropriate discovery pass fails to
establish a plausible path—not after one inert probe. A `pending` lane remains
open while the callback is unresolved; pursue other hypotheses without retiring
it. Keep pressure on `warm`/`hot` vectors with non-equivalent families until the
boundary is understood, another consumer branches, or inherited safety/stop
rules apply. `exhausted` requires evidence for the path examined; do not call a
missing owned fixture or unexplored consumer exhausted.

## Missing source and sink census

A confirmed sink without a reachable attacker-controlled source is a routing
question, not an automatic negative. Classify the blocker:

| Evidence | Next action |
| --- | --- |
| An authorized source exists but needs an owned account, field, object, or session | `account-testing-policy`; name the missing artifact and reopening condition. |
| A source exists but the server constrains its value space | `injection-testing-policy` or `waf-live-policy`; characterize the actual server boundary. |
| No attacker-controlled source reaches this consumer | Record the evidenced negative for that path; reconsider if source or consumer evidence changes. |

The first two are open work, not `exhausted`. Do not call a client-only regex a
server constraint. For prioritization, sanitizer configuration, an existing
impact amplifier, and the condition to rerun a sink census, load
`references/source-acquisition.md` when those questions arise.

Load `/bb-script-rules` when running a sink census. XSS-specific render
consumers to inspect in the observed stack include raw-HTML helpers, URL
navigation, legacy bundles, microfrontends, and bootstrap data. Track
unexamined source-to-sink paths instead of treating the ranked sink list as
coverage.

## Discovery tools, when they answer the next question

For broad parameter/reflection screening, consider Dalfox. For an SPA, route
cluster, or authenticated mapping question, consider Dursgo. Both yield triage
leads, not confirmed XSS. Do not delay investigation of an existing source-to-sink path
for a broad scan. See `references/tool-assisted-discovery.md` and load
`bounty-tools` when running either tool; the former also has the BBH
`agents/xss_framework.py` and `agents/xss_hunter.py` command examples.

For deterministic canary mapping use `skills/xss/scripts/xss_canary_mapper.py`;
use `--offline`/`plan`/`scan` for artifact-only work. For static bundle census,
load `js` and run
`bbh agents/js_analyzer.py inventory <program> --input <js-url-list> --target-host <in-scope-host>`.
Inventory analysis is static, but collection may download uncached scoped JS URLs
and source maps; apply scope and rate controls. Sink labels are non-exhaustive;
see `docs/xss-sink-inventory.md` for categories and limits. Select tool detail
only when its question arises rather than preloading every scanner.

For context-specific payload seeds, use
`skills/xss/references/payload-selection.md`; it is not a complete payload
ceiling.

## Evidence and status

Keep the source, sink/render context, auth/ownership state, meaningful
transforms, browser result, later-consumer question, cleanup state, and
sanitized Attempts/MapStore pointers. `attempt-recording-policy` owns the
per-probe record; the selected XSS lane owns its proof and report shape.

- `Confirmed`: browser or equivalent execution evidence for the controlled
  payload in the claimed consumer.
- `Likely`: strong source-to-executable-context evidence but execution proof is
  unavailable; name the blocker.
- `Potential`: controllable input and a plausible path, but exploitability is
  unproven.
- `Pending-OOB`: correlated blind probe planted, callback unresolved. A
  correlated fire from the planted executable payload with executing origin
  and page evidence is `Confirmed`; a bare collector hit without that proof
  is not.
- `False positive`: the claimed path is evidenced inert or unreachable in the
  tested context. Do not extend that negative to untested consumers.
