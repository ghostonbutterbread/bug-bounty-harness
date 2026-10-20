---
name: xss
description: Use when testing Cross-Site Scripting or routing XSS work into reflected, stored, DOM, or blind lanes. Load this first for XSS triage, then load reflected-xss, stored-xss, dom-xss, or blind-xss based on where attacker-controlled input lands.
---

# XSS Router

Classify the observed source or sink and its render consumer, then load the
matching lane as the path becomes clear. Explore context-matched parser and
sanitizer differentials while keeping impact, ownership, rate, cleanup, and
human-visible effects within the inherited live-testing boundary. A blocked
payload is evidence about a boundary, not a verdict on a plausible XSS path.

## Entry and lane selection

Read `general-security-testing-policy` and `live-testing-policy` before live
action. For a new hunt, use the former's
`references/opening-and-knowledge.md` for scope and cold-start guidance rather
than repeating that procedure here. Observe the current input and render context
with an inert marker, or trace a plausible consumer from its sink before querying
prior work; then retrieve only memory relevant to that observed surface. A
narrow or already warm vector need not produce a quota of unrelated findings.

**Breadth runs need a consumer.** Surface-first observation above is about not
letting a stale lead pick the target; it is not a reason for a sweep to ignore
its own program's warm backlog. A census that only adds leads without a
follow-up consumer can strand actionable work. When planning a breadth pass over
a program that already has warm, unresolved XSS leads, decide deliberately
whether this run adds coverage or drains the backlog, and say which. `leads`
owns cross-run reconciliation and `lead-followup`; `hypothesis-ledger` owns
stale and reclaimable owner work. This is guidance for run planning, not a
gate on probing.

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
| Sanitized/escaped output, inert payload matrices, or a second parser leave an idea-generation question | `xss-payload-engineering` → `references/mechanism-ideation.md` inside that skill; select a causal branch rather than a larger payload list |
| Observed renderer, parser, sanitizer, framework, or defense may change the next hypothesis | `xss-technology-research` |
| Filtering, challenge, or edge/origin difference needs characterization | `waf-live-policy` |
| A controlled source can select a GTM container ID or load a GTM script | `xss-gtm` for the preconfigured XSS fixture; selected lane still owns proof |

### Defense signals deepen the same XSS lane

A sanitizer hit, CSP violation, or WAF/filter block on an XSS vector is signal,
not an independent failed XSS attempt. When a controllable value has a
plausible executable consumer, locate the first observed blocker on the actual
source-to-consumer path and keep pressure on that same vector. Load
`references/defense-chain.md` for the layer-specific route and chain reasoning;
the selected XSS lane still owns browser proof. An easy unprotected sink is not
the ceiling of XSS coverage, and a blocked string without a plausible consumer
is not automatically a bypass lead.

- Sanitizer behavior: load `xss-technology-research` and `xss-payload-engineering` to map the observed transform and choose sanitizer-/parser-matched candidates.
- CSP behavior: distinguish delivered enforcement from Report-Only and establish an executable browser context before researching permitted execution paths with `xss-technology-research` and `xss-payload-engineering`.
- WAF/filter behavior: load `waf-live-policy` to classify the control, then return its evidence to the XSS candidate queue. Once a plausible consumer and reproducible filter differential exist, load `waf` plus `xss-waf-evasion` for the adaptive card → research → candidate → proof loop; a vendor label alone is not a bypass plan.
- Changed or later consumer: load `xss-lifecycle` and branch the original producer into the new render path rather than calling the first inert view a negative for all views.

When distinct probes meet similar resistance, ask whether the observed stack,
response differences, or relevant prior notes could explain the control and
change the next discriminator. If so, use `xss-technology-research` for that
specific question and test the resulting source, command, consumer, or payload
hypothesis; if not, keep probing non-equivalent, context-matched families. Do
not require a vendor fingerprint before probing, or mistake passing a filter
for execution in the claimed browser/consumer. Continue until the relevant
defense/parser boundary is understood or an inherited safety or stop boundary
applies; no fixed bypass count or CSP/sanitizer/WAF difficulty order decides
when to pivot.

The parent XSS agent owns synthesis, execution choices, and hypothesis closure.

## Investigate the path

Start from a controlled input **or** a plausible sink; trace toward the missing
end and switch direction when evidence suggests a better route. Ask how another
user could encounter the value, but do not use a missing delivery path as a gate
against exploring a promising sink. Keep self-only execution and source-starved
sinks as chain leads with their missing link and reopening condition.

1. Identify the observed source or sink, its possible feeders and consumers, and
   the render context. Compare raw response and browser behavior when client-side
   processing could change it.
2. Use an inert marker or source/sink trace to distinguish reflection, persistence,
   DOM flow, a later consumer, and a defense transform. Query prior state for
   that concrete path; do not let an old lead choose the target by default.
3. Choose the next distinct context-matched discriminator. Use
   `xss-payload-engineering` for the payload family and
   `xss-technology-research` when a fingerprint could change that choice.
   Before interpreting a non-firing family, distinguish input rejected, value
   stored, consumer mounted, inert control rendered, candidate rendered, and
   execution blocked. If the consumer never mounted, fix reachability or name
   the missing owned fixture; do not infer that a sanitizer held. For a
   mounted consumer, identify the first changed representation and use
   `xss-payload-engineering/references/mechanism-ideation.md` to derive a
   different mechanism or a falsifying control.
4. Load `attempt-recording-policy` for each deliberate target-directed probe,
   comparison, and retest. It owns the exact canonical writer, fields, redaction,
   and MapStore promotion; do not create an XSS-specific event shape.
5. Use the selected lane for browser proof, later-consumer checks, cleanup, and
   report shape. Preserve the residual question and exact stop boundary.

For a route cluster or `/hybrid`/`/hunter-loop` run, investigate source-to-sink
paths from either end before increasing payload volume. An inventory or static
sink label is a lead, not a taint trace or browser proof. Do not mark a route
complete from raw HTTP when browser routing, challenge behavior, or framework
rendering matters.

For a breadth pass, inventory **both** named input locations/fields and render
sites in the same JS corpus (`source_sites` and `sink_sites`), and reconcile the
program's parameter artifacts with the relevant route or writer. Start with the
stronger observed end; do not delay an existing controlled path for a full
census. Probe actual named fields on name-keyed renderers rather than declaring
coverage from random canary parameter names. A source/sink match by name, file,
or proximity is a review lead; trace the value through its caller, request,
response, and transforms before claiming an edge. Load `parameter-mining` for
source-attributed candidates and `references/source-acquisition.md` for the
paired inventory and scoped exhaustion decision.

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
missing owned fixture or unexplored consumer exhausted. For the non-payload axes
a vector can still be varied along, and for recording an exhaustion claim a
reader can falsify, load `references/continuation-dimensions.md`.

## Missing source and sink census

A confirmed sink without a reachable attacker-controlled source is a routing
question, not an automatic negative. Classify the blocker:

| Evidence | Next action |
| --- | --- |
| An authorized source exists but needs an owned account, field, object, or session | `account-testing-policy`; name the missing artifact and reopening condition. |
| A source exists but the server constrains its value space | `injection-testing-policy` or `waf-live-policy`; characterize the actual server boundary. |
| No attacker-controlled source reaches this consumer | Before recording the negative, check the writer inventory in `references/source-acquisition.md`; state which link cannot exist. Reconsider if source or consumer evidence changes. |

The first two are open work, not `exhausted`. Do not call a client-only regex a
server constraint. For sink-group and distinct ingress-path coverage, finding
writers, stack-matched parameter discovery, prioritization, sanitizer posture,
impact amplifiers, or census refresh decisions, load
`references/source-acquisition.md` when those questions arise.

Load `/bb-script-rules` when running a sink census; the same rule applies to a
source census. XSS-specific render
consumers to inspect in the observed stack include raw-HTML helpers, URL
navigation, legacy bundles, microfrontends, and bootstrap data. Group common
downstream consumers for review, but keep distinct input routes and their
defenses separate. Track unexamined paths instead of treating the ranked sink
list as coverage.

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
and source maps; apply scope and rate controls. Inspect `source_sites` alongside
`sink_sites` in `metadata.jsonl`, `source_map_modules.jsonl`, and review packets;
both are bounded, non-exhaustive seeds. See `docs/xss-sink-inventory.md` for
sink categories and limits. Select tool detail
only when its question arises rather than preloading every scanner.

For context-specific payload seeds, use
`skills/xss/references/payload-selection.md`; it is not a complete payload
ceiling.

## Evidence and status

Keep the source, sink/render context, auth/ownership state, meaningful
transforms, browser result, later-consumer question, cleanup state, and
sanitized Attempts/MapStore pointers. `attempt-recording-policy` owns the
per-probe record; the selected XSS lane owns its proof and report shape.
After mapping a selected route/action/input/consumer, load `/coverage` and
register that path as `no_assessment` via `agents/coverage.py discover`. For an XSS
canary mapper `plan`, use `--xss-canary-sources <plan-dir>/sources.jsonl` with
`--source-ref recon/xss/<mapper-run>/sources.jsonl`: a sanitized, lane-relative
artifact reference, **not** the local absolute scratch path. Inspect path
components and scope before import. Planned inventory is not a reflection or a
verified consumer. At selection read a bounded `brief --class-name xss`; at
pivot/handoff assess only the exact reviewed path/class with its reviewed
fingerprint, typed `attempt:<run>:<id>` and `map:<maps-relative-path>` pointers,
then `verify`. An inert response remains in progress for browser/consumer
review. `blocked` needs a real prerequisite and reopen condition; no one
payload closes sibling inputs. `ledgers/coverage.json` is static file/snapshot
review, never live URL status.
After a validated XSS finding is captured, load `impact-escalation`, which
explicitly routes to `xss-escalation` for victim-action and durable-access ideas
before final report preparation. This does not delay the initial finding or
replace the XSS lane's execution and delivery proof.

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

## Scripts map

- [`scripts/README.md`](scripts/README.md) — maintained XSS helper records and
  invocations. Use `bbh skills/xss/scripts/xss_canary_mapper.py` to map inert
  canaries from selected input artifacts to observed reflections; its sink
  classifications are non-exhaustive leads, not browser proof.
- `bbh agents/js_analyzer.py inventory` — use through `/js` for a static JS and
  source-map named-source and sink census (`agents/xss_source_sites.py` and
  `agents/xss_sink_sites.py`). The inventory supplies review leads, not verified
  source-to-sink paths; see `docs/xss-sink-inventory.md` for coverage limits.
