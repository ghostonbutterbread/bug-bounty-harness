# XSS idea-depth augmentation — before, after, and why

- **Status:** reviewed beta methodology note (not a target finding).
- **Owner:** BBH `xss` router and `xss-payload-engineering`.
- **Canonical path:** `docs/xss-mechanism-ideation.md`.
- **Supersedes:** none; complements the existing parser-stage reference and ResearchMap.
- **Implementation commits:** `639480ba23b2b490124b4866cd22a883be48412b`
  (initial feature), `7273a774a73059151df48c92cde93d5756634536`
  (reviewed mXSS/composition correction). Initially promoted to beta by
  `40077525c9794aff425aadcfe68d220f20121d6c`.

## The gap, without understating existing coverage

Before this change, the XSS router already differentiated reflected, stored,
DOM, and blind consumers, followed later renderers, and treated filters as
signal. Payload engineering already offered context-directed and exploratory
queues, while `parser-stage-character-variants.md` correctly constrained
encoding/Unicode folklore. ResearchMap already held portable, technology-specific
cards; the existing system can find ordinary XSS. What was missing was a
**repeatable next-idea procedure** between a surprisingly inert result and the
next payload family: a negative often lacked proof that the actual consumer
mounted, or a presumed second parser was never present.

A bounded read-only review of 12 recent XSS Attempt streams found 110 raw JSON
objects; the canonical reader returned 40, with 70 legacy objects lacking the
required event envelope. The sample mixes probes, setup and observations, so it
is **not** a count of tested payloads or a complete audit of agent behavior.
Examples that changed the design:

- `bunny-xss5-ld-20261020T193933Z-m6`, `A-m6-012` / `A-m6b-009`:
  discussion content or panel was absent, so a non-firing canary did not
  establish sanitizer safety. New route asks for mounted consumer and inert
  render control before interpreting execution failure.
- The same run's `m4-prescreen-harness-config` found no hypothesized HTML
  reparse in the report consumer; its 26-family local prescreen was inert in
  that configuration. New guide makes the exact parser edge falsifiable before
  launching another variant matrix. The live route was gated, so this was not
  live report-consumer proof.
- `bunny-xss5-ld-20261020T193933Z-m2m3`,
  `bbx5m2-flaglinks-closure` reported a URL-scheme matrix rejected at the
  writer, while `bbx5m3-sessionexport-closure` had no owned sessions. New guide
  distinguishes a real value constraint from an absent fixture; neither is a
  generic instruction to try percent-encoded `javascript:`.
- `sc-xss-20261017`, `A-wp03-title-render` saw stored input but escaped text
  in its browser consumer. New guide suggests *an observed different renderer
  or writer*, not claiming the same view is vulnerable.

These are sanitized navigation pointers into existing private Attempts, not a
transcription of URLs, account data, or payloads. No program was probed for
this change; the sample supports design priorities, not a comparative success
rate.

## The new agent path

```text
Before:
observed sanitizer/filter → generic context/exploratory payload queues
                    → more syntax variants → browser proof if they reach a sink

After:
source/sink observation → consumer mounted + inert control?
   no → name missing fixture/renderer and reopening condition
   yes → identify first changed representation and *actual* final interpreter
         → pick one causal branch (reparse / post-check assembly /
           URL parser mismatch / changed consumer / trusted-call path)
         → choose the smallest candidate + falsifying safe control
         → inspect the resulting DOM/navigation and browser execution
         → record target Attempts/MapStore; query portable cards by exact edge
```

Nothing changes authorization, rate limits, XSS lane ownership, browser proof,
or research-card admission. `skills/xss/SKILL.md` routes the uncertainty;
`skills/xss-payload-engineering/SKILL.md` routes to the on-demand
`references/mechanism-ideation.md`; `xss-technology-research` points back to
that exact-edge question before card search. This is a branch of the existing
skill graph, not a second XSS workflow or new app-specific store. The method
covers mXSS, fragment composition, URL check/parser differences, later
consumers, structural DOM influence, Trusted Types/CSP caller conditions, and
async renderer provenance with explicit falsifiers.

## Learning example and actual offline proof

The checked-in `tests/fixtures/xss_composition.html` is deliberately unsafe
*toy application code*, not a production sanitizer. It HTML-encodes for a text
context, splits a value across two inert parts, then wrongly interpolates their
concatenation into a quoted HTML attribute. A browser interprets an event
handler only after the join. The two individual renderings and both safe sinks
(`setAttribute`, `textContent`) remain inert. **This demonstrates
post-transformation composition plus context mismatch, not a DOMPurify bypass
and not mutation XSS.**

A task-owned, isolated Google Chrome 150 run against only this local `file:`
fixture observed `individualA=false`, `individualB=false`, `joined=true`,
`safeAttribute=false`, `safeText=false`, and a task-local execution marker
`proof=1` in the joined branch. The initial synchronous read saw `proof=0`
although the element already had an event attribute; waiting for the image
error event produced the proof. This illustrates why an HTML attribute hit
alone is not browser execution. No live target traffic was sent and no remote
scripts were loaded by the fixture. A fixture proves only its own deliberately
unsafe code.
The opt-in regression `tests/test_xss_browser_fixture.py` now asserts those
exact positive and negative outcomes against an already provisioned,
task-owned browser; it skips without an explicit private launch receipt and
does not allocate or release a browser itself. The reviewer-driven rerun passed
with that receipt, and the exact provisioner lease was released afterward.

**mXSS is different:** the same sanitized markup has one parsed tree, but after
serialization/reparse (without application rewriting it) the consumer has a
different executable tree. The historical PortSwigger/DOMPurify Chrome bypass
depended on namespaces and comment/raw-text transitions; that Chrome vector
was patched for DOMPurify 2.1. The article separately discusses a Firefox
vector found after the patch and continuing browser mutation. This is a
recognition example, not a current universal payload. Our own recent report
consumer had *no* claimed reparse, so mXSS would have been the wrong branch
there. Do not treat “two things stripped then combined” as the definition of
mXSS; that more likely describes post-check composition.

## What is deliberately excluded

- No Advanced-XSS bulk import, vendor-specific WAF success percentages,
  universal nonce-leakage claim, or copied browser API snippets of uncertain
  behavior. The source is an idea collection, not target proof.
- No new generic ResearchMap card for “try mutation XSS”: it fails the existing
  technology-specific card-admission rule. If a real library/configuration and
  narrow parser edge are observed, existing `xss-technology-research` retrieves
  relevant cards or authors one after source review. Target observations stay in
  MapStore.
- No claim that the local fixture validates DOMPurify or proves that the recent
  program runs missed a vulnerability. Tests below verify routing and one
  controlled browser mechanism; live outcomes remain with their original runs.

## Sources and verification

- Inspiration: https://github.com/Karthikdude/Advanced-XSS (HEAD recorded at
  review: `7d529fe86fe8bdef73b393db9274e427cf637182`).
- DOMPurify README (post-sanitization modification warning):
  https://github.com/cure53/DOMPurify
- Gareth Heyes, historical mXSS example and patch boundary:
  https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss
- Browser parsing and character-reference behavior:
  https://html.spec.whatwg.org/multipage/parsing.html

Focused routing tests: `python3 -m pytest -q tests/test_xss_mechanism_ideation.py`.
Optional real-browser regression: provision an isolated, task-owned Chrome
with `--url about:blank --proxy none` under the browser skill, set
`XSS_FIXTURE_CDP_LAUNCH` to its *private* launch-receipt path, run
`python3 -m pytest -q tests/test_xss_browser_fixture.py`, then release its
exact lease through the provisioner. Do not log or publish the receipt's CDP
URL. The fixture is not a live-target automation script. In the beta merge
checkout, focused checks returned 4 passed and 1 opt-in browser skip; the full
suite returned 300 passed, 1 skipped, and 2 unrelated `stack-to-program`
failures reproduced on unchanged beta. The owned offline Chrome regression
returned 5 passed before that browser was released. An independent reviewer
accepted the corrected XSS guidance and fixture; the feature-only integration
dossier was excluded from beta, and its review receipts remain in Git history.
