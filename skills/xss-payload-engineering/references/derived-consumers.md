# Derived Inputs, Messages and Later Renderers

Load from `idea-tree.md` when a value arrives through a message, API, model,
stream, inherited property or later workflow. First establish an attacker-
controlled field and the exact reachable *render* consumer. `dom-xss` owns
browser-side tracing; `xss-lifecycle` owns producer-to-later-consumer lineage;
`ai-tester`/`prompt-injection` own AI instruction-following questions. A
compromised transport or model response is not automatically XSS.

| Evidence-led idea | Distinguishing check and stop boundary |
| --- | --- |
| **Prototype pollution → XSS:** a parser/merge or setter may permit a controlled property to land on a prototype, then an observed renderer may read an inherited value as HTML, template, URL or script config. Identify the pollution writer *and* the gadget consumer. | Compare a controlled inherited property with an own-property/clean-object control at that caller. No prototype write, property lookup, or executable sink → not a demonstrated XSS chain. A local `Object.prototype` assignment in attacker-run JavaScript presupposes script execution; it is not the entry vector. Keep the separate pollution primitive and XSS impact evidence linked without claiming one proves the other. |
| **`postMessage` / channels:** an owned frame or window can deliver controlled `event.data` to a handler; checks may compare `origin`, `source`, message shape and destination window. | Trace sender origin and the handler's *actual* field-to-sink path using an inert marker and a safe-text comparison. A missing origin check is not XSS if data never reaches an executable consumer; an app accepting a message from its own frame may not imply cross-origin attacker delivery. Use only scoped windows. |
| **GraphQL errors and extensions:** an error message, path, extension or alias can contain controlled query/input text that a developer console, UI toast or later report renders. | Compare network JSON and the same controlled field in a mounted UI consumer. If the error is escaped text, returned only to the attacker's own API client, or never exposed to another user, keep it a different or self-only lead. GraphQL parsing faults do not substitute for HTML proof. |
| **SSE / WebSocket events:** a real-time event may carry a stored field, topic, label or error through a client handler to a dashboard. Arrival is not rendering. | Record the owned writer, subscribed event, handler, event-to-DOM transformation and victim reachability; compare event body with text-only rendering. If only a WebSocket authentication/Origin flaw is present, route that separately (CSWSH is not XSS); if no executable sink exists, retire the XSS branch. Avoid emitting into public/staff feeds without permission. |
| **AI/model/Markdown output:** attacker-controlled prompt, document, retrieved text or metadata may influence generated text that a product inserts into Markdown/HTML or emits via a tool. Separate the model's instruction-following behavior from the *consumer's* parsing. | Establish controlled influence, output provenance, mounted consumer, HTML/URL rendering and browser result. Compare inert output in safe text and the same renderer; if the model never emits the required construct or output stays text, name the missing edge. Do not infer model-mediated XSS from prompt injection or a raw transcript alone. Route tool misuse to `ai-tester`/`indirect-injection`. |
| **Async or delayed workflow:** previews, exports, notifications, drafts, email, logs and activity feeds may transform the same stored input differently. | Reuse the original producer marker and owned fixture; check one observed downstream consumer at a time. `xss-lifecycle` owns the graph. An unavailable entitlement, absent session or unmounted panel is a prerequisite—not sanitizer success or proof of every later view. |

**Sequence for the smallest next idea:**

1. Identify controlled writer/field, transport or producer, and a legitimate
   owned recipient. If one is unknown, mark it as the missing edge.
2. Use an inert canary to verify the exact handler and mounted renderer. Record
   intermediate representation and any sanitization/decoding.
3. Ask which final grammar parses the value; pick one context-matched candidate
   plus a safe-path control. If the handler changes representation, return to
   `mechanism-ideation.md` or `parser-stage-character-variants.md`.
4. Let the selected `xss` lane perform browser proof, impact/delivery judgment,
   Attempts recording and cleanup. Target-specific facts remain MapStore or
   Hypothesis Ledger, not a reusable card.

**Provenance:** Advanced-XSS pinned commit
`7d529fe86fe8bdef73b393db9274e427cf637182` supplies topic leads only;
this reference explicitly separates transport, prompt injection and prototype
primitives from proven browser execution. Use `xss-technology-research` for a
concrete renderer/parser/card and the selected live-testing owner for scope.
