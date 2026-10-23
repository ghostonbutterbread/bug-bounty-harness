# Evidence checklist for named Application Behaviors

Use this when a selected browser-backed or stateful capability needs a factual MapStore Behavior. The [MapStore owner](../SKILL.md) defines the commands, storage, and distinction from URL observations, Leads, Hypothesis Ledger, and Attempts.

- Start with a concrete URL observation of user influence and the evidenced input, transform, control, or consumer. For material stateful flows, reconcile available JavaScript/request-builder evidence, an owned-session UI transition, and the task-MITM request and follow-on calls. If one source is unavailable, record the gap rather than treating static or API-only inference as a fully mapped runtime boundary. Do not manufacture live traffic solely to complete a checklist.
- Create/update one stable named Behavior backed by the observation path. Derive locations from supporting observations; keep the body factual and distinguish observed, source-derived, and unknown edges. A failed vulnerability-class test does not retire the factual capability.
- When another URL observation enriches the same capability, link it and update the Behavior with the **complete** supporting observation list: `behavior write --observation` replaces the list, not appends it. Avoid fragmenting one capability into multiple names.
- A Lead needs a separate, bounded, unresolved security question supported by the facts. Private exploit rationale and next discriminators belong in Hypothesis Ledger; exact deliberate probes belong in Attempts. Do not promote a parser/renderer/fetcher label into a vulnerability claim.

Example body (illustrative, not a claim about a target):

```text
Behavior: Attachment processing
Kinds: upload, file-transform
Locations: <URLs derived from linked observations>
Observed: client transform attempted; original file retained on failure
Controls observed: client file-count restriction
Consumer boundary: server-side preview unknown
Evidence: <MapStore observation path>; <sanitized Attempt pointer if probed>
```

At handoff, name the concrete unobserved boundary (for example the server-side consumer, fetch destination policy, or saved-value renderer), and only mark the selected question reviewed after the relevant evidence-backed review through `/coverage`.
