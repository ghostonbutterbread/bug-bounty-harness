---
name: waf
description: Use when detecting, fingerprinting, or bypassing WAF blocks, rate limits, payload filtering, blocked probes, CDN security rules, or application firewall behavior during testing.
---
# WAF Skill

A WAF block is a question about the control and the protected consumer, not a
reason to rotate generic payloads. This skill owns the reusable bypass-research
loop across vulnerability classes; it does not prove the underlying class.

For live filtering load `waf-live-policy` and the inherited scope, rate,
challenge, and stop rules. Load `blocker-first-analysis` to locate the blocker,
`hypothesis-expansion-policy` to deepen or defer it, and `bypass` for generic
parser questions. For a plausible XSS path whose next obstacle is filtering,
load `xss-waf-evasion` after the XSS lane and `xss-payload-engineering`.

## Adaptive blocker loop

1. **Baseline:** Preserve one clean, in-scope request and the smallest
   one-variable change that reproducibly blocks. Record request representation,
   client/session, route, response signatures, and a green control for transient
   challenge windows. A bare 403, vendor banner, or changed status is not yet a
   classified WAF rule. Stop or slow as `waf-live-policy` requires.
2. **Locate the control:** Compare edge/CDN, bot/rate, origin application
   validation, sanitizer, and later browser processing. Ask which bytes the
   control inspected, which transformations it applied, and whether the
   relevant attacker-controlled source ever crossed it. Use a matched rule ID
   or logs when available; a vendor fingerprint is a lead, not a rule guarantee.
   An unknown control remains a behavior-first comparison, not a reason to
   guess a vendor trick.
3. **Retrieve narrowly:** Once the route/control is concrete, query MapStore
   `app-facts`/`dedupe` for this app's observed behavior, then ResearchMap for
   portable mechanisms matching the observed request component, parser,
   transform, or consumer. Match a vendor only when its identity and relevant
   configuration are evidenced; an unknown vendor does not exclude a generic
   mechanism card. The current surface chooses the query; old cards do not
   choose a new target. Read relevant program notes only for that question.
4. **Sufficiency gate:** Do the observations and retrieved knowledge explain a
   *plausible way past this blocker* that still matters to the downstream
   consumer? State what the control likely sees, what the origin/browser would
   see instead, the transport or configuration precondition, a negative control,
   and the predicted outcome. If yes, construct that candidate. If not, name
   the missing mechanism first: read `references/core-mechanisms.md` on demand
   (with `skill_view(name='waf', file_path='references/core-mechanisms.md')`)
   for a conditional inspection/representation/control question, then do
   bounded, fingerprint-led source research (`technology-research`; for XSS use
   `xss-technology-research`) before another family. Compare upstream docs,
   source, and relevant research with observed conditions; no local card or
   search result is not a negative target finding. When research remains thin,
   return to a distinct empirical discriminator rather than stalling or spraying.
5. **Test and learn:** Change one causal factor where feasible, keep a green
   control, and compare block → actual origin behavior → class-specific consumer
   proof. A 200/challenge change alone is not a bypass proof. If blocked,
   update the model and choose a non-equivalent mechanism; if accepted, verify
   the intended value before handing the result to the owning class lane for
   its postcondition and impact proof. Record exact
   probes via the class lane's Attempts contract and durable app facts in
   MapStore, with sanitized evidence pointers. Promote one portable, source-cited
   mechanism to ResearchMap only after its recognition signal, preconditions,
   smallest check, caveats, and review meet the existing card-admission rules.

A card is a hypothesis accelerator, not a prerequisite or an exhaustive bypass
bank. The on-demand shared reference is not a payload list or deployed-rule
claim; use it to ask a discriminating question only after the current blocker
is observed. Vendor-specific tricks belong in reviewed, condition-matched
ResearchMap cards; target outcomes belong in MapStore. For XSS-specific
candidate grammar, consumer proof, and source pointers, load `xss-waf-evasion`.

## Tool boundary: controlled comparison, not automatic retries

Use the selected vulnerability lane's approved request/proxy/browser workflow to
send a controlled comparison; record each deliberate baseline and mutation with
`attempt-recording-policy`. Read the repository-root `prompts/waf-playbook.md`
for the classification questions and evidence gates, not as a payload schedule.

`agents/bypass_harness.py` and `agents/waf_interceptor.py` are existing **batch
mutation and retry** tools, not single-candidate XSS comparators. The harness's
403 mode can fan out over headers, paths, methods, and protocol; a blocked
request can then trigger vendor and generic retries in the interceptor. Its
`--rps` setting does **not** govern every inner retry. Do **not** launch either
automatic retry path for a narrow live probe or cite `--rps` as an end-to-end
rate bound. Keep them inactive for scoped live WAF/XSS continuation until their
selection and aggregate request pacing have been reviewed and verified under
`waf-live-policy`. This documentation gate does not fix their runtime behavior
or override another class's explicitly authorized harness workflow.

For offline review of an already captured response, the interceptor's
`WAFInterceptor.fingerprint(response)` may supply a *vendor-family clue*, not a
matched rule or exploit verdict. Its `bypass_success` counter and WAF log files
reflect response-level heuristics; they are neither an Attempts replacement nor
proof of origin delivery, browser execution, or cross-user impact. The owning
class lane determines findings and reporting.
