# Defense-chain continuation for a plausible XSS path

Load from `xss` when controlled input has a plausible executable consumer and a
filter, sanitizer, CSP, or later transformation appears to prevent execution.
This is a **continuation** of the same source-to-consumer hypothesis, not a new
vulnerability class or a requirement to try bypasses on every blocked string.
Keep the selected reflected/stored/DOM/blind lane as the proof owner.

## Locate the first observed blocker

Follow the controlled value through its real delivery path: request/DOM source →
edge or application validation → stored representation → server/client rendering
and sanitization → final DOM or other consumer → delivered CSP and browser
execution. Compare a surviving control with the blocked or rewritten candidate.
Record what was observed at each stage and which stages remain unknown. Do not
infer an edge rule from a 403, a sanitizer from a missing reflection, or CSP
protection from a string that never reached an executable context. A DOM-only
source may never cross the WAF. More than one blocker may be active; once one
boundary changes, trace the value again to locate the next one.

A useful working question is: **What does this layer see, what does the next
parser or consumer see, and where could their interpretations diverge?** Spend
research and testing effort on an evidenced transition rather than choosing a
fixed CSP → sanitizer → WAF difficulty ranking or a generic payload rotation.
A plausible path is worth deep investigation, but no defense fingerprint or
bypass candidate guarantees XSS.

## Route the observed layer

- **Sanitizer / rendering transform:** Inspect the implementation and
  configuration when shipped JavaScript or source maps expose the *actual*
  client-side path. Compare raw input, sanitizer output, insertion context, and
  post-insertion DOM; ask whether a later decoder, renderer, mutation, or
  consumer reparses it differently. Client bundle code does not prove the
  server-side policy or another view uses the same sanitizer. Use
  `xss-technology-research` for a matching mechanism and
  `xss-payload-engineering` for context-directed and exploratory candidates.
- **CSP / browser execution:** First establish that the controlled value reaches
  a browser-interpreted executable context. Read the delivered enforcing policy
  (not only a Report-Only header or static configuration), its directives,
  nonce/hash/source relationships, and any relevant Trusted Types behavior.
  Compare the blocked execution with what the actual page loads, trusts, or
  delegates to; ask whether a different permitted path or later consumer changes
  the outcome. Route context-specific candidate work to
  `xss-payload-engineering` and stack-specific research to
  `xss-technology-research`. A console violation or markup injection alone is
  not execution proof.
- **WAF / request filter:** Use `waf-live-policy` to classify block, challenge,
  rate, and edge-versus-origin effects, then `waf` and `xss-waf-evasion` for the
  measured representation/control loop. Passing the filter only advances the
  input to downstream validation, sanitization, CSP, and browser proof. Do not
  apply a WAF playbook to a DOM-only source that never crosses it.
- **Missing or changed consumer:** Use `xss-lifecycle` to follow the same value
  through storage, preview, feed, export, notification, embedded view, or
  framework re-render. A safe first render does not settle a distinct later
  renderer. Preserve the original producer and ownership/cleanup state when
  branching to a later consumer.

## Depth and evidence

Keep working on a warm/hot path while a non-equivalent mechanism, representation,
producer, or owned consumer can distinguish the next hypothesis under inherited
scope, rate, ownership, and harm rules. There is no universal payload count or
fixed time cap; also do not confuse effort with progress. When repeated probes
produce the same observation, update the layer model, consult focused research,
or test another causal transition rather than endlessly varying syntax.

For each meaningful branch, preserve the source, claimed consumer and victim
path, layer-specific baseline and negative control, exact representation before
and after the acting layer, browser result under delivered CSP, and first failed
link. The canonical `attempt-recording-policy` writer owns target probes;
`references/continuation-dimensions.md` owns non-payload exhaustion axes.
Mark a path confirmed only under the selected XSS lane's execution standard.
If proof remains blocked, keep the chain lead and its missing link explicit;
close only the *examined path* when evidence rules out the remaining source,
consumer, or parser transition, or a concrete policy stop applies.
