# WAF Testing Playbook

**Status:** active BBH decision aid. `skills/waf/SKILL.md` owns the adaptive
loop; `waf-live-policy` and the inherited testing policies own live safety.
This playbook does not authorize a retry sweep or replace a vulnerability-class
lane. Read it from the repository root as `prompts/waf-playbook.md`.

## Classify before changing representation

1. Capture a clean, in-scope baseline, the smallest reproducibly blocked
   comparison, and a green control. Preserve the client/session, request
   representation, route, timing, status, and relevant response signatures.
2. Locate the acting control: edge/CDN rule, bot/rate/challenge, application
   validation or reject-on-match filter, sanitizer/rewriter, or browser-side
   parser. Headers and branded pages are vendor clues, not rule evidence.
3. Ask which request component and bytes that control sees, and which value
   the origin and intended consumer actually parse. A client-only source that
   never crosses the WAF needs its own XSS lane, not WAF evasion.
4. Query target-specific MapStore `app-facts`/`dedupe`, then applicable
   ResearchMap mechanisms and notes. A vendor match is conditional on evidence;
   a generic parser mechanism can fit an unknown WAF. If they do not explain
   a *plausible bypass of the current blocker*, research the precise missing
   decoder, rule, or consumer stage before choosing a new candidate.

## Choose the next discriminator, not a fixed tier

- **Time/rate/challenge:** determine whether identical controlled requests
  change with pacing/session; slow or stop on 429 or challenge escalation.
  Do not evade CAPTCHA or bot protections outside their policy.
- **Path or ingress shape:** compare one semantically equivalent representation
  only if the origin route and authorization behavior remain comparable.
- **Headers/client context:** vary only an authorized, causally justified
  field; a changed status can reflect routing, caching, auth, or challenge
  rather than filter passage.
- **Payload/decoder:** identify a representation the acting control may inspect
  differently from the origin or final consumer; state the parser stage and a
  negative control. For XSS use `xss-waf-evasion` and the selected XSS lane.

Do not exhaust generic Tier 1/Tier 2 permutations by default. In particular,
`agents/bypass_harness.py` and the interceptor have automatic nested retries
that are not all governed by `--rps`; they are **not** a bounded one-variable
probe. Use controlled requests through the owning lane until selective,
aggregate-rate-governed retries are implemented and verified. Follow
`waf-live-policy` for scope, rate, challenge, stop, and claim boundaries.
For conditional shared inspection, normalization, routing, exception, and
client/challenge questions, load the on-demand `skills/waf/references/core-mechanisms.md`
through `waf`; XSS browser/sanitizer questions stay in `xss-waf-evasion`.

## Verify and record

Keep separate observations for (1) the comparable blocked and accepted
requests, (2) the intended value/resource reaching the origin or client source,
(3) the final sink/consumer receiving it, and (4) the vulnerability-class
postcondition. A different origin response can support a *WAF-pass* conclusion
when the same relevant boundary was crossed; it is not by itself confirmed
XSS, SSRF, access, or other impact. For XSS, the parent lane requires browser or
claimed-consumer execution evidence and a distinct delivery/ownership analysis.
Name the first failed gate and any unknown, rather than calling the entire path
confirmed or closed from a status code.

Write deliberate baseline, mutation, negative control, and retest via the
owning lane's `attempt-recording-policy` writer; promote stable target facts
with sanitized evidence pointers to MapStore at observation time. Portable
source-cited mechanisms enter ResearchMap only after admission review. Verified
impact follows the owning class's Findings/report lifecycle. Interceptor logs
or `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/waf/` are legacy
artifacts, not a parallel canonical Attempts or Findings ledger.
