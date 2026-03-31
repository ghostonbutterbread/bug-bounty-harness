# WAF Testing Playbook

## Overview

Use this as a decision tree: fingerprint the blocking layer, classify what triggers the block, choose the lowest-noise bypass lane, verify whether the origin behavior becomes reachable, then report both the WAF signal and the underlying surface it protected.

## Decision Tree

1. Establish the clean baseline response first.
2. Trigger the block with the minimum request change needed.
3. Fingerprint the likely WAF from headers, body markers, or behavior.
4. If the block is rate-based, go down the pacing lane.
5. If the block is signature-based, go down the header, path, or payload lane that matches the trigger.
6. Verify whether the bypass exposed different origin behavior, then report the delta.

## 1. Fingerprint

Capture enough evidence to distinguish a WAF block from application authorization.

### Signals

- Block pages with branded markers
- Response headers such as CDN or protection headers
- Short generic bodies with `403`, `406`, `429`, `503`, or CDN error codes
- Challenge pages, cookie issuance, or JavaScript checks

## 2. Classify Trigger

Determine what actually caused the WAF to fire.

| Trigger | What To Confirm | Next Lane |
|--------|------------------|-----------|
| Request rate | Same request succeeds when slowed down | Pacing |
| Path shape | Encoded, cased, or prefixed paths behave differently | Path |
| Header profile | User agent or client-IP hints change the outcome | Header |
| Payload signature | Clean request works, payload request blocks | Payload |
| Session or cookie challenge | WAF-issued cookie changes behavior | Cookie |

## 3. Choose Lane

### Pacing Lane

Use when `429` or burst-sensitive blocking appears.

1. Reduce request rate.
2. Add delay between retries.
3. Confirm the same request reaches a different origin response when paced.

### Header Lane

Use when bot or client-profile heuristics appear relevant.

1. Rotate user agent.
2. Add only one provenance or forwarding header change at a time.
3. Record the exact header set that changed the result.

### Path Lane

Use when path normalization seems to trigger filtering.

1. Test case changes, prefixes, and minor encoding variants.
2. Keep the path semantically equivalent.
3. Confirm whether the backend path or status changes.

### Payload Lane

Use when the block appears only on injection strings or suspicious tokens.

1. Start with the clean request and the minimal triggering payload.
2. Let Tier 1 bypasses exhaust first.
3. If needed, move to Tier 2 payload obfuscation and record the exact technique that worked.

## 4. Verify

Verification means showing that the bypass reached a different origin behavior, not just a different WAF page.

### Verification Standard

1. Capture the blocked response and the bypassed response.
2. Compare:
   - status code
   - body signature
   - headers
   - redirect behavior
3. Note whether the bypass only removed the WAF page or actually exposed the protected endpoint.

### Status Rules

- `Confirmed`: a reproducible bypass reached a materially different origin response.
- `Potential`: the WAF fingerprint is clear but the post-bypass origin behavior is not yet differentiated.
- `False Positive`: the behavior was ordinary app authorization or a transient CDN error, not a WAF boundary.

## 5. Report

Write the result to:

`$HARNESS_SHARED_BASE/{program}/agent_shared/findings/waf/findings.md`

Include:

- Suspected WAF family
- Trigger type
- Bypass technique that worked or failed
- Blocked response evidence
- Post-bypass origin response evidence
- Whether the bypass materially changed downstream access
