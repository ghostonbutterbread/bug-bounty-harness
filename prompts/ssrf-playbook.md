# SSRF Testing Playbook

## Overview

Use this as a decision tree: identify fetch sinks, classify how the server resolves and follows destinations, choose the matching target lane, verify internal reachability with the lowest-noise proof, then report the exact fetch path and impact.

See `prompts/ssrf-reference.md` for metadata targets, parser-confusion families, and header requirements.

## Decision Tree

1. Probe the input.
2. If the feature fetches arbitrary attacker-controlled URLs, start with baseline reachability.
3. If allowlists or parser checks exist, move to parser-confusion and redirect lanes.
4. If the server can reach internal hosts or metadata, verify with low-risk targets before escalating.
5. If only alternate schemes might work, test those after plain HTTP and HTTPS are understood.
6. Report the exact fetch primitive, evidence of internal reach, and any bypass needed.

## 1. Probe

Start by mapping every feature that causes the server to request a URL or network resource.

### Coverage Checklist

- URL previews and link expanders
- Webhooks and callback URLs
- File imports, feed fetchers, and image resizers
- PDF, screenshot, and document renderers
- Avatar, embed, or media proxy endpoints
- XML, template, or archive parsers that can dereference external resources

### Probe Method

1. Send a benign external URL you control or can observe.
2. Record whether the server:
   - fetches immediately
   - follows redirects
   - rewrites scheme or host
   - strips credentials, ports, or fragments
   - rejects non-HTTP schemes
3. Note whether the response gives you:
   - response body reflection
   - status or error disclosure
   - blind timing only
   - webhook side effects

## 2. Classify Fetch Behavior

Pick the lane that matches the fetch primitive.

| Behavior | What To Confirm | Next Lane |
|---------|------------------|-----------|
| Direct outbound HTTP fetch | Server can reach arbitrary hosts | Baseline |
| Hostname or IP allowlist exists | URL parser can be confused | Parser |
| Redirects are followed | Open redirect or chained destination works | Redirect |
| Cloud or container clues exist | Metadata endpoints may be reachable | Metadata |
| Non-HTTP scheme handling exists | Internal protocols may be reachable | Scheme |
| Only blind effects exist | Timing or secondary interaction proves fetch | Blind |

## 3. Choose Lane

### Baseline Lane

Use when the server clearly fetches attacker-controlled HTTP or HTTPS URLs.

1. Confirm the server makes the request.
2. Compare direct external fetches to localhost or RFC1918 targets.
3. Record whether the response body, headers, or status code leak through.

### Parser Lane

Use when host validation or allowlists appear to block obvious internal targets.

1. Compare accepted and rejected URL shapes.
2. Test userinfo, dotted, decimal, octal, mixed encoding, or rebinding variants only after a plain internal host is rejected.
3. Record exactly which parser confusion primitive changed the behavior.

### Redirect Lane

Use when the server follows redirects.

1. Confirm whether one redirect hop is allowed.
2. Chain a benign external URL to an internal destination.
3. Record whether filtering happens before or after redirects are resolved.

### Metadata Lane

Use when cloud hosting or containerized runtime clues exist.

1. Start with low-risk metadata root paths.
2. Add required headers only when the platform needs them.
3. Stop once you prove metadata reachability. Do not harvest secrets.

### Scheme Lane

Use when the fetcher supports or partially parses non-HTTP schemes.

1. Confirm whether the scheme is accepted at all.
2. Prefer low-impact internal services or local file markers as proof.
3. Record whether the application normalizes or strips the scheme before requesting.

## 4. Verify

Verification should prove internal reachability with the least invasive target.

### Verification Standard

1. Reproduce with the minimum payload needed for the selected lane.
2. Capture one of:
   - internal response body marker
   - metadata banner
   - protocol-specific banner
   - redirect trace
   - blind interaction trace
3. Record whether special headers, alternate encoding, or redirects were required.
4. Stop before secret retrieval or deep internal enumeration.

### Status Rules

- `Confirmed`: the server reached an internal or controlled target in a repeatable way.
- `Potential`: the fetch path is promising but you only have ambiguous errors or timing.
- `False Positive`: the server did not leave the allowed boundary or the destination was only client-side.

## 5. Report

Write the result to:

`$HARNESS_SHARED_BASE/{program}/agent_shared/findings/ssrf/findings.md`

Include:

- Exact sink and parameter
- Fetch type: direct, redirect-chained, parser-confusion, metadata, or alternate-scheme
- Destination class reached
- Evidence of reachability
- Any required header or bypass
- Confirmation status
- Impact boundary reached without secret extraction
