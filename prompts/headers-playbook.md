# Headers Playbook

Use this after `/headers` classifies the lane or when writing a report.

## Safety Boundary

- Follow program scope and interpreted rate limits.
- Use owned accounts and approved test resources only.
- Mutate one header family at a time.
- Do not use trusted headers to access real-user resources or bypass explicit target policy.
- Stop if WAF, bot protection, or rate limiting starts to dominate the signal.

## Method

1. Capture the baseline request and response.
2. Record method, full URL, cookies, auth state, account/resource ownership, status, body length, redirect target, and server/cache headers.
3. Remove unrelated headers when possible so the delta is attributable.
4. Apply one header family from the selected technique pack.
5. Compare against the baseline and repeat once for reproducibility.
6. Minimize the header mutation.

## Useful Comparisons

- no header vs single mutated header
- intended user vs alternate approved test user
- logged-out vs logged-in
- browser request vs raw proxy replay
- safe GET/HEAD route before any state-changing route

## Evidence Standard

Strong evidence shows a reproducible change in:

- authorization or role/tenant boundary
- internal route reached
- origin/CORS/CSRF trust decision
- upstream host or tenant selection
- parser or API representation
- method-specific access control

Weak evidence includes same body with different status, cache-only behavior, generic error changes, or public content.

## Report Fields

- full target URL
- baseline request/response
- header family and exact header mutation
- auth state and owned account/resource
- response delta and security impact
- minimized reproducible request
- cleanup performed or needed
- raw artifacts path
