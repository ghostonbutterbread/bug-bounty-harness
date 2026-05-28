# Baseline Fetch

Use when the target appears to fetch attacker-controlled HTTP or HTTPS URLs.

## Checks

- Send a benign controlled URL.
- Record whether the server fetches immediately, asynchronously, or after workflow completion.
- Compare reflected body, status, headers, timing, and callback evidence.
- Check whether redirects are followed only after baseline fetch is confirmed.

## Evidence Required

- Full target URL and parameter.
- Controlled destination and interaction log.
- Proof the server performed the fetch.
- Whether response data is reflected, stored, transformed, or blind.

## Stop

Stop if the feature is client-side only or the only evidence is unrelated timing noise.
