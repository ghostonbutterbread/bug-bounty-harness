# Proxy Trust Headers

Use when the app trusts client IP, proxy, CDN, geography, or internal-network headers.

## Checks

- Compare normal request to private, loopback, and public test IP header values.
- Check whether admin, debug, rate-limit, or geo behavior changes.
- Compare first vs last IP in comma-separated `X-Forwarded-For`.
- Check CDN-specific headers only when the target stack plausibly uses that CDN.

## Mutations

- `X-Forwarded-For: 127.0.0.1`
- `X-Forwarded-For: 127.0.0.1, <your-observed-ip>`
- `X-Real-IP: 127.0.0.1`
- `Forwarded: for=127.0.0.1;proto=https;host=<host>`
- `True-Client-IP: 127.0.0.1`
- `CF-Connecting-IP: 127.0.0.1`

## Evidence Required

- Header value that changed behavior.
- Baseline and mutated response.
- Proof that the change affects a security decision, not just analytics or logging.

## Stop

Stop if the only path forward is bypassing a ban, rate limit, abuse control, or target policy.
