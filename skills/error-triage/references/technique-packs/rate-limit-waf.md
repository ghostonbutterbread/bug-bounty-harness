# Rate Limit Or WAF Errors

Use for `429`, CAPTCHA, Cloudflare/Turnstile, WAF blocks, bot challenges, temporary bans, and CDN security pages.

## Checks

- Identify the block page or rate-limit header.
- Record request rate, recent actions, endpoint, and account/IP state.
- Determine whether the task can safely wait, lower rate, or switch to manual handoff.
- Do not rotate IPs or evade abuse controls by default.

## Route

- WAF fingerprinting -> `/waf`
- browser challenge/CAPTCHA -> `/chromium-handoff`
- target-enforced rate limit -> back off and record
- repeated blocks -> stop

## Evidence Required

- Status and block markers.
- Rate-limit headers or WAF fingerprint.
- Last safe request before block.
- Backoff decision.

## Stop

Stop on CAPTCHA, bot challenge, account lock, IP ban, or target policy enforcement unless Ryushe explicitly approves the next step.
