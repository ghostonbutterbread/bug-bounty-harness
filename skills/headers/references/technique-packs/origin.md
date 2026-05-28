# Origin And Referer Headers

Use when security decisions depend on `Origin`, `Referer`, `Sec-Fetch-*`, or browser cross-site context.

## Checks

- Compare absent `Origin`, correct origin, sibling subdomain, attacker origin, and `null`.
- Compare missing, truncated, path-confused, and mixed-scheme `Referer`.
- Check whether `Origin` and `Referer` disagree and which one wins.
- For CORS, confirm whether credentials are allowed and whether private data is exposed.

## Mutations

- `Origin: null`
- `Origin: https://trusted.example.attacker.example`
- `Origin: https://attacker.example`
- absent `Origin`
- absent `Referer`
- same host with downgraded or upgraded scheme

## Evidence Required

- Baseline response and mutated response.
- Whether cookies or auth headers were sent.
- Exact policy decision changed: CORS read, CSRF acceptance, redirect, or state change.

## Stop

Stop before state-changing CSRF proof unless the action is safe and uses an approved test account/resource.
