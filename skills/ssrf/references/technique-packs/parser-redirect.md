# Parser And Redirect

Use when URL filters, allowlists, redirect handling, hostname parsing, or IP parsing block obvious SSRF payloads.

## Checks

- Compare accepted and rejected URL shapes.
- Test parser differences only after a plain internal destination is rejected.
- Determine whether filtering happens before or after redirects are followed.
- Use `/bypass` for broader URL parser and encoding mutations.

## Mutations

- userinfo host confusion
- encoded dots or slashes
- decimal, octal, hex, and shortened IP forms
- trailing dot hostnames
- mixed scheme casing
- same-site redirect to internal destination

## Evidence Required

- Baseline allowed external URL.
- Rejected direct internal URL.
- Mutated URL that changes behavior.
- Redirect trace or callback proof.

## Stop

Stop before DNS rebinding unless Ryushe explicitly approves safe infrastructure and target scope.
