# Key Confusion And Weak Secret

Use when the app may confuse asymmetric and symmetric algorithms, accept a public key as an HMAC secret, or use a weak HMAC secret.

## Checks

- If an original token uses RS256, look for a public key or JWKS from owned/in-scope discovery.
- Try RS256 to HS256 only with known public key material as the HMAC secret.
- Test whitespace/key-format variants only after the base confusion hypothesis is plausible.
- For weak HS256 secrets, crack offline against the captured owned/lab token using a small approved wordlist.
- Verify a cracked secret with one low-rate signed token that changes a harmless role/scope claim.

## Evidence Required

- Mutated token verifies with confused key material or cracked weak secret.
- Authorization changes at a protected endpoint.
- Key material source and token mutation are documented without exposing secrets broadly.

## Stop

Stop if no public key or token secret is available from owned/in-scope evidence. Do not brute force live endpoints.
