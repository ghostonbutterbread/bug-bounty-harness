# JWT Auth Context Pack

Use this as the compact branch map for `/jwt-auth`.

## Rules

- Load this after a JWT-bearing request or JWT-shaped `403` is observed.
- Decode only header and payload for routing. Treat token values, cookies, signatures, secrets, and remote documents as sensitive evidence.
- Prefer one lane at a time. Do not mix claim tampering, key injection, and path/header bypass in the same pass.
- Use owned accounts/resources. Stop on non-owned data.

## Branch Map

### Algorithm And Signature

Load when the lab/page/history mentions `alg:none`, array wrapping, no signature verification, missing signature, or signature stripping.

Reference:
- `$HARNESS_ROOT/skills/jwt-auth/references/technique-packs/algorithm-signature.md`

Lab seeds:
- `https://403.brutelogic.net/authz/jwt/none` - alg:None, Array Wrapping
- `https://403.brutelogic.net/authz/jwt/nosig` - No Signature Verification

### Claims

Load when authorization depends on `iss`, `aud`, `jti`, `sub`, `role`, `scope`, `tenant`, object IDs, expiry, replay, wildcard, null, array, or removed claim behavior.

Reference:
- `$HARNESS_ROOT/skills/jwt-auth/references/technique-packs/claims.md`

Lab seeds:
- `https://403.brutelogic.net/authz/jwt/iss` - iss Spoofing + Array Bypass
- `https://403.brutelogic.net/authz/jwt/iss-ssrf` - iss URL Injection (SSRF)
- `https://403.brutelogic.net/authz/jwt/aud` - aud Removal + Wildcard + Array Bypass
- `https://403.brutelogic.net/authz/jwt/relay` - Cross-Service Relay
- `https://403.brutelogic.net/authz/jwt/jti` - jti Removal + Null + SQL Injection
- `https://403.brutelogic.net/authz/jwt/claims` - Claim Enumeration

### Key Source

Load when JWT header or discovery uses `kid`, `jku`, `x5u`, `x5c`, `x5t`, inline `jwk`, or JWKS/certificate lookup.

Reference:
- `$HARNESS_ROOT/skills/jwt-auth/references/technique-packs/key-source.md`

Lab seeds:
- `https://403.brutelogic.net/authz/jwt/kid` - kid Path Traversal + URL Injection
- `https://403.brutelogic.net/authz/jwt/jku` - jku Injection
- `https://403.brutelogic.net/authz/jwt/x5u` - x5u Injection
- `https://403.brutelogic.net/authz/jwt/x5c` - x5c Injection
- `https://403.brutelogic.net/authz/jwt/x5t` - x5t + x5c Combined
- `https://403.brutelogic.net/authz/jwt/jwk` - jwk Injection + No-alg Confusion

### Key Confusion And Weak Secret

Load when RS256/HS256 confusion, public-key-as-HMAC-secret, weak HMAC secret, JWKS public key reuse, or whitespace bypass is plausible.

Reference:
- `$HARNESS_ROOT/skills/jwt-auth/references/technique-packs/key-confusion-weak-secret.md`

Lab seeds:
- `https://403.brutelogic.net/authz/jwt/confusion` - RS256->HS256 + Whitespace Bypass
- `https://403.brutelogic.net/authz/jwt/weak` - Weak Secret

### Format Confusion

Load when parser behavior matters: duplicate claims, extra dots, JSON arrays, base64 padding, whitespace, nested JWTs, JWE accepted as JWS, or sign/encrypt confusion.

Reference:
- `$HARNESS_ROOT/skills/jwt-auth/references/technique-packs/format-confusion.md`

Lab seeds:
- `https://403.brutelogic.net/authz/jwt/format` - JWT Format Confusion
- `https://403.brutelogic.net/authz/jwt/jwe` - Sign/Encrypt Confusion
