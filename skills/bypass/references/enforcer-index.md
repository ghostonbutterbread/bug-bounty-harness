# Enforcer Index

A router for bypass techniques keyed by **the layer that actually refused**,
not by vulnerability class. At the moment of a refusal an agent knows "something
rejected me"; it rarely knows which class label applies. The acting layer is
observable, so it is the usable key.

## 1. Attribute the layer first

Do not pick variations before you know what answered.
`general-security-testing-policy/references/testing-posture.md` owns
attribution; the short form is a comparison that differs in exactly one
property:

| Observation | Acting layer | Relevant family |
|---|---|---|
| foreign object refused, **nonexistent** object answers differently | authorization or query scope — the check loaded the object | §5 reference divergence |
| foreign and nonexistent refused **identically** | route/pattern matcher, before the load | §2 resource identity |
| request succeeds but the value comes back transformed | output encoder or sanitizer | §3 representation |
| rejected on shape/type before any resource lookup | input validator or allowlist | §4 shape |
| signature, challenge, or payload-dependent block | edge/WAF/CDN | `waf-live-policy` |
| response varies by an input absent from the cache key | cache key | §6 unkeyed input |

An unattributed refusal is not evidence about the application's own controls.

Also classify the refusal shape, because only one of the three needs a
representation ladder: **absence** (nothing enforces the rule — often provable
directly), **divergence** (a control enforces it but a later consumer reads the
value differently), **logic** (the enforced rule differs from the intended one).

## 2. Route / pattern matcher

The matcher and the framework router disagree about which string names the
resource. Walk resource-identity equivalences:

- **Case** — `/Admin`, `/ADMIN`, mixed. Matchers are often case-sensitive while
  the router or backing store is not.
- **Trailing and doubled separators** — `/admin/`, `/admin//`, `//admin`.
- **Dot segments** — `/x/../admin`, `/./admin`, encoded `%2e%2e%2f`,
  `..%2f`, `.%2e/`.
- **Suffix and extension** — `/admin.json`, `/admin;`, `/admin%20`,
  `/admin.`, `/admin~`, `/admin#`, `/admin?`.
- **Matrix / path parameters** — `/admin;x=1`, `/admin;/`.
- **Encoding depth** — single, double (`%252e`), overlong UTF-8, unicode
  equivalents and fullwidth forms, mixed-case escapes (`%2F` vs `%2f`).
- **Method** — a rule bound to GET/POST may not cover PUT, PATCH, DELETE,
  HEAD, OPTIONS, or an arbitrary verb.
- **Method override** — `X-HTTP-Method-Override`, `X-Method-Override`,
  `_method` as a body or query field, when the matcher reads the real verb and
  the framework honours the override.
- **Prefix trust** — a proxy-stripped prefix re-sent (`/api/api/x`), or a
  rewritten base reintroduced.

`&./` has been raised as a normalization token but we have **not** confirmed a
mechanism for it; treat it as unverified and record the result rather than
citing it as known.

## 3. Output encoder / sanitizer

The escaper and the eventual parser disagree. Build the model before inventing
a payload — you cannot design a bypass for a transform you have not
characterised. Vary one property at a time:

- **Per character** — `< > " ' & / \ ` { } ( ) ; :`, whitespace, newline, tab,
  null, unicode and fullwidth equivalents. Which are neutralised, which pass?
- **Per context** — HTML text, double- and single-quoted attribute, unquoted
  attribute, JS string, template literal, JSON, URL, CSS, SVG, `srcdoc`,
  event handler. One encoder is rarely correct for all of them.
- **Stage order** — does a decode pass run before or after the escape? One
  decode or several? Order inversion is the common defect.
- **Idempotency** — does double-encoded input survive one pass and decode
  later?
- **Allowlist vs blocklist** — a blocklist implies unlisted equivalents exist.
- **Normalisation** — case folding, NFKC, whitespace stripping, comment
  removal, and tag/attribute rebuilding can each reintroduce a neutralised
  character.

A surviving character is only interesting next to a consumer whose context
makes it executable; pair the model with the consumer rather than reporting
raw survival.

## 4. Input validator / allowlist

Rejected on shape before any resource lookup. Vary the shape, not the value:

- **Type** — string for int, array for scalar (`id[]=1`), object for string,
  `null`, boolean, nested object where a scalar is expected.
- **Cardinality** — duplicate parameters (first/last/all wins differs between
  parser and consumer), parameter pollution across query, body, and path.
- **Content type** — form vs JSON vs multipart vs XML vs text for the same
  endpoint; a validator bound to one parser may be skipped by another.
- **Charset and wrapping** — `;charset=`, boundary tricks, filename vs name,
  nested multipart.
- **Field presence** — omit an enforced field, send it empty, send it twice,
  send an unexpected sibling (mass assignment: role, owner, price, flags).
- **Length and boundary** — at, below, and above a stated limit; truncation
  that drops a suffix check.
- **Allowlist edges** — for URL and host allowlists, the authority-parsing
  differences in §7.

## 5. Authorization / query scope

The check loaded the object, so identity tricks are irrelevant — the
authorizer and the loader disagree about *which* object, or the scope is
missing from the query. Walk reference divergence:

- **Parent/child mismatch** — correct parent, foreign child; foreign parent,
  own child.
- **List vs direct fetch** — a listing endpoint filtered by tenant while the
  direct fetch is not, or the reverse.
- **Batch and bulk** — authorize the first element only; send N where element
  2 is foreign. Resolver and object-resolver batch endpoints are frequent.
- **GraphQL second path** — the same object through a different field, alias,
  fragment, or nested resolver that skips the top-level check.
- **Lifecycle and stale references** — pre-creation, soft-deleted, archived,
  expired-invite, or superseded IDs whose check was written for the live state.
- **Storage and media paths** — a signed or direct object path that bypasses
  the application check entirely.
- **Actor substitution** — the same request as a lower role, an unauthenticated
  caller, a different tenant, a service token, or an invited-but-unaccepted
  member.
- **Write vs read asymmetry** — read blocked, write permitted on the same
  object, or the reverse.

## 6. Cache key

The cache key and the response content disagree about what varies. Identify an
input that changes the response but is absent from the key, then confirm
keying before any poisoning claim. Candidates: unkeyed headers, header
casing/duplication, query-parameter order, unkeyed parameters, `Vary` gaps,
and normalisation differences between edge and origin. Treat shared-cache
impact as requiring evidence of cross-user effect under program rules.

## 7. Path / file resolver

The path checker and the resolver disagree. Beyond §2's encodings: absolute
paths, `~` expansion, null truncation, nested traversal
(`....//`), encoded separators on platforms accepting both `/` and `\`,
symlink-sensitive names, and suffix appending that a checker assumed
(`name + ".pdf"` defeated by a null or a query fragment). For URL and host
allowlists, the authority is the usual defect: userinfo (`@`), alternate
ports, trailing dot, uppercase host, IDN and unicode equivalents, decimal and
hex IP forms, IPv6 wrapping, redirect-following, and DNS names resolving to
internal space.

## 8. Deserializer / signature check

The verifier and the constructor disagree. Confirm whether integrity is
checked at all — flip one byte and compare the error. If unsigned, the format
and its gadget surface are the lead; if signed, the key, algorithm, and
header-trust handling are (see `jwt-auth` for token-specific axes). Never
exercise a destructive gadget; prove reachability and stop.

## Recording

Record a ladder as **one** payload family with the varied axis per attempt, from
a controlled vocabulary fixed when the ladder starts. Do not mint a new family
per probe — that makes the stream unauditable and hides whether the layer was
actually characterised. `hypothesis-expansion-policy/references/operating-details.md`
owns why this is coverage rather than repetition.

Before claiming a layer is bounded, state which of its classes were walked,
which were not, and why — an unwalked class is a remaining branch, not a
blocker.
