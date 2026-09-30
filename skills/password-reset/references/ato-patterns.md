# Password Reset ATO Patterns

Source inspiration: `https://github.com/wadgamaraldeen/ATO-Via-Password-Reset/blob/main/ATO-Via-Password-Reset-Test.md?plain=1`

Primary-source grounding: OWASP describes account-bound, expiring, single-use reset tokens, trusted reset URL construction, and final account binding.[1][2] Session invalidation after reset should be checked against the product's policy, not assumed to be an automatic ATO finding.[1]

These are examples to adapt to the observed application. They are not mandatory payloads and should not be used against non-owned accounts.

## Email Recipient Confusion

Goal: determine whether the reset request parser can be confused into generating a victim-bound token while delivering mail to an attacker-controlled inbox.

Examples to adapt:

```http
POST /api/v1/auth/password-reset
Content-Type: application/json

{"email":["owned-a@example.com","owned-b@example.com"]}
```

```text
email=owned-a@example.com,owned-b@example.com
email=owned-a@example.com|owned-b@example.com
email=owned-a@example.com%0aowned-b@example.com
email=owned-a@example.com%0d%0aCc:owned-b@example.com
```

Evidence to collect: which inbox receives mail, which account the token changes, whether headers are sanitized, and whether duplicate or list inputs are rejected.

## Parameter Pollution

Goal: compare duplicate parameter handling across frontend, edge, app framework, and downstream identity provider.

Examples:

```text
email=owned-a@example.com&email=owned-b@example.com
email=owned-b@example.com&email=owned-a@example.com
email=owned-a@example.com&email[]=owned-b@example.com
```

Watch for first-wins vs last-wins behavior, mismatched UI/API validation, and email delivery/account-binding disagreement.

## JSON Shape Confusion

Goal: identify whether alternate JSON shapes affect recipient or target account selection.

Examples:

```json
{"email":"owned-a@example.com","backup_email":"owned-b@example.com"}
```

```json
{"email":"owned-a@example.com","user":{"email":"owned-b@example.com"}}
```

Avoid relying on duplicate JSON keys as proof by themselves. Some parsers discard duplicates before the app sees them; only promote if the live behavior demonstrates account confusion.

## Reset Link Host Poisoning

Goal: determine whether reset links are generated from untrusted request headers instead of a configured canonical origin.

Route this lane through `/headers` and the host-routing pack.

Header families to adapt:

```text
Host
X-Forwarded-Host
Forwarded
X-Original-Host
X-Host
X-Forwarded-Proto
X-Forwarded-Port
Origin
Referer
```

Safe proof: use an owned account and an owned callback/domain. Promote only if the received reset email points to the injected host or otherwise leaks the token to attacker-controlled infrastructure.

## Token Exposure After Opening A Valid Link

This is distinct from poisoning the generated link: when an owned inbox receives a normal reset link, inspect the reset page's browser requests and redirects, its `Referrer-Policy`, and any *owned, authorized* request-log sink. Does the full token-bearing URL enter a third-party `Referer`, external redirect, or accessible log after the link is opened? Record only redacted evidence of the destination and token presence. Do not send a usable token to an unowned collector, and do not infer leakage from a third-party request lacking the token.[1][2]

Also inspect *automatic telemetry payloads* generated on page load, not only headers and redirects. One disclosed report found an unused reset token copied into analytics page-event URL/search fields before redemption, with browser identity correlation. An outbound event containing a usable owned token proves exposure, **not remote takeover**: that path additionally requires timely read access to the paired events or a downstream destination before token use/expiry. Do not inspect a third party's dashboard or disclose the raw token in evidence.[27]

## Reset Authority Retained in Browser State

After opening a valid link for an owned account, check whether a new reset-capability cookie or browser state remains usable after the link closes, on a later reset page, or after the product promises it is consumed. A disclosed case required access to the same shared browser; that is a different precondition from remote unauthenticated ATO. Read back the owned account's final password change, avoid collecting raw cookies, and state the attacker-access prerequisite explicitly.[28]

## Link/Code Purpose Confusion

When the application exposes magic login, signup confirmation, email change, and password reset in related link/code flows, identify the account, intended purpose, pending transaction, single-use state, and **resulting session** at redemption. Compare only valid artifacts from owned inboxes; opening a correct link on another device is not itself ATO. A cross-purpose or wrong-account session requires read-back proof.[1][4]

For mobile magic links, follow the URL through the app-link/deep-link handoff. A disclosed report showed an unverified Android app-link domain letting another installed app intercept an owned login token; a web redirect alone does not prove a malicious app can receive or redeem it. Use only a test device, owned app fixture, and owned account under program rules.[30]

## Token Lifecycle

Goal: verify reset tokens are account-bound, purpose-bound, single-use, short-lived, and invalidated after password change.

Checks:
- request reset twice and verify older token behavior
- redeem token once, then retry the same token
- request token for account A, attempt redemption against account B's final reset request shape
- verify token invalidation after password change
- check once whether an old unused reset link remains usable after the account's recovery/primary email changes when product policy says prior recovery authority should be retired; distinguish an old mailbox holder's lingering access from ordinary self-service use.[29]
- verify old sessions are invalidated when the product promises that behavior

Do not brute force tokens or codes.

## Final Reset IDOR

Goal: test whether the final password-change endpoint trusts user-controlled account identifiers instead of binding the token server-side.

Example shape:

```json
{
  "user_id": "owned-account-a-id",
  "token": "REDACTED_TOKEN_REFERENCE",
  "password": "REDACTED_TEST_PASSWORD"
}
```

Mutation: swap only to another owned account ID. Route through `/access-control` or `/idor` if object/account ownership becomes the main boundary.

## Race And Token Mix-Up

Goal: test whether simultaneous reset requests or redemption attempts cause token mix-up, stale-token acceptance, or double-use behavior.

Use `/race`. Keep the test to owned accounts and within the live-testing policy's race request boundary.

Good candidates:
- two reset requests for the same account at nearly the same time
- reset requests for two owned accounts sharing the same browser/session
- two redemption requests for the same token

## Referer And Origin Influence

Goal: determine whether `Referer` or `Origin` influences the generated reset target, selected account, CSRF enforcement, or redirect after reset.

Route header trust through `/headers`. Route browser-driven password reset/change CSRF through `/csrf`.

## Email Canonicalization

Goal: find account identity confusion between signup, login, reset request, and identity provider normalization.

Examples to adapt with owned addresses:
- plus addressing
- dot normalization
- `gmail.com` vs `googlemail.com`
- case changes
- leading/trailing whitespace
- Unicode or homoglyph lookalikes

Promote only if canonicalization affects the wrong account, bypasses ownership, or delivers a reset for one identity to another controlled inbox.

## Hidden Reset Endpoints

Goal: locate alternate reset surfaces that bypass modern checks.

Search terms and paths:

```text
forgot-password
password-reset
reset-password
recover
recovery
resetPwd
/api/reset-password
/api/v2/reset
/graphql
/internal/reset
/admin/reset
```

Use normal recon and URL indexing first. Do not fuzz high-volume reset endpoints without scope and rate clarity because reset flows can notify users or trigger lockouts.

## Rate Limit And Header Spoofing

Goal: determine whether reset request throttling is per account, per email, per IP, per session, or bypassable through trusted proxy headers.

Route proxy/client-IP trust through `/headers`.

Header examples:

```text
X-Forwarded-For
X-Real-IP
X-Originating-IP
Client-IP
True-Client-IP
```

Stop before lockout-prone loops, inbox flooding, or repeated reset delivery to non-owned recipients.

## Sources

[1] https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
[2] https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/04-Authentication/09-Weak_Password_Change_or_Reset_Functionalities
[4] https://cheatsheetseries.owasp.org/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.html
[27] https://hackerone.com/reports/4000185
[28] https://hackerone.com/reports/1004536
[29] https://hackerone.com/reports/685007
[30] https://hackerone.com/reports/855618
