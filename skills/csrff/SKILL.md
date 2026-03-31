---
name: csrf
description: Test for Cross-Site Request Forgery vulnerabilities, including missing anti-CSRF protections, weak token validation, SameSite bypass opportunities, and broken Origin or Referer enforcement
---
# CSRF Testing

Test for Cross-Site Request Forgery vulnerabilities on authenticated, state-changing functionality.

## Usage

Use this skill when the target exposes actions that change account, billing, profile, admin, or workflow state and you need to verify whether those actions can be triggered cross-site from an attacker-controlled page.

There is no dedicated `agents/csrf_hunter.py` in this repo yet. Run this workflow manually with a browser, proxy, and reproducible PoC HTML.

## Files

- **Knowledge:** `$HARNESS_SHARED_BASE/{program}/ghost/knowledge.md`
- **Notes template:** `agent_shared/templates/notes/observations.md`
- **Checklist:** `agent_shared/templates/checklist.md`

## Workflow

1. Read program knowledge first to avoid re-testing endpoints that were already covered.
2. Capture authenticated requests that change state. Prioritize `POST`, `PUT`, `PATCH`, `DELETE`, and any `GET` request that performs an action.
3. Record the protection model for each endpoint:
   - CSRF token in form field or header
   - Token rotation and session binding
   - `SameSite` cookie behavior
   - `Origin` and `Referer` validation
   - Content-Type restrictions and custom-header requirements
4. Build the simplest cross-site PoC that matches the original request:
   - Plain HTML form for form-encoded or multipart requests
   - Auto-submit form for one-click reproduction
   - Method override or alternate encodings if the endpoint accepts them
   - Cross-site navigation or top-level GET if `SameSite=Lax` may still send cookies
5. Test common failure modes:
   - No CSRF token required
   - Token accepted when omitted, stale, replayed, or copied from another session
   - Token duplicated in a cookie without server-side binding
   - Validation trusts only `Referer` or only a weak `Origin` check
   - State-changing endpoint is reachable with a simpler method or content type
   - JSON endpoint becomes reachable through content-type confusion or alternate parsers
6. Confirm impact with a safe state change in a controlled account. Capture the before/after state and the exact victim prerequisites.

## Validation Notes

- Distinguish CSRF from CORS. A blocked cross-origin read does not prevent a forged write if the browser still sends the victim's cookies.
- Treat `SameSite=Lax` as partial protection, not a blanket defense. Top-level navigations and some GET-driven workflows can still be exploitable.
- If the application requires a custom header that a normal cross-site form cannot send, document that as a mitigating control unless you find an alternate request shape that bypasses it.
- If a token is present, verify whether it is actually enforced and bound to the victim session.

## Evidence To Save

- Vulnerable endpoint and HTTP method
- Raw request and response summary
- Cookie attributes relevant to the exploit
- PoC HTML used for reproduction
- Exact victim conditions needed for exploitation
- Observed state change proving impact
