# Error behavior signals

## Research basis

OWASP WSTG-ERRH-01 recommends identifying expected input points and types, then comparing focused unexpected data and edge cases. Errors can reveal internal APIs, service boundaries, versions, paths, and control weaknesses. Error Intelligence also considers success bodies and redirects; an HTTP error status is not required for an observed error.

OWASP WSTG-ERRH-02 lists malformed, empty, overlong, or non-alphanumeric input, unauthenticated access to internal pages, and bypassed workflow assumptions as ways stack traces may appear. A stack trace is useful follow-up evidence, not a vulnerability by itself.

OWASP's Error Handling Cheat Sheet recommends generic public errors and detailed server-side diagnostics. An input-specific 5xx or response differential is a signal to understand the handling path, not proof of security impact.

## Reading an error

- **Evidence:** stable differential, parser family, safe header or correlation ID, client exception, or service boundary.
- **Hypothesis input:** bounded question about control ordering, ownership, parsing, integration, or client/server divergence.
- **Insufficient alone:** one-off exception, generic edge page, or implementation disclosure without a demonstrated security consequence.

Follow the parent skill's scope, noise, redaction, and store-admission rules; these source notes do not authorize additional requests.

## Sources

- OWASP WSTG-ERRH-01: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling
- OWASP WSTG-ERRH-02: https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces
- OWASP Error Handling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
