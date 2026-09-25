# Browser auth site contract (inactive)

The operator supplies one private JSON file per exact `(program, auth_domain, account_alias)` pool. The manager—not an agent or browser page—selects its path and expected pool identity. Use a root- or manager-owned regular file with mode `0600` in a manager-exclusive directory (no symlinked path; no unprotected group/world-writable ancestors). The loader opens each parent directory by file descriptor and opens the file relative to the pinned parent, rejecting symlinks and unsafe modes; this prevents a parent pathname swap from redirecting the read. It **does not** isolate against a process running as the same UID that can mutate the private directory/file. The manager must keep that directory and its contents outside agent-writable storage. Do not put this file in the repository or a run artifact. The file contains selectors and an expected principal, **not** cookies, tokens, passwords, or executable code.

Disposable offline fixture example, *not* a live-site authorization:

```json
{
  "program": "fixture",
  "auth_domain": "fixture.invalid",
  "account_alias": "anon",
  "disposable_fixture": true,
  "allowed_origins": ["http://localhost:8765"],
  "check": {
    "url": "http://localhost:8765/me",
    "method": "GET",
    "principal_selector": "[data-testid=\"account-name\"]",
    "expected_principal": "anon"
  },
  "local_storage_keys": ["fixture-credential"],
  "cookie_selector": {"name": "__Host-session", "domain": "localhost", "path": "/"}
}
```

`agents.browser_auth_site_contract.load_site_contract(path, *, program, auth_domain, account_alias, origin)` returns an immutable `SiteContract` only on exact pool and allowlisted canonical origin match. Explicit default ports (`:443` for HTTPS, `:80` for HTTP) are refused rather than treated as distinct aliases; nondefault ports remain exact. HTTPS is required except `http://localhost` for precisely the disposable fixture pool above. Check URL must be on the selected origin; only GET, a restricted element selector (`#id` or `[data-testid="name"]`), and an exact nonblank expected principal are supported. `verify_check_response(contract, *, response_url, status, redirected, principal)` requires status 200, exact response URL, no redirect, and exact selected text. The future caller must itself configure **no redirect following** and extract text from exactly that element on an owned browser fixture; caller-supplied principal text alone is not evidence of a real browser check. These functions make no request and do not enable auth transfer.

The schema is closed. Missing/extra keys, wildcard domains, free-form JavaScript, alternate storage types, unselected cookies, extra cookie attributes, or a check requiring redirects are unsupported and refused rather than guessed. Cookie selection is an exact `(name, domain, path)` for the selected origin host; localStorage is an explicit list of exact keys. Production cookie hosts must be multi-label, nonnumeric DNS names and cannot be one of the bounded common two-label suffixes in the loader (for example `co.uk` or `com.au`). This is **not** a public-suffix database or proof of registrability: operator review and the actual browser state gate remain required. Before any cookie copy, inspect authoritative host-only metadata when available. CDP `Network.getAllCookies` does not expose that metadata: the only supported missing-metadata proof is a browser-enforced `__Host-` cookie with `Secure`, `Path=/`, and the exact origin hostname. Non-prefixed cookies and a `Domain`-scoped cookie fail closed even if their displayed domain looks exact; do not infer host-only from a leading dot convention. This prefix boundary is necessary, not sufficient, for future production qualification. Public `SiteContractError` text never includes raw JSON values or file paths. No real site contract is supplied by this change.

The private fixture integration reads only the manager-selected `fixture-site-contract.json` under the manager state directory, mode 0600 and outside agent-writable storage. It remains hard-fenced to `(fixture, fixture.invalid, anon)` and `http://localhost:<port>` with `__Host-session` and `fixture-credential`; no path, script, or selector is accepted from the agent. Its check uses a fixed browser-side `fetch` with `redirect: manual`, parses the returned HTML with `DOMParser`, extracts the selected element text, and requires exact URL/status/principal. It neither enables a production site nor implements peer promotion or general account transfer. The example port above illustrates schema only; the runnable canary uses a disposable ephemeral port.
