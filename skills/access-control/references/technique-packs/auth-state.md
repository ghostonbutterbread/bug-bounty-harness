# Auth-State Access Control

## Related Terms

- unauthenticated access
- stale session replay
- expired session access
- logout replay
- authenticated-only data exposure
- redirect body leakage

## Detection Keywords

```text
session, token, cookie, authorization, api_key, reset, invite, export,
download, attachment, invoice, report, private, account, profile
```

## Try

- Remove cookies and Authorization headers.
- Replay after logout.
- Replay with expired, stale, or partial session state.
- Check direct URLs for exports, downloads, reports, invoices, and attachments.
- Inspect 302, 401, and 403 bodies before dismissing.

## Proof

Anonymous, logged-out, expired, or stale session reads authenticated-only data or performs authenticated-only action.

## Stop

Response contains non-owned private content. Capture minimal evidence and stop.
