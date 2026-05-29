# Request-Shape Repair

Use when the server tells the agent the request shape is wrong: missing field, unsupported media type, method not allowed, invalid schema, filename/MIME mismatch, multipart boundary issue, or browser-generated header required.

## Checks

- Capture the browser's valid request for the same owned action.
- Compare method, path, query, body, `Content-Type`, `Accept`, CSRF token, and custom headers.
- Repair syntax or representation before trying security mutations.
- Route header/content-type/method behavior to `/headers`.
- For uploads, compare filename, extension, declared MIME type, multipart field names, and server-visible content type.

## Allowed Modifications

- Add a required field with owned/safe value.
- Switch `Content-Type`/`Accept` among small expected variants.
- Try a safe method matrix for read-only methods.
- Align filename, extension, and MIME type for owned upload flows.

## Evidence Required

- Original error.
- Repair applied.
- Whether the repair reached the intended action.
- Any follow-up security route.

## Stop

Stop if repair requires guessing privileged IDs, adding admin-only headers, using non-owned files/resources, or performing destructive actions without approval.
