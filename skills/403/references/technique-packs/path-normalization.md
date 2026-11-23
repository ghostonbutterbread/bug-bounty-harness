# Path Normalization

Use when a `403` may result from mismatched normalization between CDN, reverse proxy, router, framework, and application authorization checks.

## Checks

Each row bets on one pair in that chain reading the path differently. Pick from
the stack you actually observed rather than running the column.

| Check | Shape, against `/admin` | Which pair it splits |
|---|---|---|
| trailing slash | `/admin/` | gate matches an exact string; the router treats both as one route |
| duplicated slash | `//admin`, `/admin//` | one hop collapses repeated separators and the other does not |
| dot segments | `/./admin`, `/admin/.`, `/x/../admin` | gate matches literally; the router resolves segments first |
| encoded slash | `/admin%2fsub` | gate decodes before matching; the router decodes after routing |
| double-encoded | `/admin%252fsub` | two decode passes with the gate between them |
| semicolon path parameters | `/admin;x=1`, `/admin;/` | gate includes the parameters in its match; the container strips them |
| suffix or prefix change | `/admin.json`, `/admin;`, `/admin.` | gate matches the exact path; the router strips an extension or suffix |
| mixed case | `/Admin`, `/ADMIN` | gate compares case-sensitively; the router or filesystem does not |

A `200` is not a bypass on its own. Confirm the body is the protected resource
rather than a login page, a generic application shell, or an error served with
`200`, and compare against the direct baseline before recording anything.

When no row produces a delta, the gate and the router are not split on the path;
the question becomes identity or method, so move to `auth-state.md` or
`trusted-headers.md` rather than lengthening this list.

## Evidence Required

- Direct protected-path baseline.
- Mutated path request.
- Response delta showing route reachability or protected behavior, not just a different error page.

## Stop

Stop if the route targets real-user data, destructive functionality, billing controls, or out-of-scope paths.
