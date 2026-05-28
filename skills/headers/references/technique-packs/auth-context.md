# Auth Context Headers

Use when cookies, bearer tokens, API keys, basic auth, or duplicated auth headers may conflict.

## Checks

- Compare cookie-only, bearer-only, API-key-only, and mixed-auth requests.
- Check duplicate `Authorization` behavior only with approved test credentials.
- Check which identity wins when session and header identities disagree.
- Record account aliases and ownership for every credential used.

## Mutations

- remove `Authorization`
- remove session cookie
- send session cookie plus bearer token for a different approved account
- duplicate `Authorization` headers through proxy tooling when supported
- send malformed auth scheme with valid session cookie

## Evidence Required

- Identity expected from each credential.
- Identity observed in the response.
- Whether authorization checks use one identity while data lookup uses another.

## Stop

Stop if credentials, ownership, or account destructibility are unclear. Do not mix real-user credentials or private resources.
