# Program Auth Recovery

## Separation of authority

- Scope/testing policy: what is authorized to test.
- Program auth policy (the selected program's resolved `auth-policy.json`): non-secret
  access mechanics.
- Account registry: exact owned aliases, lifecycle, capabilities, lease
  eligibility, and opaque Bitwarden/Gmail references.
- Secret systems and live browser: passwords, OTPs, magic links, cookies, and
  session state.

## Policy shape

```json
{
  "schema_version": 1,
  "program": "example",
  "default_session_mode": "browser-bound",
  "login": {"method": "email-otp", "login_url": "https://login.example/"},
  "recovery_order": ["existing-browser", "browser-login", "manual-handoff"]
}
```

Never put secret values in this file. `unknown` session portability fails closed.

## Recovery matrix

1. Reuse only the selected account's healthy owned browser.
2. Otherwise lease/provision its persistent profile.
3. Password/password+OTP uses the selected opaque Bitwarden reference and only
   the approved mailbox for that initiating owned login. Passwordless flow uses
   the declared mailbox likewise.
4. Validate authentication inside the browser; do not export browser-bound state.
5. Human-only failures produce a loopback-only Tailscale Serve handoff with SSH
   fallback and `awaiting-input` lease state.

An explicit Ryushe instruction to pull from proxy is a one-run exception, scoped
to exact program/account/host and retained only as non-secret provenance. It
never alters the default policy and active tests remain on the agent MITM lane.
