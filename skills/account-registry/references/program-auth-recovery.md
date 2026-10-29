# Program Auth Recovery

## Separation of authority

- Scope/testing policy: what is authorized to test. The one operational
  login document is `auth-contract.md` in that program's scope directory
  (`program-testing-policy`); load it when login is needed.
- Account-management and browser owner: current non-secret login/handoff
  instructions and inventory projection of that contract; an `auth-policy.json`
  loader is not implemented by the resolver.
- Account registry: exact owned aliases, lifecycle, capabilities, lease
  eligibility, and opaque Bitwarden/Gmail references.
- Secret systems and live browser: passwords, OTPs, magic links, cookies, and
  session state.

## Current resolver boundary

For `browser-bound` and `unknown`, the resolver returns
`needs-browser-handoff` without seed inspection, proxy refresh, or automated
login. This is a classification and handoff instruction, not proof that a
browser login, OTP step, or Tailscale Serve link was already performed.

## Recovery matrix

1. Reuse only the selected account's healthy owned browser.
2. Otherwise lease/provision its persistent profile.
3. Follow `account-management` and the approved owned-account browser login
   workflow when available; never infer login method or OTP source from a
   speculative schema.
4. Validate authentication inside the browser; do not export browser-bound state.
5. Human-only failures produce a loopback-only Tailscale Serve handoff with SSH
   fallback and `awaiting-input` lease state.

An explicit Ryushe instruction to pull from proxy can be considered only for a
`proxy-replayable` or `hybrid` session with an approved refresh source, scoped
to the exact program/account/host and retained as non-secret run provenance.
`browser-bound` and `unknown` remain browser-only even on such a request; the
resolver does not export their session material. Active tests remain on the
agent MITM lane.
