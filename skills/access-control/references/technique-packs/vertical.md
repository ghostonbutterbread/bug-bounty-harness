# Vertical Access Control

## Related Terms

- vertical privilege escalation
- function-level authorization
- admin endpoint exposure
- role confusion
- privilege escalation
- unprotected admin function

## Detection Keywords

```text
admin, moderator, support, owner, staff, role, permission, is_admin,
plan, paid, premium, billing, config, settings, impersonate, export
```

## Try

- Visit hidden admin/support routes found in JS, route manifests, docs, or source maps.
- Replay privileged endpoint as low-privileged account.
- Check role/plan/permission fields in query, body, headers, cookies, and local storage.
- Test privileged list/export/config endpoints separately from UI.
- Check whether an object owned by admin creates horizontal-to-vertical impact.

## Proof

Low-privileged user reads privileged data or performs privileged functionality.

## Stop

Action would affect real users, billing, admin settings, messages, or production state.
