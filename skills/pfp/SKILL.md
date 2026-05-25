---
name: pfp
description: "Route profile-picture, avatar, and image-profile workflows into focused upload, SSRF, XSS, IDOR, WAF, race, and storage testing lanes."
---

# Profile Picture Testing

Use for profile-picture, avatar, profile-image, account-photo, and image URL import workflows.

## Invocation

```text
/pfp <program> [goal/context]
/pfp canva profile-picture
/pfp superdrug avatar-upload
```

## Required Preflight

1. Read program scope, owned-account context, and active live-testing policy.
2. Read `$HARNESS_ROOT/prompts/pfp-playbook.md`.
3. Use `$HARNESS_ROOT/prompts/pfp-research-terms.md` only when a branch needs expansion.
4. Keep tests tied to owned accounts and owned profile/image resources.

## Workflow

1. Map the profile-picture flow: local upload, remote URL import, crop/resize, profile render locations, storage/CDN object, and update/delete behavior.
2. Run a small scout set first. Treat responses as observations.
3. Branch only where behavior supports it:
   - URL fetch/import -> `/ssrf`
   - file path or server file marker behavior -> LFI/file-upload lane
   - metadata/name/URL rendering -> `/xss`
   - object ownership or profile image IDs -> `/idor`
   - blocking/filtering/CDN behavior -> `/waf`
   - replace/delete/crop timing -> `/race`
4. Save a handoff card before deeper testing.

## Evidence

Write notes under `$HARNESS_SHARED_BASE/{program}/ghost/pfp/`.

Record:
- owned account/resource used
- upload/import endpoint and full URLs
- scout payload family, not raw secret values
- observed behavior
- child lane chosen
- policy boundary and next safe test
