---
name: pfp
description: "Route profile-picture, avatar, and image-profile workflows into focused upload, SSRF, XSS, IDOR, WAF, race, and storage testing lanes."
---

# Profile Picture Testing

Use for profile-picture, avatar, profile-image, account-photo, and image URL import workflows.

`/pfp` is a coordinator skill. It maps the profile-picture workflow, creates a queue of focused child lanes, and runs those child agents one at a time through a shared browser/live-testing slot. Child lanes should test bounded mutation families and return evidence, not just decide from the parent scout that a branch is impossible.

## Invocation

```text
/pfp <program> [goal/context]
/pfp <program> --no-ledger [goal/context]
/pfp canva profile-picture
/pfp superdrug avatar-upload
```

## Required Preflight

1. Read program scope, owned-account context, and active live-testing policy.
2. Read `$HARNESS_ROOT/prompts/pfp-playbook.md`.
3. Read `$HARNESS_ROOT/prompts/pfp-context-pack.md` to load the focused branch map and local-note sources.
4. Use `$HARNESS_ROOT/prompts/pfp-research-terms.md` only when a branch needs expansion.
5. Default to ledger mode for prior context and durable findings. If the user says `--no-ledger`, do not read prior findings or write durable ledger/coverage state.
6. Use a scheduler gate for live/browser work: only one child lane may own Chrome/CDP/session state at a time unless Ryushe explicitly approves parallel browser instances.
7. Keep tests tied to owned accounts and owned profile/image resources.

## Workflow

1. Map the profile-picture flow: local upload, remote URL import, crop/resize, profile render locations, storage/CDN object, and update/delete behavior.
2. Build a sequential child-agent queue from observed capabilities:
   - local upload or transformed bytes -> upload/parser lane
   - URL fetch/import -> `/ssrf`
   - filename, metadata, URL, error, or render surface -> `/xss`
   - object ownership, profile image IDs, storage keys, or update/delete endpoints -> `/idor`
   - blocking/filtering/CDN behavior -> `/waf`
   - replace/delete/crop timing -> `/race`
3. Give each queued child lane a bounded test budget and the shared browser slot when needed. The child should run concrete variants/mutations, record where data reflects or changes, and hand control back.
4. Do not force a lane with no reachable precondition, but do not reject a lane only from parent intuition. Rejection needs a short observed reason.
5. Save a handoff card before each child lane runs and a result card after it returns.

## Evidence

Write notes under `$HARNESS_SHARED_BASE/{program}/ghost/pfp/`.

Record:
- owned account/resource used
- upload/import endpoint and full URLs
- scout payload family, not raw secret values
- observed behavior
- child lane chosen
- child queue order and lane status
- mutation/test families attempted
- ledger mode and ledger action
- policy boundary and next safe test
