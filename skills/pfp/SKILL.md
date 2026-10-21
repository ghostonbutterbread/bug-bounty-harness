---
name: pfp
description: "Route profile-picture, avatar, and image-profile workflows into focused upload, SSRF, XSS, IDOR, WAF, race, and storage testing lanes."
---

# Profile Picture Testing

Use for owned profile-picture, avatar, banner, username, profile-image, account-photo, and image URL import workflows.

## Owned profile edits are allowed

Agents may freely edit **our own validated account's** username, display name,
banner, avatar/profile picture, and other ordinary profile fields for scoped
testing. A profile being public-facing does **not** by itself make these edits
prominent public-form submissions: no `public-forums` artifact lease or
form-spam restriction is required for ordinary owned profile edits. Repeated
owned-profile updates and upload/replace/delete tests are allowed when useful;
do not stop merely because another person could view the profile.

This permission does not extend to another user's profile, impersonation,
engagement with other users, public posts/comments, reports or help/community
forms, or actions that notify other users, enter human review, or publish a
separate artifact. Those workflows retain their respective scope, ownership,
rate, viewer-safety, and public-form boundaries. Ordinary profile visibility
and image/CDN propagation do not revoke the permission. If a profile change
also publishes a separate feed item or submits a prominent form, classify that
separate action under `public-forums` before submitting it.

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
2. Read `prompts/pfp-playbook.md`.
3. Read `prompts/pfp-context-pack.md` to load the focused branch map and local-note sources.
4. Use `prompts/pfp-research-terms.md` only when a branch needs expansion.
5. Default to ledger mode for prior context and durable findings. If the user says `--no-ledger`, do not read prior findings or write durable ledger/coverage state.
6. Use a scheduler gate for live/browser work: only one child lane may own Chrome/CDP/session state at a time unless Ryushe explicitly approves parallel browser instances.
7. Keep tests tied to owned accounts and owned profile/image resources; ordinary
   owned profile edits follow the permission above, not public-form leasing.

## Workflow

1. Map the profile-picture flow: local upload, remote URL import, crop/resize, profile render locations, storage/CDN object, and update/delete behavior.
2. Build a sequential child-agent queue from observed capabilities:
   - local upload, transformed bytes, filename/metadata, storage, or retrieval question -> `upload-surface` to trace the file lifecycle and select the concrete specialist; keep `/pfp` as the avatar coordinator, not a prerequisite for other uploads
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
