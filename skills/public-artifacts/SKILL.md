---
name: public-artifacts
description: "Track and safely reuse owned public test artifacts."
---

# Public Artifacts

Use this skill when testing requires a post, community item, profile, shareable
resource, listing, or other artifact that can be visible outside the acting
account. It records only non-secret ownership references and public artifact
pointers; it does not authorize publication or replace the public-forums policy.

**Ordinary owned-profile exception:** Editing our validated account's own
username, display name, bio, banner, avatar/profile picture, or profile
fields does not require a public-artifact registry entry or private/delete
cleanup simply because the profile is visible. These are ordinary owned-account
updates and may remain visible; restore any test payload after use. A separate
owned social post is an artifact to reuse and eventually clean, not a prominent
form merely because it is public. Reports, community/help forms, direct
broadcasts, other-user engagement, and human-review submissions retain their
specialist boundaries.

## Defaults

1. **Choose the relevant render context.** A private/owned-only surface is useful
   for initial execution checks, but public rendering of an owned social post or
   profile may be the behavior under test; do not defer it for visibility alone.
2. **Use owned communities.** If publication is necessary, prefer the agent's
   own approved community, workspace, or audience rather than a third-party
   community.
3. **Edit where you can.** Reuse owned social posts for additional hypotheses;
   a few concurrently active owned artifacts are fine when the test needs them.
   Avoid accumulating duplicate posts or a public payload dump.
4. **Clean up at the end of use.** Keep a post for later tests in the same run;
   after the final test, restore benign content, privatize, or delete it and
   verify the final state. Do not leave an active test payload or a growing set
   of posts behind.

## Prerequisites

- Load `general-security-testing-policy` and `live-testing-policy` before any
  live action.
- Load `public-forums` for report/support/help forms, community submissions,
  directly broadcast posts, or staff/moderation review. Ordinary owned social
  posts do not select it merely because they are public.
- For a connected social/community integration, load `social-integration-policy`
  before choosing a destination.
- Use a validated owned account. Store an approved non-secret account alias or
  email/username only; never store credentials, tokens, private bodies, or
  sensitive share links.

## Procedure

1. **Classify the channel.** Distinguish an owned social post/profile from a
   staff/help/community form or a direct broadcast. Choose the owned render
   surface that answers the hypothesis and note its visibility/notifications.
2. **Reuse before create.** List reusable artifacts for the program:
   ```bash
   bbh agents/public_artifacts.py current --program {program}
   ```
   Edit an appropriate owned artifact instead of creating another when viable.
3. **Record immediately after creation or mutation.** Use the non-secret
   account reference, exact artifact URL, kind, visibility, and lifecycle event:
   ```bash
   bbh agents/public_artifacts.py record --program {program} --event created \
     --account-ref "<owned alias or approved email>" --artifact-kind "<post|listing|profile>" \
     --url "<artifact URL>" --visibility public --purpose "<bounded hypothesis>"
   ```
   Use the actual visibility (`private`, `unlisted`, `community`, or `public`),
   not the example value when it differs.
   Save the returned `artifact_id`; use it for every later mutation. Completion:
   the event is visible in `current` and points to the correct account/artifact.
4. **Test incrementally.** Change one meaningful field or condition at a time.
   Record `updated` or `visibility_changed` for each retained state. Scoped XSS
   payloads on owned posts are allowed; verify with owned viewers where possible,
   avoid non-owned visitor data collection or disruptive effects, and do not
   drive real users to the post.
5. **Clean up after the final run/use.** Restore benign content, privatize, or
   delete the artifact as supported. Verify the final state from the relevant
   listing and direct URL. The current CLI's terminal cleanup events only
   support private/deleted artifacts; record `updated` and note verified benign
   restoration in the run summary if the post remains public. For a post made
   private before deletion, first record that change; the CLI requires
   `visibility_changed` → `cleanup_pending` → `deleted` → `cleanup_verified`:
   ```bash
   bbh agents/public_artifacts.py record --program {program} --event visibility_changed \
     --artifact-id {artifact-id} --account-ref "<owned alias>" \
     --artifact-kind "<kind>" --url "<artifact URL>" --visibility private
   bbh agents/public_artifacts.py record --program {program} --event cleanup_pending \
     --artifact-id {artifact-id} --account-ref "<owned alias>" \
     --artifact-kind "<kind>" --url "<artifact URL>" --visibility private
   bbh agents/public_artifacts.py record --program {program} --event deleted \
     --artifact-id {artifact-id} --account-ref "<owned alias>" \
     --artifact-kind "<kind>" --url "<artifact URL>" --visibility private
   bbh agents/public_artifacts.py record --program {program} --event cleanup_verified \
     --artifact-id {artifact-id} --account-ref "<owned alias>" \
     --artifact-kind "<kind>" --url "<artifact URL>" --visibility private --cleanup-verified
   ```
   If the platform deletes a still-public post without a private transition,
   do not falsify visibility to satisfy the CLI. Verify deletion and note the
   CLI limitation in the run summary; its registry entry remains unresolved
   until the store supports that transition. A private/deleted verified artifact
   is terminal; a benign restored public
   post remains `current` in the registry and may be reused. A pending test in
   the same run may keep a post active until that test finishes; record it.

## Store contract

Bounty Core persists the append-only registry at:

```text
<family>/<program>/<lane>/public_artifacts/events.jsonl
```

Each event includes a generated artifact ID, non-secret `account_ref`, artifact
kind, canonical URL/object ID, visibility, lifecycle state, purpose, and cleanup
method. The CLI rejects URLs with credentials, query parameters, or fragments.
The registry is a durable ownership/cleanup pointer, not an attempt log, a
public-content archive, or authorization evidence.

## Verification

- `current` returns only artifacts that have not entered cleanup.
- Any new artifact has its account reference and URL/object ID recorded.
- Public testing used an owned placement and reused existing posts when viable.
- Finished test payloads were removed; posts were restored to benign content,
  made private, or deleted and the final state verified. Pending tests are named.
- No secret, payload body, raw request, or sensitive share link entered the
  store.
