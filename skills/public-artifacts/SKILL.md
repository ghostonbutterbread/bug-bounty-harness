---
name: public-artifacts
description: "Track and safely reuse owned public test artifacts."
---

# Public Artifacts

Use this skill when testing requires a post, community item, profile, shareable
resource, listing, or other artifact that can be visible outside the acting
account. It records only non-secret ownership references and public artifact
pointers; it does not authorize publication or replace the public-forums policy.

## Defaults

1. **Prefer private testing.** Use a private/owned-only surface whenever it can
   answer the hypothesis.
2. **Use owned communities.** If publication is necessary, prefer the agent's
   own approved community, workspace, or audience rather than a third-party
   community.
3. **Publish only when private testing cannot answer the question.** A justified
   example is a bounded cross-user authorization check when there is no share
   link or private equivalent.
4. **Reuse one artifact.** Edit the current owned artifact for additional tests
   when that preserves the hypothesis. Create another only when the new test
   needs a distinct artifact; clean up the old one first where possible.
5. **Private first for cleanup.** Set the artifact private before cleanup when
   the platform supports it. If it cannot be made private, delete it. Verify the
   final state before recording cleanup.

## Prerequisites

- Load `general-security-testing-policy` and `live-testing-policy` before any
  live action.
- Load `public-forums` before a prominent public/community submission. It owns
  visibility classification, public-artifact leasing, content hygiene, and
  verification of public cleanup.
- For a connected social/community integration, load `social-integration-policy`
  before choosing a destination.
- Use a validated owned account. Store an approved non-secret account alias or
  email/username only; never store credentials, tokens, private bodies, or
  sensitive share links.

## Procedure

1. **Classify and minimize.** Determine whether a private owned surface exists.
   If not, identify the smallest owned-community publication that can test the
   stated behavior. Completion: the selected placement and reason private was
   insufficient are explicit.
2. **Reuse before create.** List reusable artifacts for the program:
   ```bash
   bbh agents/public_artifacts.py current --program {program}
   ```
   Edit an appropriate owned artifact instead of creating another. Completion:
   either one existing artifact is selected or the new-artifact necessity is
   recorded.
3. **Record immediately after creation or mutation.** Use the non-secret
   account reference, exact artifact URL, kind, visibility, and lifecycle event:
   ```bash
   bbh agents/public_artifacts.py record --program {program} --event created \
     --account-ref "<owned alias or approved email>" --artifact-kind "<post|listing|profile>" \
     --url "<artifact URL>" --visibility private --purpose "<bounded hypothesis>"
   ```
   Save the returned `artifact_id`; use it for every later mutation. Completion:
   the event is visible in `current` and points to the correct account/artifact.
4. **Test incrementally.** Change one meaningful field or condition at a time.
   Record `updated` or `visibility_changed` for each retained state. Do not
   batch-create variants or treat public placement as approval for active or
   viewer-affecting content.
5. **Close the artifact.** If it can be private, record the private visibility
   change before starting cleanup. Otherwise mark cleanup pending, delete, then
   verify deletion from the relevant listing and direct URL. A cleanup-pending
   artifact is terminal and cannot be reused.
   ```bash
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
   Completion: the store contains `cleanup_verified` and the public-forums
   verification record confirms the listing/direct URL result when applicable.

## Store contract

Bounty Core persists the append-only registry at:

```text
<family>/<program>/<lane>/public_artifacts/events.jsonl
```

Each event includes a generated artifact ID, non-secret `account_ref`, artifact
kind, URL/object ID, visibility, lifecycle state, purpose, cleanup method, and
optional sanitized details. The store redacts sensitive URL query values. It is
a durable ownership/cleanup pointer, not an attempt log, a public-content
archive, or authorization evidence.

## Verification

- `current` returns only artifacts that have not entered cleanup.
- Any new artifact has its account reference and URL/object ID recorded.
- Public testing used the minimum owned placement and reused an existing artifact
  when viable.
- Private-first cleanup was attempted; otherwise deletion and the visible
  absence check were recorded.
- No secret, payload body, raw request, or sensitive share link entered the
  store.
