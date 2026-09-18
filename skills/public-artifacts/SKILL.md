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
3. **Edit where you can.** Reuse the current owned artifact for additional
   tests instead of creating variants. Create another only when the new test
   needs a distinct artifact.
4. **Clean up as you go.** When done with an artifact, set it private (or
   delete it) and verify the final state from the listing and direct URL.
   Do not let finished artifacts accumulate across a run.

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
5. **Clean up when done.** Set the artifact private where the platform supports
   it; otherwise delete it. Verify the final state from the relevant listing
   and direct URL, then record it:
   ```bash
   bbh agents/public_artifacts.py record --program {program} --event deleted \
     --artifact-id {artifact-id} --account-ref "<owned alias>" \
     --artifact-kind "<kind>" --url "<artifact URL>" --visibility private
   bbh agents/public_artifacts.py record --program {program} --event cleanup_verified \
     --artifact-id {artifact-id} --account-ref "<owned alias>" \
     --artifact-kind "<kind>" --url "<artifact URL>" --visibility private --cleanup-verified
   ```
   A verified artifact is terminal; a later test creates a new one.
   Exception: keep the artifact active when a later planned test in the same
   run still needs it — cleanup happens when testing on it is done, and the
   reuse record names the pending test.

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
- Public testing used the minimum owned placement and reused an existing artifact
  when viable.
- Finished artifacts were made private or deleted and the visible absence was
  verified; any artifact kept active for a pending test names that test.
- No secret, payload body, raw request, or sensitive share link entered the
  store.
