# Default-root BBH drafts and storage shadow audit

- **Status:** review-ready (parent review pending)
- **Owner:** Hermes BBH migration child; parent card `t_7478b065`
- **Branch / owning ref:** `docs/default-root-bbh-storage-audit`
- **Worktree:** `/home/ryushe/worktrees/bbh-default-root-bbh-storage-audit`
- **Base commit:** `c8f59045c8edbe224a72795216b87e9b5ec052a2` (`origin/beta` after fetch)
- **Intended integration target:** `beta`; no merge or push authorized for this child
- **Last updated:** 2026-10-23
- **Latest immutable recovery checkpoint:** `7eada47` (reachable on owning feature branch)
- **Feature implementation commit(s):** `7eada47`
- **Inspiration / canonical references:** three default-root trees under `~/.hermes/skills/{security/adaptive-security-testing,security/bounded-bbh-cdp-consumer-comparison,devops/bounty-storage}`; BBH `agents/index.md`, `skills/xss`, `skills/chromium-test`, `skills/bounty-storage`; shared `general-security-testing-policy`, `live-testing-policy`, `browser-session-policy`, `attempt-recording-policy`, `desktop-mobile-amplifier-policy`, and `policies/bug-bounty/bounty-storage.md`.

## Intent and boundary

Audit every file in the three default-root trees (two files, one file, and two files respectively), compare the procedures with current canonical owners, carry across only unique, safe reusable BBH mechanics. No profile-local skill edits, live target, Hoster interaction, sync, archive, beta integration, or push. The default-root files remain unmodified pending parent review and runtime projection verification.

## Disposition by source (complete file inventory)

| Source file | Decision and owner |
| --- | --- |
| `security/adaptive-security-testing/SKILL.md` | Do **not** promote a second cross-class live policy. Its permission/rate/side-effect premise is owned by shared live/security policies; progressive request testing by BBH `skills/request-exploration`, XSS `skills/xss`, `skills/form-submission-testing`, `skills/blocker-first-analysis`, and `agents/index.md` (already says signal does not gate discovery). Attempts writer and readback semantics belong to shared `attempt-recording-policy` and BBH `docs/attempt-recording-contract.md`; Coverage to `skills/coverage`. Form conditional state, state-changing postconditions, consumer-specific negatives, and blocker cards are already routed by those owners. A fixed mandate to probe every remaining sibling with markup or to log every browser action would overstate coverage and conflict with policy's deliberate-test distinction. Do not introduce an extra named skill or universal payload ladder. |
| `security/adaptive-security-testing/references/adaptive-live-exploration.md` | No unique BBH helper/contract: generic XSS/auth/SSRF probe ladders and cold-vector wording already live under class skills and shared policy. Do not transplant a generic callback sequence into BBH's SSRF lane without its own impact/scope gate. |
| `security/bounded-bbh-cdp-consumer-comparison/SKILL.md` | Do **not** promote as independent skill. Browser provisioner `about:blank`, local live-profile filesystem, MITM/CA, owner-record control, and process/profile teardown already in `skills/chromium-test`; browser-first consumers in shared `browser-session-policy`; XSS route/sink and distinct consumer proof in `skills/xss`; per-probe records in shared `attempt-recording-policy`; Coverage in `skills/coverage`. Its specific wall-clock spacing regardless of actual published aggregate rate rule is not a valid default, and same-origin Boolean side effect is not automatically safe (must use permitted owned proof and class lane). Avoid a route-cluster sweep or claiming all siblings tested from shared chrome. Lab-title/origin evidence ban is task-specific, not a reusable universal retention rule. |
| `devops/bounty-storage/SKILL.md` | Mostly byte/semantic overlap with BBH `skills/bounty-storage/SKILL.md`. Migrate only binary-bundle classification and link to symlink guidance into that BBH skill. Do not copy Shared peer handoff: transport/mode/index verification belongs to sync operations; Syncthing `receiveonly` details are backend-specific and must not be represented as the active Shared transport. No default-root link is changed. |
| `devops/bounty-storage/references/storage-layout.md` | Layout and aggregates overlap BBH's reference and shared bounty-storage policy. Carry forward a conditional, non-destructive check for existing symlinked bulk pointers and placement of non-secret desktop binary bundles in resolved mounted-artifact lane. Reject asserted blanket MEGA `-s:*` exclusion (verify configured transport), mandated top-level `/mnt/bounty/binaries/<program>/` (competes with program-first resolved layout), `rsync`/hash-then-delete relocation recipe and background `terminal` prescription (no deletion without owner decision, command environment not universal), and instruction to clear `~/Shared/.debris/` (destructive, sync ownership). Do not infer a peer received bytes from a local symlink. |

## Archive eligibility (recommendation only)

- `adaptive-security-testing/`: eligible for owner-approved archive **after** verifying the shared policies and BBH class-entry routes still resolve in a fresh intended runtime; no separate unique procedure remains to migrate. Do not retire merely because a route was named in a file.
- `bounded-bbh-cdp-consumer-comparison/`: eligible under the same route verification, with its run-specific wall-clock pacing and Boolean proof intentionally rejected rather than copied. Preserve the audit record, not the active duplicate.
- `devops/bounty-storage/`: **not yet eligible**. Only after this branch is reviewed/integrated, the canonical `bounty-storage` projection resolves without local shadowing and its linked reference loads, may the owner archive the entire old directory (including its reference). Inspect the live sync transport separately for delivery claims. Never delete or archive another profile's skills as a side effect.

## Implemented contract

BBH `skills/bounty-storage` now routes non-secret installers/unpacked desktop bundles to the resolved mounted artifact lane with a sanitized Shared pointer. Its layout reference says to inspect existing artifact-map symlinks and destination/hash before rewriting, mark stale pointers rather than replacing uncertain data, verify actual sync link semantics and peer presence independently, and preserve originals until approved cleanup. Secret-bearing artifacts remain restricted local evidence. No storage operation is performed by this documentation change.

## Evidence and review

- Tests and commands: `python3 -m unittest discover -s tests -p 'test_bounty_storage_skill_contract.py' -v` (1 pass); `python3 -m unittest discover -s tests -p 'test_skill_promotion_routes.py' -v` (7 pass); `git diff --check` (clean). These are static contract tests, not live storage/sync verification.
- Independent review: parent to review candidate diff and this disposition before integration.
- Replay/cohort/fixture evidence: not applicable; documentation-only contract test.
- Merge/ancestry evidence: re-fetched `origin/beta` at `c8f5904`; ancestor of this branch at implementation commit. No beta merge/push.

## Blockers and deferred work

- **Runtime projection/archival:** This feature branch is not published or active. Parent must review, merge to selected beta if accepted, verify sync source and fresh resolver, and only then separately decide eligibility to archive the three default-root trees; archive requires full-content decision and must not be performed by this child. Unchanged same-name default-root `bounty-storage` may still shadow canonical runtime.
- **Shared policy owner:** Do not use this BBH commit to claim that Syncthing-specific peer delivery or MEGA cleanup is shared policy. If those need general rules, owner review belongs in AI Policies / sync operations separately.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/default-root-bbh-storage-audit`
- **Latest immutable recovery checkpoint:** `7eada47` (implementation and initial dossier)
- **Feature implementation commit(s):** `7eada47`
- **Exact resume point:** parent reviews cumulative diff from `c8f5904`, runs focused tests, and decides beta integration/archival; do not infer active runtime from this branch.
- **Working-tree state at handoff:** clean after the dossier-only handoff commit.

## Decision gates

- **Integration:** parent independent review and focused checks against fetched beta; remove this temporary dossier from integration target at merge.
- **Activation:** reviewed beta source projection plus fresh runtime skill load, not this feature worktree.
- **Promotion:** no stable promotion authorized.

## Decision record

- 2026-10-23 — audited complete source trees and selected only storage symlink/binary mechanics for canonical BBH migration; all other material is duplicate, policy-owned, task-specific, or unsafe as a general rule.
- 2026-10-23 — implementation checkpoint `7eada47`; eight focused static tests passed, parent review remains.
