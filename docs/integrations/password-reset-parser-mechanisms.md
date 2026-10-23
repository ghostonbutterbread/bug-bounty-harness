# Password-reset recipient parsing augmentation

- Task: t_281d325c; user request in Discord thread 1563045722415177810, message 1563295112342016023.
- Intent: turn existing whitespace/multiple-email payload hints into conditional mechanism teaching, preserving the umbrella ATO router and existing examples.
- Branch: docs/password-reset-parser-mechanisms.
- Worktree: /home/ryushe/worktrees/bbh-password-reset-parser-mechanisms.
- Base beta commit: a2227a206ef0189b8a113f0fd68bc5c9a2b73f05.
- Intended target: beta only; no stable/main promotion.

## Contract and ownership

`ato` remains unchanged and routes recovery to `password-reset`. That specialist and its existing ATO-pattern reference now point conditionally to packaged `references/recipient-parsing.md`. Five mechanism families explain observed signal, consumer disagreement, controlled owned-account comparison, and falsifier. All prior examples and unrelated reset lanes remain intact.

Neighbors checked: ATO router, password-reset specialist and pattern reference, shared policy-authoring, branch-lifecycle, live-testing ownership route and repository instructions. No new authorization, transport, evidence-storage owner, mandatory hunt checklist, or global discovery rule. No Twitter integration, live target testing, mail delivery, account creation, or capability claim follows from this documentation change.

Sources verified through managed safe-fetch: original GitLab January 11, 2024 CVE-2023-7028 advisory, OWASP WSTG-INJT-04, Gareth Heyes's PortSwigger email-parser research. Distinguish historical reset-recipient vulnerability from email-domain validation research; MFA qualification remains explicit.

## Verification and release gate

- Checkout dependencies installed through the repository setup entrypoint into its own .venv, including the manifest-pinned Bounty Core revision.
- Focused new contracts: 4 passed. Combined guidance/lane/script checks: 36 passed, 2 baseline failures, 10 subtests passed.
- Full tests/ suite: 343 passed, 3 failed, 1 skipped, 196 subtests passed. Unchanged base a2227a2 with the identical interpreter and its own source first: 339 passed, the same 3 failed, 1 skipped, 196 subtests passed. Failures: stack-to-program script index missing Outputs/Mutates; that index contains a checkout-direct command; upload-surface test expects obsolete wording. None are task-owned; no exclusions or unrelated fixes. Full-suite status is baseline-red, not green.
- Staged whitespace check passed. Independent read-only content/navigation review PASS on implementation 901c7c16ead0bbce0eadab45e0d1aed6762ac2b0 (deleg_9d52e75c): exact five-path diff, all existing pattern content preserved, unchanged ATO router, focused 4 passed and whitespace check independently rerun. All five semantic scenarios passed, including unauthorized reset authority versus unproved MFA bypass. No blockers; full-suite baseline comparison was parent-verified, not independently rerun.
- Documentation tests prove packaged routes, a missing-reference negative, per-mechanism teaching structure and example preservation, not exploit behavior.
- Semantic review scenarios: form newline vs literal JSON percent string; accepted array delivering separate account-bound tokens; MIME Q whitespace/domain verification vs reset authority; duplicate parameters consistently selecting one identity.
- Activation: after independent approval, merge/push beta, focused synchronizer dry-run and fresh default-profile resolver loads of ATO, password-reset, and both references. No remote host activation is claimed.
- Recovery checkpoint: implementation 901c7c16ead0bbce0eadab45e0d1aed6762ac2b0 on docs/password-reset-parser-mechanisms. The branch tip includes a later dossier-only review receipt; implementation content is unchanged. This file stays in feature history and is removed from the integration target.
- Outstanding blockers: none for this scoped documentation release. The three reproduced unrelated baseline failures remain outside this task; beta publication and default-profile activation checks are the remaining release steps.
