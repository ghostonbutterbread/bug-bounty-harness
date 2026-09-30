# Public HackerOne pending-session ATO premise — integration dossier

- **Status:** independent review accepted the implementation for beta; merge/push and projection pending. This is a single follow-up to the first 13-case tranche, not an exhaustive census.
- **Owner/task:** Hermes, Kanban `t_921f8fc5`.
- **Feature branch/worktree:** `docs/ato-h1-pending-session` at `/home/ryushe/projects/bug_bounty_harness/ato-h1-pending-session`.
- **Base beta / target:** `f487c0a4f7bb3d634ab0fb60f8b3a52140c0f459` → `beta` (not main).
- **Latest immutable implementation checkpoint:** `59437cafb04c3106d28ab5b76b5be7a90efb0437` (a later dossier-only handoff commit follows).
- **Implementation commit(s):** `59437cafb04c3106d28ab5b76b5be7a90efb0437`.

## Intent and source method

Add the distinct pending-session proof-binding failure reported in public HackerOne report #1245762 (https://hackerone.com/reports/1245762). The canonical report body and program summary were read in the public browser before the site's later rate wall; they described a phone-keyed session creation endpoint returning the same *not-yet-authorized* token to separate callers and the legitimate user's SMS-code verification activating both copies. The historical report was marked Resolved/Disclosed and records a successful fix retest in July 2021; the skill does **not** claim Zenly remains vulnerable. No target action was performed. Registration in the task's citation ledger returned `[40]` for that canonical URL. The first 13-case tranche and its source qualification are already active at beta `f487c0a`.

## Implemented contract and proof boundary

The root idea map now routes observed pending phone/SMS login to the factor/session reference. The reference asks whether two separate owned clients get the same pre-verification credential for the same owned phone/account and whether one valid owned SMS verification turns both into authorized sessions. It does not confuse an unprivileged pending token with a bypass, recommend OTP guessing or repeated delivery, or imply a remote exploit absent shared token and a later legitimate verification. Test only owned phone numbers/accounts and record the resulting principal on both clients. This is a conditional pattern, not a fixed checklist, and does not cap other plausible ideas.

## Evidence and review

- `sources.py render --replace-in` added the canonical `[40]` URL; non-strict `verify` passed (other global ledger IDs are intentionally used by other topical references). All 40 source IDs are uniquely mapped across topical owners. Root route, final-session proof, owned-phone stop, and no-cap assertions passed. `git diff --check` passed. Focused pytest on business-logic/security-reporting skill tests: **3 passed, 24 subtests**, but these do not validate the factual report claim; the primary-report check and focused structural assertions do.
- Independent reviewer verdict on `f487c0a..59437ca`: **Yes, no blockers.** The reviewer checked the primary body in a JavaScript-enabled browser, the historical fix caveat, pre-verification token status, subsequent SMS proof, owned-phone and final-session requirements, source `[40]`, root route, no-cap rule, diff check and focused tests. No files were changed by the reviewer.
- Current `origin/beta` advanced to unrelated Bunny changes at `fdcc015dffe356826cec44d8d278aab7901346e5`; a three-way merge-tree against that ref showed only the intended ATO changes and the branch-local dossier, with no conflicts. No Bunny file is modified by this feature.
- Pending: merge from clean current beta excluding the dossier, post-merge tests, push and runtime projection.
- Broader corpus limitation persists: public HackerOne report browsing returned Cloudflare 1015 after two research shards (8/56 readable); one Wayback snapshot fetch returned 429. Do not infer inaccessible report mechanisms from titles or claim a complete platform census. Three additional title-index shards remain untouched.

## Resume handoff

- **Branch/ref:** `docs/ato-h1-pending-session`; **base:** `f487c0a4f7bb3d634ab0fb60f8b3a52140c0f459`; **target:** `beta`.
- **Checkpoint:** implementation `59437cafb04c3106d28ab5b76b5be7a90efb0437`; verify ancestry and the later dossier-only branch tip.
- **Next:** merge/push from current clean beta excluding this branch-local dossier; verify post-merge tests and active skill projection.
