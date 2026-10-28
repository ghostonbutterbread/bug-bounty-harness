# Cloudflare XSS knowledge integration dossier

- **Status:** feature
- **Owner:** Hermes; Kanban t_dc583940; Discord thread 1565086077407068231.
- **Branch / owning ref:** feat/cloudflare-xss
- **Worktree:** task-owned bbh-cloudflare-xss worktree.
- **Base commit:** 3011f2d55e1e0f8abc953211bd273aa73c23d63d
- **Intended integration target:** beta
- **Latest immutable recovery checkpoint:** none yet; implementation not committed.
- **Feature implementation commits:** none yet.
- **Inspiration:** user-approved single Cloudflare XSS knowledge shelf, inspired by Searchlight's Cache Me If You Can and its six introductory sources.

## Intent and implemented contract

One source-cited cloudflare-xss SKILL.md, directly discoverable from xss, waf,
xss-waf-evasion, and the companion AI Policies cloudflare-waf entry. Consultation
requires observed Cloudflare plus XSS work, not a WAF block or proven consumer.
Mechanisms retain their prerequisites, comparison ideas and historical limits;
existing XSS/policy owners retain scope, execution, evidence and impact.
No new reference tree, executable helper, target traffic or root-context edits.

Policy-alignment preflight: existing XSS lane/proof, WAF adaptive loop, shared
Cloudflare block interpretation, technology research and canonical evidence
ownership remain compatible. The new skill owns portable explanatory knowledge,
not a second target store or bypass approval rule. It includes a JavaScript Lens.

## Evidence and review

- RED: seven focused cases failed before the owner/routes existed.
- GREEN: 31 focused/adjacent tests plus seven subtests passed; AI Policies lint and all 55 tests passed.
- Broad BBH: 18 failures, 375 passed, one skipped, 202 subtests passed. Failures are outside changed paths (safety-incident CLI, stack-to-program script records/lane guidance, upload wording). Unchanged-beta reproduction is running; no blanket green-suite claim.
- Independent navigation/source review: pending.
- Live exploit validation: intentionally not performed; this is knowledge/routing work.

## Blockers and deferred work

AI Policies beta/grant-policies is clean but has two unrelated unpublished commits
(06c2950 and 3481211). Preserve them. The companion pointer/test may be committed
locally on that lane under its contributor rules, but pushing that lane would
publish unrelated work; remote policy publication awaits its owner's disposition.
Local symlink activation can be verified separately from remote publication.

## Decision gates and resume

- Integration gate: focused/adjacent checks and independent semantic review.
- Activation gate: published BBH beta plus focused security projection and fresh default-profile resolver read.
- Promotion gate: no stable/main promotion requested.
- Exact resume point: finish checks, review the source claims and independent
  no-block/DOM/cache/non-XSS navigation scenarios, then integrate only owned paths.
- Dossier is branch-local; remove it from the accepted beta merge.
