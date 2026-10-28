# Cloudflare XSS knowledge integration dossier

- **Status:** review-approved
- **Owner:** Hermes; Kanban t_dc583940; Discord thread 1565086077407068231.
- **Branch / owning ref:** feat/cloudflare-xss
- **Worktree:** task-owned bbh-cloudflare-xss worktree.
- **Base commit:** 3011f2d55e1e0f8abc953211bd273aa73c23d63d
- **Intended integration target:** beta
- **Latest immutable recovery checkpoint:** dc90f53 (implementation); later dossier-only commits retain the test/handoff receipts.
- **Feature implementation commits:** dc90f53.
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
- Broad BBH after the documented checkout-local dependency install: three failures, 380 passed, one skipped, 212 subtests passed. The identical three unrelated documentation failures reproduce on unchanged beta (373 passed, one skipped, 212 subtests); new skill adds seven passing cases. Initial safety-incident failures were missing feature-worktree .venv, not a product regression; the repository installer resolved that prerequisite. No blanket green-suite claim.
- Independent navigation/source review: approved for implementation dc90f5318da82c20479064ac60c01f2b94317d5e and the exact companion pointer/test by reviewer sa-0-b75dc737. Independently ran 22 BBH focused/adjacent tests, two companion route tests, full 55-test policy suite and lint; all passed. Six synthetic navigation cases confirmed no-block discovery, shared owner, DOM-only separation, cache/CSP counterexamples, non-XSS non-trigger and missing-feeder/product boundaries. This is content/routing approval, not live exploit or remote activation proof.
- Live exploit validation: intentionally not performed; this is knowledge/routing work.

## Blockers and deferred work

AI Policies companion pointer/test is committed locally as
baaf3695247458044942088158fe3856a56f0cbb on beta/grant-policies; its checkout
is clean. Two unrelated unpublished predecessors (06c2950 and 3481211) are
preserved. Pushing that lane would publish unrelated work; remote policy
publication awaits its owner's disposition. This is a publication boundary,
not a local activation or BBH integration blocker. Verify local symlink
activation separately and report publication state explicitly.

## Decision gates and resume

- Integration gate: accepted; focused/adjacent checks and independent semantic review passed, with the three unchanged baseline failures documented above.
- Activation gate: publish BBH beta, project the knowledge owner through the focused security profile, then load owner and all four pointers with a fresh default-profile resolver.
- Promotion gate: no stable/main promotion requested.
- Exact resume point: intentionally merge the accepted feature into clean beta,
  removing this branch-only dossier; run post-merge checks, publish BBH beta and
  verify projection/resolution. Retain the policy publication boundary above.
- Dossier is branch-local; remove it from the accepted beta merge.
