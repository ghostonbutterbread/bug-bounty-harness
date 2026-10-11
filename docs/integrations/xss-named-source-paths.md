# XSS named-source and path coverage integration

Status: in progress (branch-local handoff; remove from beta merge)
Owner: Hermes, Kanban `t_ad9aaabf`
Worktree: `/home/ryushe/projects/bug_bounty_harness/.worktrees/t_ad9aaabf`
Branch: `bug-bounty-harness/t_ad9aaabf-integrate-named-xss-source-mining-and-bi`
Base: `4260fe2e2ce16d4546575a9f22ac984aea7189a9` (`origin/beta` at task start)
Target: `beta`; Hoster beta runtime and selected XSS/JS skill projections after review.
Input: `origin/feat/xss-source-sites-20261009` at `fd90163cabce44930e1606010490c119137acb09`; seed `~/Shared/skill_seeds/2026-10-09-xss-named-source-enumeration.md`.

## Intent and contract

Keep the existing bidirectional XSS method; pair bounded JavaScript named-input discovery with sink inventory and the existing parameter corpus, without treating static proximity as a proven path or forcing a full census before a strong live lead. Record distinct ingress-to-consumer paths, actual tested names and missing links. Do not use or modify live target accounts and do not interrupt active Hoster agents.

## Evidence and release gate

Integrated source feature into task worktree at `8ca2c95` and inspected its API. Found a real handoff defect: `extract_signals()` detected named sites but `JsRecord` did not receive them, so persisted metadata/packets lost every hit. Added end-to-end regressions and repaired bundle/source-map persistence; widened bounded source rules and adjusted caps after an offline Hollister sample (`js__catalogV2.js`: 43 source hits, five distinct names, three sink hits, no caps after source-classification corrections; candidate names include config noise). Paired XSS/JS/parameter-mining guidance treats proximity and name overlap as leads only, handles name-only vs URL-shaped `params.txt`, and preserves source/sink path-specific exhaustion.

Focused isolated source/sink suite on accepted `c0f7055`: 406 passed; `git diff --check` clean. Review history: the first three independent reviews requested bounded source-classification and formatted-input fixes; a fresh fourth re-review accepted `c0f7055` without blockers. The scanner does not claim exhaustive coverage. Full `agents tests` run with the first three reproduced baseline reporting failures deselected: 2,515 passed, 31 skipped, three deselected and eight failed in 1121.37s. Two failures were task-owned guidance contracts: XSS skill lost the established sink-census `/bb-script-rules` phrase, and the new script-index verification used ambient `python3`; both were corrected with focused regressions. Five of the other six failures reproduced on clean `origin/beta` in isolated targeted runs (CDP bridge fixture, dormant/report labels, two sync-report outputs, Hoster AGENTS contract). The remaining CDP display-fallback failure occurred only in the full feature suite, not in isolated CDP tests on feature or beta; it is unresolved and must not be reported as baseline-proven. A post-correction broad run excluding known baseline-related failures is required before release; full unfiltered suite is not green. Hoster's selected symlinks and launcher currently resolve to a clean feature-branch checkout `fd90163`, even though its sync bridge declares beta; preserve running browser agents and do not switch this checkout in place. No live target probes.

## Recovery

Implementation checkpoints: `5a2e667b5cc2378f96b2f06361181e484a0d57d8`, dossier-only `268fec3925853ed2c9b8e367f4983ed0a763fb84`, first-review correction `3716ca7f9c701ecd84a67b0fddaf4f3393fc5be5`, second-review correction `20e13080195454284fabe6f54edcb34c5861338e`, and accepted code correction `c0f7055e0ad1a61c6e2cf73970c5f6bc2c11c01b`. The current guidance-contract correction and this dossier are a later branch tip; review them against the full-suite failures. Verify all named ancestors and current tip. Run the broad suite with documented baseline exclusions, then integrate from a clean, current beta worktree only if the gate is satisfied. Before Hoster activation, choose a separate clean beta checkout and inspect the full security-profile sync/launcher plan; preserve the existing feature checkout used by running agents. Do not promote an unreviewed code or skill snapshot. No live probes authorized by this dossier.
