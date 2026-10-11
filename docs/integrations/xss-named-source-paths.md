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

Integrated source feature into task worktree at `8ca2c95` and inspected its API. Found a real handoff defect: `extract_signals()` detected named sites but `JsRecord` did not receive them, so persisted metadata/packets lost every hit. Added end-to-end regressions and repaired bundle/source-map persistence; widened bounded source rules and adjusted caps after an offline Hollister sample (`js__catalogV2.js`: 47 source hits, five distinct names, three sink hits, no caps; candidate names include config noise). Paired XSS/JS/parameter-mining guidance treats proximity and name overlap as leads only, handles name-only vs URL-shaped `params.txt`, and preserves source/sink path-specific exhaustion.

Focused isolated suite: `python3 -m pytest -q agents/test_xss_source_sites.py agents/test_xss_source_integration.py agents/test_xss_skill_clarity.py agents/test_js_analyzer.py agents/test_xss_sink_sites.py tests/test_js_hunt_skill.py` → 388 passed. `git diff --check` clean. Broad `agents tests` suite running via an absolute interpreter after an initial foreground transport timeout and background PATH mismatch; resolve its failures against unchanged beta before release. Independent review and Hoster rollout pending. No live target probes.

## Recovery

Checkpoint: pending implementation commit. Resume with `git status` in this worktree, inspect the broad-suite receipt, rerun focused tests after any fix, obtain independent review, then integrate from the clean beta worktree. Do not promote an unreviewed code or skill snapshot. No live probes authorized by this dossier.
