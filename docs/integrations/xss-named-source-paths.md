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

Focused isolated suite after second-review corrections: `PYTHONPATH=$PWD python3 -m pytest -q agents/test_xss_source_sites.py agents/test_xss_source_integration.py agents/test_xss_skill_clarity.py agents/test_js_analyzer.py agents/test_xss_sink_sites.py tests/test_js_hunt_skill.py` → 403 passed. `git diff --check` clean. First independent review requested removal of false ingress labels, query-anchor parity, and source-map cap visibility; corrected at `3716ca7`. Second independent review found remaining constructor-to-unrelated-getter proximity and `&&=`/`||=` hash writes mislabeled reads; these are now covered by negative tests, and incidental short receiver tokens no longer consume the scan window cap. A fresh review of the final corrected commit is required. A capped isolated broad run `PYTHONPATH=$PWD .../python3 -m pytest -q agents tests --maxfail=3` found 242 passes and three failures in AppMap/base-team reporting tests; the exact same three tests failed independently on clean `origin/beta` at `4260fe2` (baseline unrelated to this diff). An uncapped run was stopped after ~21% because it was projected to exceed its runtime guard; the rest of the broad suite remains unverified. Hoster's selected symlinks and launcher currently resolve to a clean feature-branch checkout `fd90163`, even though its sync bridge declares beta; preserve running browser agents and do not switch this checkout in place. No live target probes.

## Recovery

Implementation checkpoints: `5a2e667b5cc2378f96b2f06361181e484a0d57d8`, dossier-only `268fec3925853ed2c9b8e367f4983ed0a763fb84`, and first-review correction `3716ca7f9c701ecd84a67b0fddaf4f3393fc5be5`. The current second-review correction at branch tip supersedes those checkpoints and needs a fresh independent verdict. Verify all named ancestors and the current tip. After review, integrate from a clean, current beta worktree. Before Hoster activation, choose a separate clean beta checkout and inspect the full security-profile sync/launcher plan; preserve the existing feature checkout used by running agents. Do not promote an unreviewed code or skill snapshot. No live probes authorized by this dossier.
