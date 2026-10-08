# WAF core and XSS overlay consolidation

- Owner: Hermes Agent, task `t_02a8a160`.
- Source: Discord message `1557853328640184432`.
- Branch/worktree: `docs/waf-core-xss-overlay`, `/home/ryushe/worktrees/bbh-waf-core-xss-overlay`.
- Base: `origin/beta` at `134de76f99238a2302a10fe1cb115826e025f823`.
- Target: `beta` only; no `main` promotion.
- Status: independently reviewed PASS; beta merge and projection pending.
- Reviewed implementation commit: `c751c31e32ab9915e1ee98edc1d179fa66087c23`.
  A later dossier-only commit, if present, is not part of the reviewed code.

## Scope and ownership

Consolidate, do not duplicate, the existing adaptive loop. `waf` owns the universal observation → acting control → app facts/portable research → sufficiency for a plausible bypass → focused research when needed → one causal candidate with negative control → separate class proof → retained learning. A new on-demand shared reference describes conditional inspection/normalization/coverage/control mechanisms and source leads. `xss-waf-evasion` inherits that loop and adds XSS grammar, sanitizer/reparse/browser context, four proof gates, and victim-reachable delivery. `bypass` handles other generic parser/access families but routes an observed WAF obstacle to `waf`. The WAF playbook is a subordinate classification/evidence aid.

Do not change the automatic retry runner, ResearchMap schema, or live target state. Its nested retries remain unsuitable for narrow rate-bounded probes. No guaranteed vendor tricks or static payload lists. Attempts owns executed probes, MapStore target facts, ResearchMap reviewed portable mechanisms. A WAF pass is not class impact.

## Verification and integration

- Static routing/reference tests: new tests observed RED (missing shared reference
  and XSS delegation), then GREEN. Review corrections observed RED (invalid inert
  marker negative control and generic batch step), then GREEN (2 passed).
- Focused and related suite: `PYTHONPATH="$PWD" /home/ryushe/projects/bug_bounty_harness/bbh-beta-integration/.venv/bin/python -m pytest tests/test_waf_interceptor.py agents/test_xss_*.py agents/test_agent_context_routing.py agents/test_shared_skill_adoption.py -q` — 161 passed in the feature worktree; `git diff --check` clean.
- First independent read-only review: BLOCK on an inert marker misdescribed as
  a blocked negative control and a generic batch instruction applying to WAFs.
  Both corrected in shared reference and bypass playbook, with regression tests.
- Fresh independent read-only re-review: PASS for exact
  `134de76f99238a2302a10fe1cb115826e025f823..c751c31e32ab9915e1ee98edc1d179fa66087c23`;
  both blockers resolved, no new actionable findings. Reviewer reran 9 focused
  tests and checked 18 repository-path references; `git diff --check` clean.
- Beta merge and push/read-back: pending.
- Local and Hoster projection: pending.
