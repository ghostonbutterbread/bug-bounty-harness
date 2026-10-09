# JS, PoC, reporting, and audit guidance integration

Status: independently reviewed and accepted for beta. Owner: Hermes. Canonical path: `docs/integrations/js-poc-report-audit.md`. Supersedes: none. Implementation commit: `97fd459c0d0c47f2ff67b7df5daa3b7445bb05ce`.

- Intent: reduce JS subagent proliferation, make triage reproduction copy-pasteable, prohibit em dashes in final authored submission prose, and clarify that Attempts are only one component of an agent-run audit.
- Source: `docs/js-poc-report-audit` in the task worktree, based on `origin/beta` at `44e209d7b5b151285efa41861173e4a5caadcf9a`; intended integration ref: `beta`.
- Contract: JS offline review uses up to three active complementary role workers; report manual replay favors curl, then browser JS for stateful same-origin steps, then Python for complex orchestration; inline proofs need no redundant file; agent audit reconciles run traces and attempts; final submission prose uses no em dash.
- Boundary: no live exploit execution or generated PoC validation in this documentation change. AI Policies owns the reusable Attempts/audit and PoC-authoring decision; this repository owns BBH routing, JS fanout, and report formatting.
- Evidence: `python3 -m pytest -q tests/test_security_reporting_skill.py agents/test_attempts.py tests/test_js_hunt_skill.py tests/test_jsluice_skill.py` passed (17 tests, 45 subtests); `git diff --check` passed. Independent review found four stale-neighbor issues and a remaining JS playbook category route; all were fixed. Final narrow independent JS re-review: PASS, with 4 JS hunt tests passing. AI Policies `python3 scripts/policy_lint.py` and `python3 -m pytest -q tests/test_policy_lint.py` passed (33 tests). No runtime activation or remote deployment is implied by the branch.
- Decision: accepted for beta, subject to clean integration and post-merge checks. Remove this temporary dossier from beta in integration; stable promotion remains separate.
