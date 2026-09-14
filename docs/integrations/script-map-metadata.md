# Hermes-manager and script-maintenance boundary

- Status: accepted for beta integration; protected AGENTS alignment approved and applied.
- Owner/task: bugfix-profile delegated maintenance-boundary clarification; parent owns independent review and integration.
- Worktree: `/home/ryushe/projects/.worktrees/bbh-script-map-metadata`
- Branch: `docs/script-map-metadata`; intended target: `beta` after approval and review.
- Original base: `7fb840d8493a53d1bccfd02e5407f92d3e0d7104`.
- Fetched/reconciled base: `0d9231ec748e31541cff8c899ca0efb73cf23f4a` (`origin/beta`).
- Implementation checkpoint: `0dbd6093f571e68ab6b89e7f13aa003b77b4a18a` on `docs/script-map-metadata`; the following dossier-only commit records this SHA. Verify that final handoff-only diff separately.
- Prior reachable checkpoint: `aeed2c4822635ce90917b4bf0eecd968557cfb62`; includes reconciliation at `ee0102b5e93c2adfafc9db78ee0da7664fdfa701`.

## Clarified contract

Hermes manages repository code, skills, and policies within its authorized task;
existing scope, protected-file approval, review, and lifecycle boundaries remain.
Other agents may implement scoped scripts, maintain associated tests and native
map/index entries, and add only the script-map pointer at the bottom of the main
SKILL.md. Creating a script MUST update its map in the same change. Broader code
proposals and skill/policy seeds route to Hermes. No new implementation-agent
requirement or alternate release gate was added.

Changed SCRIPT_POLICY.md and its existing policy assertions. No runtime,
security-testing logic, script implementation, repository access machinery, or
installed/synced skill projections changed.

## Shared owner and alignment

AI Policies canonical source `/home/ryushe/projects/ai-policies`, local
`beta/grant-policies`, follows its AGENTS direct-beta convention (no task branch
or integration-lane dossier). Fetched base:
`68fbd36f0d37d74d3d1032034b7ddbde46db48dd`. Review commit:
`6b5db3361694fbc045398813818a351c47eef189` (unpushed).
It updates coding-agent-operations-policy as canonical role-boundary owner,
coding-proposal-packets-policy as narrow router, and existing policy tests.

Checked universal coding-policy, branch-lifecycle, policy-authoring and its
contributor guide, proposal router, policies/coding/agent-operations.md owner
route, AI Policies root-context/AGENTS.md entry route, and BBH root AGENTS.md.
Script Manager at published General Skills commit
`27070c1a819e9a670a79d3e4991633e7db1a5f01` already routes lifecycle to these shared
owners and placement to repository SCRIPT_POLICY.md; no duplicated manager
prose or General Skills edits needed. Its generic main-SKILL pointer permission
is narrowed to bottom-only by the maintenance owner here.

A sibling-write warning on the shared operations owner was inspected against
Git and the current file; the diff contained only this delegated change, and
previous committed work remained intact.

## Verification

Commands executed from the respective owning checkouts:

- BBH: `PYTHONPATH="$PWD" python3 -m pytest tests/test_script_policy.py -q` — 23 passed (before and after clarification).
- BBH: `PYTHONPATH="$PWD" python3 -m pytest -q --disable-warnings --maxfail=5` — collection blocked by missing `bac_checks` import in root test_catalog.py.
- BBH: `PYTHONPATH="$PWD" python3 -m pytest tests -q --disable-warnings --maxfail=5` — 136 passed, 85 subtests passed, 2 failed: stale expected Bounty Core SHA in test_runtime_dependencies.py; existing broad-goal-map-reconciliation dossier command flagged by test_skill_command_lane_safety.py.
- Baseline comparison: root test_catalog.py blob matches origin/beta exactly; the two failing tests, requirements-bounty-core.txt, and broad-goal-map-reconciliation.md have no diff against origin/beta. No claim of a separately executed full baseline suite.
- AI Policies: `python3 scripts/policy_lint.py` — passed; `python3 -m pytest -q` — 27 passed. An intermediate obsolete text assertion failed and was updated to the clarified owner/router contract; existing independent-release assertions remain.
- Both repositories: `git diff --check` passed.

## Accepted review and exact handoff

The parent successfully applied the renewed user-authorized protected AGENTS.md
alignment. The earlier denial is superseded; no protection bypass was used.
Fresh independent reviewer `sa-0-a6f70c6f` approved BBH checkpoint
`3d790d3887b2e7a419342921aab44ea84e3a4fcb` plus the intentional AGENTS diff
(SHA256 `afa4886c1aa9e3fe3567d959109a1f3c873b92d038e48649373d1ca3c6a141b5`)
against `0d9231ec748e31541cff8c899ca0efb73cf23f4a`, and AI Policies
`6b5db3361694fbc045398813818a351c47eef189` against its published base above.
Reviewer independently reproduced BBH 23 focused passes and AI Policies 27
passes plus lint/diff checks. No release blocker; extra AGENTS assertions were
optional, not a gate. Root guidance now agrees with the manager and scoped
other-agent metadata boundary, without new security authority or a new
implementation-subagent requirement.

Release successor: commit the approved AGENTS alignment with this final handoff,
merge into clean current BBH beta, remove this dossier during integration,
rerun focused checks, push only named integration refs, and read back exact
remote revisions. AI Policies uses its clean reviewed direct-beta checkout.
Verify focused authorized local/Hoster source updates and projections separately;
do not infer runtime activation from publication. Stable remains untouched.

Full BBH verification remains deferred until the missing bac_checks
dependency/layout and the two unchanged baseline failures are resolved by their
owners; rerun the full commands above when those prerequisites change.
The inherited Kanban child-context guard failure remains a tracker limitation;
no bypass or tracker success is claimed. This committed dossier is the recovery
receipt until accepted integration retires it. Preserve unrelated General Skills
work and previously approval-blocked temporary-config cleanup remnants.
