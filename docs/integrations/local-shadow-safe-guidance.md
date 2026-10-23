# Local-shadow safe guidance integration dossier

- **Status:** feature checkpoint; independent review and integration pending
- **Owner:** Hermes BBH integration, parent card `t_7478b065`
- **Branch / owning ref:** `docs/local-shadow-safe-guidance`
- **Worktree:** `/home/ryushe/worktrees/bbh-local-shadow-safe-guidance`
- **Base commit:** `38cdff90dfbeb4926bec3f9efba07aec633b7105` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-23
- **Latest immutable recovery checkpoint:** `71360ee` (merge of fetched beta after implementation commit)
- **Feature implementation commit(s):** `355bfd0`
- **Inspiration:** profile-local shadows under `/home/ryushe/.hermes/profiles/bugfix/skills/{security,bug-bounty,autonomous-ai-agents}/`; these remain untouched. Canonical owner is the BBH `skills/` tree. Compared full file inventories and differences against fetched beta before selecting content.

## Intent and implemented contract

Migrate only unique, safe operational guidance: synthetic secret-guard acceptance/rejection regression method into `account-registry`; fixture-versus-disclosure choice into `blocker-first-analysis`; source-cited OWASP reading reference into `error-intelligence`; card retrieval checks and provenance-aware public-disclosure survey into `research-knowledge-management`; evidence-bounded coordinator pressure and account/session collision triage into `hunt-orchestration`. Route checks in `tests/test_local_shadow_guidance_routes.py` pin the owning paths and non-regression boundaries. No runtime implementation, live request, integration merge, push, shadow edit, or local archive is part of this branch.

## Source-by-source disposition / archive eligibility

- **account-registry:** unique synthetic guard-test guidance migrated. Shadow's `bounty_web` default, universal tombstone rejection, shared-loader claim, and automatic auth-policy/OTP workflow contradict current canonical implementation; rejected. **Not archive-eligible** pending owner review of all consumers and a separately verified migration.
- **blocker-first-analysis:** owned mutation fixture versus in-scope disclosure nuance migrated. Canonical continuation, prior-work, rate and optional blocker-store contracts retained; shadow's alternate store/sidecar simplification rejected. **Not archive-eligible** until canonical review and runtime projection.
- **error-intelligence:** unique OWASP citations migrated as a linked background reference; novelty and redaction admission remain canonical. **Potentially archive-eligible only after reviewed beta integration and projection verification.**
- **research-knowledge-management:** card query check and public-disclosure severity/provenance method migrated; existing canonical functionality-first reference and source-admission constraints retained. Shadow's absolute checkout paths and narrower research ladder rejected. **Not archive-eligible** until reviewed integration and exact route parity.
- **bug-goals:** no edits. Claude interactive launch, bypass-permission confirmation, tmux, and Remote Control capability URL handling belong to the Claude/Hermes operator owner, not the BBH goal router; its removal of goal-state/coverage safeguards is rejected. **Not archive-eligible**; route distinct guidance to its owning repository/task.
- **hunt-orchestration:** pressure and session-collision triage migrated with explicit evidence/lease gates. Shadow's fixed reset quota, global transport stop, and raw MapStore intermediary failure route are rejected. **Not archive-eligible** until reviewed integration and policy/projection parity.

No shadow is authorized for deletion by this branch. Archive decisions require canonical acceptance, exact runtime projection, and an owner decision about unique deferred content; this dossier is not a retirement instruction.

## Evidence and review

- Focused checks: `python3 -m pytest -q tests/test_local_shadow_guidance_routes.py tests/test_research_map.py tests/test_goal_router.py` — 34 passed (7.04s); after reconciling fetched beta, the same set plus `tests/test_js_hunt_skill.py` — 40 passed (4.86s).
- Diff: `git diff --check origin/beta...HEAD` passed after reconciliation; staged implementation diff and scoped feature diff inspected.
- OWASP citation URLs retrieved and checked read-only; no target traffic.
- Independent review: pending parent/integrator.
- Merge/ancestry evidence: `origin/beta` advanced to `49a5344` in non-overlapping `js-hunt` paths; merged into feature at `71360ee`, `git merge-base --is-ancestor origin/beta HEAD` passed. No beta merge/push authorized.

## Blockers and deferred work

- Missing: independent diff review, beta integration and runtime projection parity. Trigger: parent accepts the branch. Resume: fetch latest `origin/beta`, compare/reconcile if advanced, rerun focused tests, review and integrate under branch lifecycle. This blocks archive/activation, not branch checkpoint.
- Missing: cross-consumer tombstone/shared-loader migration. Trigger: dedicated implementation task, with synthetic fixtures against account CLI, resolver, Chromium launcher and lease helper. This blocks claims that the account shadow is wholly superseded.
- Missing: Claude/Hermes-owned launch guidance disposition. Trigger: separate owner task and its own confirmation/capability URL safety review. It is not a BBH goal-route change.

## Interruption / resume handoff

- **Owning ref:** `docs/local-shadow-safe-guidance`
- **Recovery checkpoint:** `71360ee` (later dossier-only commit is recoverable from the branch ref)
- **Implementation commit:** `355bfd0`; reconciliation merge `71360ee`
- **Exact resume point:** review diff, tests and source dispositions; do not merge or archive before parent approval.
- **Working tree:** expected clean after commit.

## Decision gates

- **Integration:** parent independent review + current beta ancestry + tests; dossier removed from integration target when accepted.
- **Activation:** exact projection and fresh consumer read-back; none claimed.
- **Promotion:** no stable promotion requested.

## Decision record

- 2026-10-23 — selected bounded canonical guidance, explicitly deferred conflicting and other-repository claims.
