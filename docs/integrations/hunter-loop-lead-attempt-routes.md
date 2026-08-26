# Hunter Loop lead and Attempts routing

- **Status:** accepted for beta integration
- **Base / target:** `beta` at `1373cb9fe7a9da94a443541c7b69c5d387b866bf` → `beta`
- **Feature branch / worktree:** `fix/hunter-loop-lead-attempt-routes` / `/home/ryushe/worktrees/bbh-hunter-loop-routes`

## Intent

Make the parent Hunter Loop policy explicitly discover and invoke the canonical
private-candidate (`/hypothesis-ledger`), shared-lifecycle (`/leads`), and
exact-probe (`/attempt-recording-policy` + Attempts writer) paths.

## Implemented contract

- Hunter Loop and the canonical BBH storage routers distinguish bounded shared
  lead reads from private ledger ownership.
- Every viable untested angle is preserved in `/hypothesis-ledger`; an
  evidence-backed unresolved question is promoted or updated in `/leads`.
- Deliberate target-directed testing loads `/attempt-recording-policy` and
  records baseline, meaningful mutations, and outcomes through the canonical
  Attempts stream/writer.
- The matching shared AI-policy update is committed separately in the
  `ai-policies` beta lane; it extends the same transition through the universal
  entry, live-testing, hypothesis-expansion, and Attempts policies.

## Evidence

- `python3` routing-contract assertion against `skills/hunter-loop/SKILL.md`:
  passed.
- `pytest -q agents/test_attempts.py`: 7 passed.
- `git diff --check`: passed.

## Integration decision

Accepted for `beta` after routing assertions, the canonical Attempts unit test,
and diff checks passed. The change is policy/documentation only; it does not
alter traffic, scope, or storage schema. The integration cleanup removes this
dossier from `beta`; Git history retains the handoff record.

## Activation boundary

This is a policy change in the BBH `beta` source lane. It is not active on
Hoster until the reviewed beta commit is fetched into its runtime checkout and
the actual runtime skill projection is verified.

## Blockers / deferred work

- Hermes Kanban task creation was rejected because this session is classified as
a delegate child; no board card exists. The dedicated worktree and branch are
the temporary handoff identity.
- Hoster runtime was observed on the older stable checkout and uses the legacy
Hunter Memory-only attempt harvesting path. Runtime deployment and migration
are separate from this policy-routing slice.
