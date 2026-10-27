# Data store guidance integration dossier

- Status: feature; independent review pending.
- Owner: Hermes / Kanban bug-bounty-harness t_745d2e3d.
- Branch: feat/data-store-guidance.
- Base: 9e0702536791c49d38e9b5cc48442dea91e613ee (fetched origin/beta).
- Intended integration target: beta, never stable.
- Inspiration: user-approved single ownership skill in Discord thread 1564454883384500364, request 1564480665683103775; preceding source/metadata review at artifacts/bounty-navigation-review-1564454883384500364/REPORT.md under the operator home.
- Latest immutable recovery checkpoint: initial implementation commit follows this dossier; resolve branch history before resuming.

## Intent and contract

One canonical store-ownership map in skills/data-store-guidance/SKILL.md,
loaded early through agents/index.md; runtime entry and catalog link to it.
The skill teaches identity resolution, scoped selection, provenance traversal,
host-aware availability, read-only lookup and existing-owner writes/read-back.
Commands/schemas stay with domain skills; bounty-storage retains tier ownership.
No agents named, new database, automatic join, production store read/write,
migration, network testing or testing-methodology changes.

The skill carries a same-change maintenance requirement for persistent-store
additions/renames/retirements/meaning changes, including coordinated Core work.
The AGENTS.md contributor reminder was blocked by protected-file approval;
the user subsequently explicitly requested AGENTS.md stay unchanged in message
1564492453468438641. That file is excluded, not a remaining authorized edit.

## Verification evidence

- New focused ownership tests: initial RED 5 failed before implementation.
- Initial combined run: 22 passed, 10 subtests passed; two moved-route assertions
  identified and migrated to follow entry -> guidance -> owner. One lane-safety
  failure is unchanged on beta: stack-to-program/scripts/README.md:11 advertises
  a direct checkout command. Baseline reproduction: lane suite 1 failed/1 passed.
- New tests check inventory domains, local skill-route targets, early loading,
  single map, portable paths and owning-skill maintenance. Semantic routing
  requires the independent walkthrough below, not just text assertions.
- Owner alignment: bounty-storage, Coverage, MapStore, Attempts contract,
  account-registry, blockers, agent-audit, ResearchMap and entry safety/report
  rules. Existing retrieval privacy, coverage cadence and provenance retained.
- Independent review: pending exact feature checkpoint; reviewer must rerun
  focused checks and walk URL/feature, run/FID, cross-host missing artifact,
  read-only absent store, private peer hypothesis and new-store maintenance.

## Boundaries and next step

Next: finish regression checks, commit checkpoint, independent review and fix /
re-review, fetch/reconcile beta before integration. Retire this dossier from the
integration tree after the accepted merge. Default runtime security projection
only; other Hermes profiles and Hoster are intentionally unchanged. Verify a
fresh default resolver load and route before claiming local activation.

The broad repository suite is not claimed green; the known unrelated lane
failure is documented above and remains outside this text-guidance change.
No live target validation is needed or authorized for this ownership map.
