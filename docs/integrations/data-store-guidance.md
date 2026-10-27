# Data store guidance integration dossier

- Status: approved for beta integration; default projection verification follows merge.
- Owner: Hermes / Kanban bug-bounty-harness t_745d2e3d.
- Branch: feat/data-store-guidance.
- Base: 9e0702536791c49d38e9b5cc48442dea91e613ee (fetched origin/beta).
- Intended integration target: beta, never stable.
- Inspiration: user-approved single ownership skill in Discord thread 1564454883384500364, request 1564480665683103775; preceding source/metadata review at artifacts/bounty-navigation-review-1564454883384500364/REPORT.md under the operator home.
- Latest immutable recovery checkpoint and implementation commit: 8c62a45d60f2f5f989d050f1607085e08422e394.

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
- Independent review: deleg_a10e912d approved exact checkpoint
  8c62a45d60f2f5f989d050f1607085e08422e394 with no blocking findings;
  independently reran six focused modules (23 passed, 10 subtests) and walked
  URL/feature, run/FID, cross-host missing artifact, read-only absent store,
  unauthorized peer hypothesis and new-store maintenance. All 34 local routes
  resolved. Reviewer's system interpreter used editable Core rather than the pin.
- Parent repeated all six focused modules with the integration virtualenv:
  23 passed, 10 subtests in 0.26 seconds; installed Core direct-url commit
  6c36ee88a60073e1b687ec32deeade24ffafdd4f matches requirements.txt.

## Boundaries and next step

Next: commit this decision-only receipt, publish feature, integrate reviewed
implementation into the clean current beta checkout. Retire this dossier from the
integration tree after the accepted merge. Default runtime security projection
only; other Hermes profiles and Hoster are intentionally unchanged. Verify a
fresh default resolver load and route before claiming local activation.

The broad repository suite is not claimed green; the known unrelated lane
failure is documented above and remains outside this text-guidance change.
No live target validation is needed or authorized for this ownership map.
