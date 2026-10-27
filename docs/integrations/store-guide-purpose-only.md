# Store guide purpose-only correction

- Owner: Hermes; Kanban t_38ad39d7; source user message 1564728459647783073.
- Branch: docs/data-store-guidance-purpose-only; worktree: bbh-store-guide-simple.
- Base: 66ba028 (fetched beta); target: beta, not stable.
- Intent: correct overbuilt data-store-guidance to store purposes and owner pointers only.
- Implementation: 167 -> 38 lines; remove workflow, executable examples, paths, handoff/verification rules. Keep store meanings, owner references and a short same-change maintenance reminder. Existing owning skills are unchanged; excess prose is deleted, not relocated.
- Entry/card/catalog describe the reduced responsibility; AGENTS.md unchanged.
- Tests: updated purpose-only tests initially RED (3 failed, 2 passed); focused post-change run 19 passed plus 10 subtests in integration virtualenv, with installed Core pin matching requirements.
- Review: pending exact implementation checkpoint; checkpoint is the commit that introduces this dossier.
- Scope: no live traffic, store reads/migrations, Hoster or other Hermes profiles. Existing Ghost managed symlinks follow beta source after integration; fresh resolver check required.
- Next: independent narrow review, publish beta after acceptance, verify projection, close task and retire contained branch/worktree. Remove this dossier from integration tree; retain decision in branch history.
