# Stack-to-program integration dossier

- **Status:** review-ready
- **Owner:** Hermes bugfix
- **Branch / owning ref:** `feat/stack-to-program`
- **Base commit:** `ff9ebafe6f953819c65cd1e18471d74db0070ef4` (`origin/beta` fetched 2026-10-20)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-20
- **Latest immutable recovery checkpoint:** `2e8268af148af95bd7796b4f3e173bad792867b3`
- **Feature implementation commit(s):** `9c6b8b6cba9b84cbb4b107c43e2435ef6bec8058`, `2e8268af148af95bd7796b4f3e173bad792867b3`
- **Inspiration:** `~/Shared/skill_seeds/2026-10-20-stack-to-program.md`; Discord thread 1562182691246317579

## Intent

Make CVE/component-led program discovery repeatable at scale without treating public composition evidence or directory domains as authorization, deployed version, vulnerability, or current payment proof.

## Implemented contract

BBH `stack-to-program` skill with Ghostscript recipe; public-only evidence labeling and offline join CLI over evidence JSONL and dated public directory snapshot. Program Finder receives candidates for current paid/rules verification. No live target requests or scans in this phase.

## Evidence and review

- Tests and commands: `python3 -m unittest discover -s tests -p test_stack_to_program.py -v` (4 passing fixture tests after review fixes); `git diff --check`. Real public snapshot fetched from ProjectDiscovery `dist/data.json` (149894 bytes) on 2026-10-20; offline Ghostscript run over Moodle's Assignment settings docs and Nextcloud preview docs returned one `hypothesis_only` Nextcloud directory candidate and one unmatched `source-derived` Moodle row. Snapshot digest in output `6a9961ad42968d9759f3c0d09eedbff7f0c120d785815e046fc2b49e69d91a3a`. This is intentionally not a confirmed Ghostscript bounty deployment. Scratch inputs/output: `/home/ryushe/.hermes/profiles/bugfix/cache/scratch/stack-to-program-ghostscript-*` and dated `public-bugbounty-programs-20261020.json` (non-durable; rerun from public sources).
- Independent review: fresh read-only reviewer found two P2 issues (negative-only evidence promoted to candidate; missing snapshot provenance) and one P3 limitation (manual evidence harvesting). Fixed P2 with `review_only` bucket, support status, snapshot date/digest and regression test; explicitly documented P3 as first-slice limit. Independent narrow re-review passed both fixes with four tests, `git diff --check`, and saved public-data smoke; no further code findings.
- Replay/cohort/fixture evidence: exact-match, no substring/subdomain/fallback, duplicates, mixed contradiction, negative-only exclusion, snapshot digest, unpaid-status unknown and invalid-input fixtures.
- Merge/ancestry evidence: worktree based on fetched `origin/beta` SHA above.

## Blockers and deferred work

No target scan is authorized by a directory join. A production version/affected-surface assertion requires later scoped program selection and normal testing gates. Broad automated evidence harvesting/API integrations are deferred beyond this first reproducible vertical slice; add only after source contracts and coverage are verified.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/stack-to-program`
- **Latest immutable recovery checkpoint:** `2e8268af148af95bd7796b4f3e173bad792867b3`
- **Feature implementation commit(s):** `9c6b8b6cba9b84cbb4b107c43e2435ef6bec8058`, `2e8268af148af95bd7796b4f3e173bad792867b3`
- **Exact resume point:** merge reviewed feature to a clean current beta checkout, rerun focused tests, then verify selected beta activation; evidence-harvesting automation remains a separate follow-up.
- **Working-tree state at handoff:** clean after this dossier update is committed.

## Decision gates

- **Integration:** tests, real public-evidence smoke, independent review, clean current beta merge.
- **Activation:** verify selected beta skill/script resolution; no automatic rollout to other hosts.
- **Promotion:** stable only on explicit owner direction.

## Decision record

- 2026-10-20 — created feature branch and public-only boundary; skill documentation drafted.
- 2026-10-20 — independent review P2 fixes accepted on 2e8268a; first-slice manual collection remains explicitly deferred. Approved for beta integration only after current-tip reconciliation and post-merge tests; no stable promotion or host scanning.
