# MapStore Application Behavior integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `feat/mapstore-application-behavior`
- **Base commit:** `975bd6d433710567f9a447259a85271a3b54d9f9`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-04
- **Owning feature branch/ref:** `feat/mapstore-application-behavior`
- **Latest immutable recovery checkpoint:** `1aa14fbc799ee930a04d1296b10bad793c1a0896`
- **Feature implementation commit(s):** `1aa14fbc799ee930a04d1296b10bad793c1a0896`
- **Inspiration / canonical references:** Discord thread `1545529965565444126`; MapStore skill and reference.

## Intent

Add a first-class Application Behavior layer within canonical MapStore so agents can name evidence-backed, user-influenceable application capabilities (such as parsers, upload pipelines, renderers, fetchers, and transforms) and concrete URLs without presenting those records as vulnerability leads. Preserve ordinary URL observations, URL-Ingest projection, private hypotheses, and public Lead lifecycle semantics.

## Implemented contract

`agents/map_store.py behavior write` creates or updates a behavior stored under `recon/maps/_behaviors/` with a separate JSONL index. Every behavior requires a name, at least one kind, at least one concrete URL, and factual body content. `behavior query` filters by kind, URL, and tags. Ordinary `map_store.py write` accepts repeatable `--behavior` links and fails clearly when the named behavior does not exist. Behavior records do not enter `map.jsonl` or URL-Ingest projections.

## Evidence and review

- Tests and commands: focused RED/GREEN receipts in session; full focused suite pending.
- Independent review: pending after implementation and test receipt.
- Replay/cohort/fixture evidence: temporary MapStore fixture in `agents/test_map_store.py`.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- **Missing test or evidence:** full MapStore test-suite and independent review.
- **Command / fixture / environment needed:** `PYTHONPATH=<feature-worktree> <BBH base .venv>/bin/python -m pytest agents/test_map_store.py -q`.
- **Trigger to run it:** before review and commit.
- **Why it blocks integration, activation, or promotion:** prevents claiming compatibility with existing MapStore behavior.
- **Next completion step / successor reference:** run tests, review diff, resolve findings, commit, then request beta integration decision.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/mapstore-application-behavior`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** run full MapStore tests and review CLI/doc diff.
- **Working-tree state at handoff:** intentionally uncommitted (implementation underway).

## Decision gates

- **Integration gate:** focused and full MapStore tests pass; independent review has no unresolved blocking findings; explicit beta merge after clean target verification.
- **Activation / cohort gate:** no runtime activation; feature is storage/CLI capability only.
- **Promotion gate:** explicit user direction for any beta-to-main promotion.

## Decision record

- 2026-09-04 — created branch-local dossier and implemented initial behavior record API/CLI/tests.
