# Program initializer full-recon integration dossier

- **Status:** feature
- **Owner:** Hermes delegated implementation
- **Branch / owning ref:** `feat/program-init-full-recon`
- **Base commit:** `95c073603582732f520c59d94d8f3b03a76dcedd` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-22
- **Latest immutable recovery checkpoint:** `c55148d42cfe8b79b4bf45805002a3fee814ec08`
- **Feature implementation commit(s):** `331caa65f21737c89604b616a22f8fb06abbe775`, `c55148d42cfe8b79b4bf45805002a3fee814ec08`
- **Inspiration / canonical references:** `scripts/program_init.py`, `agents/recon/full.py`, `skills/recon/SKILL.md`, `scripts/README.md`

## Intent

Preserve basic create-only initialization and add an opt-in full agent-facing handoff for independent collection, ordered JS→Katana endpoint extraction, API mapping, default bounded public docs, Recon Bus promotion and URL Ingest review. No target traffic or CLI subagent spawn.

## Implemented contract

`--mode basic` remains default. `--mode full` requires a platform scope source, nonempty saved scope and a web/API lane. Bounded public docs discovery is included by default; `--include-docs` remains a compatibility spelling. Full-mode platform pull rejects alternate `--shared-root` before I/O because the puller and ScopeManager use `~/Shared/scopes`; basic retains its existing custom-root behavior. Full writes a deterministic pending JSON packet to the selected lane's `recon/_meta/full-recon-handoff.json`, refreshing only changed content on rerun and reporting creation separately from refresh. Dry-run requires pre-existing saved scope and writes nothing. The owning agent follows `skills/recon/SKILL.md`: approves request-level scope and aggregate rate first; calls `delegate_task` for independent recon and JS acquisition; waits for JS receipt before Katana, then API mapping; collects bounded public docs, awaits all source receipts, promotes via Recon Bus and queues via URL Ingest. Failed/pending work holds dependencies. The packet is not a completion ledger. Recon-Ry remains owner of its stages and archive promotion; `agents/recon_full.py` remains plan-only.

## Evidence and review

- Tests: `python3 -m pytest tests/test_program_init.py tests/test_full_recon.py tests/test_recon_docs.py tests/test_recon_ry_snap_default.py -q` — 24 passed on revised tip, 2026-10-22; `git diff --check` passed. Offline basic CLI dry-run JSON returned `scope_state=skipped`, `refreshed=[]`, `dry_run=true`.
- Independent review: original review identified lack of dispatch, optional docs, custom-root mismatch and rerun receipt; fixes pending parent review. No merge or push authorized.
- Fixture: mocked pull and saved scope; deterministic rerun, docs default, pending statuses, dependency order, missing scope, dry-run no-write and created/refresh, pre-pull custom-root rejection.
- Merge/ancestry: branch created at the fetched `origin/beta` base; integration intentionally deferred.

## Blockers and deferred work

- **Missing evidence:** No live target execution, platform scope pull or subagent dispatch tested (no target or approved rate budget). Literal CLI-spawning remains unimplemented: the CLI has no approved delegated policy/aggregate-rate enforcement; only a live owning agent can call `delegate_task`.
- **Command / fixture:** authorized program and its published rules, saved scope, approved rate budget and agent ownership receipts.
- **Trigger:** separate operator-approved live campaign after beta integration and policy review.
- **Why:** prevents claiming collection or promotion from an offline handoff.
- **Next step:** parent independently reviews diff/tests and integrates into beta if accepted; on an approved named program the owning agent executes the skill workflow and verifies producer receipts. Ryushe chose conversational `init <program> fully` dispatch after basic initialization, not a standalone CLI launcher. The recon child must reuse a comparable current completed baseline rather than duplicate it; Katana's JS endpoint pass follows JS receipt.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/program-init-full-recon`
- **Latest immutable recovery checkpoint:** `c55148d42cfe8b79b4bf45805002a3fee814ec08`
- **Feature implementation commit(s):** `331caa65f21737c89604b616a22f8fb06abbe775`, `c55148d42cfe8b79b4bf45805002a3fee814ec08`
- **Exact resume point:** parent independently reviews revised tests and workflow against policy; integrate only after a separate decision.
- **Working-tree state at handoff:** clean after repair commit expected.

## Decision gates

- **Integration gate:** independent review plus focused offline tests on current beta; no merge requested here.
- **Activation / cohort gate:** no target traffic or runtime activation in this change.
- **Promotion gate:** explicit owner decision, not implied by beta integration.

## Decision record

- 2026-10-22 — repaired review findings on owning feature branch; literal CLI-spawning remains a deliberate boundary.
