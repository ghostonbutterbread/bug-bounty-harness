# Browser run-end leak, swap admission and exact-run release integration dossier

- **Status:** review-ready
- **Owner:** Hermes (default profile) subagent, delegated by the parent integrator
- **Branch:** `fix/browser-leak-swap-admission`
- **Worktree:** `/home/ryushe/worktrees/bbh-fix-browser-leak-swap`
- **Base commit:** `3f72ed81247d0eacb9b7d1e859c57a5ce20a4a2d` (fetched `origin/beta`, 2026-11-24)
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-24
- **Owning feature branch/ref:** `fix/browser-leak-swap-admission`
- **Latest immutable recovery checkpoint:** `d4b7d1d50c01acb7cc11f46a5497a24682d5612e`
- **Feature implementation commit(s):** `d4b7d1d50c01acb7cc11f46a5497a24682d5612e`
  (the branch tip adds a later dossier-only handoff commit)
- **Inspiration / canonical references:** papercuts PC-20260901-181544-9b2b73ff,
  PC-20260918-222033-c990c35b, PC-20261020-021756-adc41ee2; Kanban t_297ebf3e and
  children (t_a465b37a, t_f9938cf9, t_414d3d60, t_b3dda7dc, t_3ca526e0); prior beta
  work fd095a5 (exact-owner stop fence), 727961e6 (manual swap-threshold retry
  guidance), b21630dd/af4ee9cc (orphan startup recovery, lifecycle merge),
  59a525e0 (keep Chrome inside its unit by masking the session bus).

## Intent

Stop *new* browser leaks at their root, make swap exhaustion with healthy RAM
admit without an agent-side workaround, and give run owners a supported,
exact-identity way to release a run's browsers so nobody hand-rolls unit-name
selectors. Unchanged boundary from t_297ebf3e: historical **ownerless** rows are
never adopted, backfilled or retired by age/idle heuristics.

## Root cause (new leaks)

`--owner-pid` was optional and the canonical agent examples omit it. Without
it, `metadata.owner` is `None`, `owner_state(None) == "unknown"`, and
`maintain`/`watch` either renews the lease every 5 s (activity-tracked browsers
classify as `active`/`idle`) or does nothing (`unknown`). An agent that exited,
crashed or lost context without calling `release` therefore left its browser
unit, Chrome processes and lease alive indefinitely; TTL never lapsed because the
watcher kept renewing. The exact-owner terminal path (verified unit/root/CDP stop
plus fenced canonical release) already existed but had no owner to observe.

Historical context: before 59a525e0 (2026-09-23) Chrome could also move itself
into an `app-org.chromium.*.scope`, so stopping `browser-<id>.service` left
children running (PC-20260919-012520-526cc7b2). PC-20260901 (14-day-old
processes) predates that fix; the 2026-11-23 recurrences are consistent with the
ownerless-lifecycle gap above. Hoster was unreachable during this work, so the
mix on the live node is not verified.

## Implemented contract

1. **Agent-ancestor lifecycle owner** (`browser_lifecycle.agent_supervisor_identity`).
   When `start` runs without `--owner-pid`, a browser it launches or takes over
   records the exact `process_identity` (pid, start tick, boot id, node) of the
   nearest ancestor whose comm/argv0 (or interpreter script) is a known agent
   runtime (`claude`, `codex`, `hermes`, `pi`, `omp`, `opencode`, `gemini`,
   `grok`, `aider`, `goose`, `crush`, `qwen`, `droid`, `cursor-agent`), with
   `owner_source: agent-ancestor`. When that process exits, the existing
   watcher/`maintain` terminal branch stops and releases the browser through
   `fenced_stop_release`. Holds (`awaiting-input`), in-flight commands and
   activity-tracked team grants still protect it.
   - No ancestor match (e.g. a one-shot SSH request from Ghost) or unreadable
     `/proc` → owner stays `None`, i.e. exactly the previous behavior.
   - Explicit `--owner-pid` wins. A derived owner never triggers the
     owner-process-mismatch lock: a same-agent/run request with an explicit
     `--owner-pid` replaces it (dropping `owner_source`) under the node lock,
     exactly as an explicit owner adopts onto an ownerless browser; only a
     conflicting explicit owner still locks. The derived owner is not used for
     the task-MITM listener owner, and derivation never adopts an
     already-running ownerless row.
   - Headed / `--driving-mode manual` handoff browsers are bound too: after the
     agent exits, only an unexpired `awaiting-input` hold (max 3600 s) keeps
     them alive, so the hold must be set before exit/handoff.
   - **Residual (not fixed):** a browser whose owning agent is alive but idle —
     an interactive session left open in tmux, or a long-lived Hermes
     host/gateway process — keeps being renewed exactly as before. The leak is
     fixed only when the owning agent process exits; idle live agents still
     need explicit `release`/`release-run`.
2. **Swap-aware admission** (`admission`, `memory_pressure`). RAM below its
   minimum always rejects. If only free swap is below its minimum, admit when
   `MemAvailable >= min_ram + (min_swap - SwapFree)` and memory PSI is healthy
   (`some avg10 <= 10`, `full avg10 <= 1`); receipt `swap_gate:
   covered-by-available-ram`. Unreadable PSI never admits. Rejections carry a
   `reason`. Admission stays read-only and before lease acquisition. This is
   the automatic form of the operator-approved manual retry rule (727961e6),
   but stricter: it also requires RAM to cover the swap shortfall.
3. **`release-run`** — `release-run --agent-id A --run-id R --disposition D
   --profile-health H [--apply]`. Dry-run by default. Selects running manager
   rows by exact recorded `(agent_id, run_id)`, never by unit name; every stop
   re-proves the canonical lease, unit invocation, terminal root and closed CDP
   via `fenced_stop_release`. Receipt: per-browser result, unit as
   `<name>.service`, `kept_running` count, this run's `starting` rows (reported
   as `starting-not-stopped`, never stopped: identity is not yet proven),
   task-proxy metadata and a `task-proxy-finish` pointer. Exit 2 with
   `cleanup-incomplete` if any exact
   stop is unverified; siblings are still attempted.
4. Guidance updated in `skills/chromium-test/SKILL.md`, `scripts/README.md` and
   `prompts/chromium-test-playbook.md` (automatic owner, `release-run`, swap
   gate, never hand-roll `systemctl list-units` keep/stop comparisons).

Non-claims: no change to historical ownerless rows, task-MITM proxy ownership,
`cleanup`/`reap-idle` thresholds, unit launch flags, or Hoster runtime.

## Papercut disposition

- **PC-20260901-181544-9b2b73ff** (leaked Chrome exhausts swap): fixed-on-branch
  for new leaks **when the owning agent process exits** (agent-ancestor owner +
  existing verified terminal stop; `release-run` as the run-ID-keyed reaper).
  Not fixed for idle live agents (see residual). Existing leaked/ownerless
  processes on Hoster are not touched and still need exact operator proof per
  t_297ebf3e.
- **PC-20260918-222033-c990c35b** (swap exhausted, RAM plentiful): fixed-on-branch
  (automatic RAM-covered swap gate under healthy PSI). Not previously fixed:
  727961e6 is documentation-only and depends on agents reading and acting on it.
- **PC-20261020-021756-adc41ee2** (keep-list `.service` mismatch): the faulty
  selector was an ad-hoc audit command; no BBH code compares unit lists (bounded
  `rg` for `list-units`/`.service`/keep selectors under `skills/` and `agents/`
  found none for browser units). Mitigated on branch: `release-run` selects by
  exact recorded identity, normalizes receipt unit names, reports `kept_running`,
  and guidance forbids hand-rolled unit-name comparisons. Partially fixed: the
  repo cannot prevent an operator from running another ad-hoc command.

## Evidence and review

- Tests and commands (BBH `.venv` python 3.11, pytest 9.1.1; each module run
  from its own checkout with `PYTHONPATH=<checkout>:<checkout>/agents` and a
  short scratch `--basetemp`; long basetemps add unrelated `AF_UNIX path too
  long` failures):
  - New module: `python -m pytest -q agents/test_browser_run_lifecycle.py` →
    **33 passed**.
  - Before/after sweep of 57 modules (every `agents/test_browser_*.py`, every
    module importing the provisioner/lifecycle/lease-recovery helpers, and the
    three skill-text contract modules that read the edited guidance): base
    `3f72ed81` **978 passed / 58 failed / 66 skipped**; branch **1011 passed /
    58 failed / 66 skipped**. The failing test IDs are identical on both
    (no new failures, none fixed); they are pre-existing and recorded in
    `BUGFIXES.md`. Unchanged key modules: `test_browser_provisioner` 106/106,
    `test_browser_lease_recovery` 21/21, `test_browser_safe_resume` 33/33,
    `test_browser_stop_fence` 25/25, `test_browser_driving_mode` 4 skipped
    (opt-in real-browser fixture) on both.
  - RED/GREEN probe (scratch, not committed) asserting the fixed behavior:
    base `3f72ed81` **3 failed** (ownerless start, swap-exhausted rejection,
    no run-keyed release); branch **3 passed**.
  - `git diff --cached --check` clean.
- Review-fix loop (after APPROVE-WITH-NITS on `6bbde711`): new module now
  **35 passed**; the two new/extended regressions fail on `6bbde711` (3 failed:
  inferred-owner mismatch lock, two `starting`-row report assertions) and pass
  on the fix. Same 58-module sweep re-run on the fix: **1013 passed / 58
  failed / 66 skipped**, failing test IDs identical to base `3f72ed81`
  (baseline receipts reused: unchanged base tree, interpreter and method).
- Independent review: APPROVE-WITH-NITS on `6bbde711` (parent-run); nits
  addressed in the review-fix commit; re-review owned by the parent.
- Replay/cohort/fixture evidence: temporary SQLite registries, fake `/proc`
  trees, a real short-lived child process for terminal identity, mocked systemd.
  No live target traffic, no Hoster mutation.
- Merge/ancestry evidence: branch created from fetched `origin/beta` 3f72ed81.

## Blockers and deferred work

- **Missing evidence:** live Hoster observation of the current leaked process mix
  (ownerless rows vs. pre-59a525e0 scope escapes vs. non-provisioner launchers).
  **Command:** read-only `ps`/`/proc/<pid>/cgroup`/`systemctl --user list-units
  'browser-*'` joined against the provisioner DB on Hoster. **Trigger:** Hoster
  reachable (SSH timed out on 2026-11-24). **Why:** confirms the root-cause mix;
  does not block integration of the new-leak fix.
- **Deferred:** task-MITM listeners still need explicit `task-proxy-finish` (or
  explicit `--owner-pid`) — the derived owner was deliberately not applied to the
  proxy because proxy reuse requires owner equality across same-run requests.
- **Not fixed (residual):** idle *live* agents. An interactive agent left open
  in tmux, or a Hermes host/gateway process (long-lived shared daemon) as the
  ancestor, keeps its browser renewed indefinitely — same as the previous
  ownerless contract. Mitigation is explicit `release`/`release-run`; an
  activity-based policy for live owners would need a separate decision.
- **Activation:** Hoster activation/projection is a separate step after beta
  integration; verify the selected runtime checkout, not just beta.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/browser-leak-swap-admission`
- **Latest immutable recovery checkpoint:** `d4b7d1d50c01acb7cc11f46a5497a24682d5612e`
- **Feature implementation commit(s):** `d4b7d1d50c01acb7cc11f46a5497a24682d5612e`;
  the branch tip is a later dossier-only commit — verify it separately.
- **Exact resume point:** independent review of `3f72ed81..fix/browser-leak-swap-admission`
- **Working-tree state at handoff:** clean

## Decision gates

- **Integration gate:** independent review of the diff and receipts; focused
  before/after suites show no new failures relative to base 3f72ed81.
- **Activation / cohort gate:** Hoster runtime update + read-only verification
  that new browsers record `owner_source: agent-ancestor` for local agents.
- **Promotion gate:** none requested.

## Decision record

- 2026-11-24 — created; implementation, tests and guidance committed on the
  feature branch; review-ready for the parent.
