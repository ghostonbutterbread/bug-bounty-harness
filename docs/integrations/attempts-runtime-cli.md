# Attempts runtime CLI integration dossier

- **Status:** review-ready (review nits addressed; narrow delta re-review assigned to parent)
- **Owner:** Hermes bugfix subagent
- **Branch / owning feature ref:** `fix/attempts-runtime-cli`
- **Worktree:** `/home/ryushe/worktrees/bbh-fix-attempts-runtime-cli`
- **Base commit:** `243a97bd52d970eb7d22cebcbd5f34baaf33f83e` (fetched `origin/beta` on 2026-11-24; dispatch named `643411a8`, beta had advanced; re-fetched before the review fix loop, unchanged)
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-24
- **Latest immutable recovery checkpoint:** the review-fix commit following `754e1b492f4804bc5488cbb69b41c0d75840810d` on this branch (Git cannot embed a commit's own ID; see the parent handoff)
- **Feature implementation commit(s):** `754e1b492f4804bc5488cbb69b41c0d75840810d` (initial), then the review-fix commit
- **Inspiration:** papercuts `PC-20260914-164802-40b9f8db`, `PC-20260925-194019-94adeebd`, `PC-20260928-220519-1125e0d7` (agents improvising system Python or `PYTHONPATH=<stale bounty-core>` fail with `No module named 'agents.attempts'` / `'bounty_core.provenance'`, then hand-append JSONL); `docs/attempt-recording-contract.md`

## Intent

Agents had no runnable shell entry to the canonical Attempts writer: the policy
names only `agents.attempts.append_attempt`, and `python -m agents.attempts`
deliberately refuses to run. On Hoster the active `bbh` runtime is healthy, but
there is no `~/projects/bug_bounty_harness`, and `~/projects/bounty-core` is a
stale clone without `provenance.py`, so improvised imports fail. Make the right
invocation one `bbh` command and make wrong invocations explain the remedy.
Writer semantics (redaction, IDs, locking) stay unchanged.

## Implemented contract

- `scripts/append_attempt.py` (run as `bbh scripts/append_attempt.py`): reads one
  JSON object from stdin or `--json`; destination is `--program/--lane/--run-id`
  (family inferred for default lanes, `--family` for custom lanes, `--root` for
  an explicit shared base) via `resolve_attempts_path(..., create=False)`, or an
  exact `--path`. Calls `append_attempt(..., agent_id, model_id)` and prints
  `{attempt_id, run_id, path}` with an absolute, lexically normalized path.
- Input checks before any storage access, all exit 2 without an Attempt and
  without a traceback: missing/closed/empty stdin (`no attempt JSON; pass --json
  or a quoted heredoc`), invalid or non-object JSON, required fields that are
  missing, null, blank, or non-string, `--timestamp-now` with a present
  timestamp (null counts as absent), a JSON `run_id` differing from the
  destination run (null/blank is dropped so the writer fills it), program/lane
  values that are empty, `.`, `..`, or contain `/` or `\`, run IDs outside
  `[A-Za-z0-9][A-Za-z0-9._-]*` (`--run-id` or the `--path` run directory; never
  echoed), and option conflicts.
- Program/lane mode refuses a missing lane root. A default lane's message names
  `program_init.py <program> --lane <lane>`; a custom lane's says its owning tool
  creates it and points to the packet's lane or `--path`.
- Recording creates only `attempts/_runs/<run-id>/` and appends; it no longer
  rescaffolds the lane or rewrites `context/target_profile.json`.
  `resolve_attempts_path` gained `create: bool = True` (default unchanged).
- `agents/attempts.py`: a Bounty Core `ImportError` is re-raised with the same
  type/name plus the interpreter, the located (not executed) `bounty_core`
  origin, and the remedies (`bbh scripts/append_attempt.py`, re-sync via
  `./setup.sh --install-python-deps`, no foreign `PYTHONPATH`). Non-Core import
  errors propagate unchanged. The `__main__` refusal now names the CLI.
- Docs/maps: contract doc leads with the runnable heredoc command; launcher doc,
  `scripts/README.md` index (inputs/mutation boundary updated), and
  `data-store-guidance` store map point to it.
- `BUGFIXES.md`: open entries for the Bounty Core dot-segment normalizer root
  cause and `append_attempt`'s null/non-string required-field check.
- Non-claims: does not change Hoster, Bounty Core, re-sync any venv, remove the
  stale Hoster clone, or migrate class skills that cite the Python API.

## Evidence and review

- Focused (`PYTHONPATH=<worktree>:<bounty-core@9db8b23 worktree>`, harness
  `.venv` Python 3.11): `tests/test_append_attempt_cli.py agents/test_attempts.py`
  — 43 passed after the review fixes (20 before).
- Negative controls: the `754e1b49` script fails 23 of the new/updated CLI
  tests; base `agents/attempts.py` failed the 4 import-guidance tests.
- Fake-runtime E2E: symlinked `bbh` → copied launcher; inherited
  `PYTHONPATH=<stale bounty-core without provenance>` makes direct execution
  fail actionably while `bbh scripts/append_attempt.py` records the Attempt.
- Independent review of `754e1b49`: APPROVE-WITH-NITS; nits 1-7 addressed here.
- Related suites and the pre-existing-failure comparison: see parent handoff.

## Blockers and deferred work

- **Hoster activation:** not performed (read-only task). After beta merge, the
  Hoster runtime-beta checkout must fast-forward through its normal deployment;
  smoke with `bbh scripts/append_attempt.py --help` and a disposable `--root`.
- **Policy sentence:** ai-policies `attempt-recording-policy` BBH sentence
  should name the command; drafted in the parent handoff, not committed here.
- **Stale Hoster clone:** `~/projects/bounty-core` (dc31a6c) remains; owner
  decision whether to remove/refresh it.
- **Bounty Core normalizers:** dot-segment names remain accepted for other BBH
  callers until fixed in Bounty Core and the pin is bumped (`BUGFIXES.md`).

## Interruption / resume handoff

- **Exact resume point:** narrow re-review of the review-fix delta against
  `754e1b49`, then beta integration by the parent.
- **Working-tree state at handoff:** clean after commit.

## Decision gates

- **Integration gate:** delta re-review + focused rerun on current beta.
- **Activation gate:** Hoster runtime-beta fast-forward and CLI smoke.
- **Promotion gate:** not requested.

## Decision record

- 2026-11-24 — Created; CLI adapter plus actionable import guidance chosen over
  changing writer semantics or Hoster state.
- 2026-11-24 — Review nits: run-id conflict and charset, dot-segment names,
  closed/empty stdin, null/non-string fields, absolute receipt path, no lane
  rescaffold (`create=False`), custom-lane remedy. Library-side required-field
  strictness and the Core normalizer fix deferred to `BUGFIXES.md`.
