# Attempts runtime CLI integration dossier

- **Status:** review-ready (local gate passed; independent review assigned to parent)
- **Owner:** Hermes bugfix subagent
- **Branch / owning feature ref:** `fix/attempts-runtime-cli`
- **Worktree:** `/home/ryushe/worktrees/bbh-fix-attempts-runtime-cli`
- **Base commit:** `243a97bd52d970eb7d22cebcbd5f34baaf33f83e` (fetched `origin/beta` on 2026-11-24; dispatch named `643411a8`, beta had advanced)
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-24
- **Latest immutable recovery checkpoint:** the implementation commit on this branch (see the parent handoff for its SHA; Git cannot embed a commit's own ID)
- **Inspiration:** papercuts `PC-20260914-164802-40b9f8db`, `PC-20260925-194019-94adeebd`, `PC-20260928-220519-1125e0d7` (agents improvising system Python or `PYTHONPATH=<stale bounty-core>` fail with `No module named 'agents.attempts'` / `'bounty_core.provenance'`, then hand-append JSONL); `docs/attempt-recording-contract.md`

## Intent

Agents had no runnable shell entry to the canonical Attempts writer: the policy
names only `agents.attempts.append_attempt`, and `python -m agents.attempts`
deliberately refuses to run. On Hoster the active `bbh` runtime is healthy, but
there is no `~/projects/bug_bounty_harness`, and `~/projects/bounty-core` is a
stale clone without `provenance.py`, so improvised imports fail. Make the right
invocation one `bbh` command and make wrong invocations explain the remedy.
Writer semantics (validation, redaction, IDs, locking) stay unchanged.

## Implemented contract

- `scripts/append_attempt.py` (run as `bbh scripts/append_attempt.py`): reads one
  JSON object from stdin or `--json`; destination is `--program/--lane/--run-id`
  (family inferred for default lanes, `--family` for custom lanes, `--root` for
  an explicit shared base) via `resolve_attempts_path`, or an exact `--path`.
  Calls `append_attempt(..., agent_id, model_id)` and prints
  `{attempt_id, run_id, path}`. `--timestamp-now` fills the required timestamp
  with `utc_timestamp()` and conflicts with a supplied timestamp.
- Program/lane mode refuses a missing lane root (resolver `create=True` would
  otherwise build a whole program tree for a typo). Invalid JSON, non-object
  JSON, missing required fields, and option conflicts exit 2 with no Attempt
  written and no traceback.
- `agents/attempts.py`: a Bounty Core `ImportError` is re-raised with the same
  type/name plus the interpreter, the located (not executed) `bounty_core`
  origin, and the remedies (`bbh scripts/append_attempt.py`, re-sync via
  `./setup.sh --install-python-deps`, no foreign `PYTHONPATH`). Non-Core import
  errors propagate unchanged. The `__main__` refusal now names the CLI.
- Docs/maps: contract doc leads with the runnable heredoc command; launcher doc,
  `scripts/README.md` index, and `data-store-guidance` store map point to it.
- Non-claims: does not change Hoster, re-sync any venv, remove the stale Hoster
  clone, or migrate class skills that cite the Python API.

## Evidence and review

- Focused (`PYTHONPATH=<worktree>:<bounty-core@9db8b23 worktree>`, harness
  `.venv` Python 3.11): `tests/test_append_attempt_cli.py agents/test_attempts.py`
  — 20 passed; related owners (launcher, script policy/index, data-store
  guidance, papercut contract docs, skill hygiene, agent audit, AI review
  attribution, coverage CLI, Hoster script authority) — 101 passed.
- Negative controls: base `agents/attempts.py` fails 4 new/updated tests;
  removing the lane guard fails the uninitialized-lane test.
- Fake-runtime E2E: symlinked `bbh` → copied launcher; inherited
  `PYTHONPATH=<stale bounty-core without provenance>` makes direct execution
  fail actionably while `bbh scripts/append_attempt.py` records the Attempt.
- Full-suite receipt and independent review: see parent handoff.

## Blockers and deferred work

- **Hoster activation:** not performed (read-only task). After beta merge, the
  Hoster runtime-beta checkout must fast-forward through its normal deployment;
  smoke with `bbh scripts/append_attempt.py --help` and a disposable `--root`.
- **Policy sentence:** ai-policies `attempt-recording-policy` BBH sentence
  should name the command; drafted in the parent handoff, not committed here.
- **Stale Hoster clone:** `~/projects/bounty-core` (dc31a6c) remains; owner
  decision whether to remove/refresh it.

## Interruption / resume handoff

- **Exact resume point:** independent review of the branch diff against
  `origin/beta`, then beta integration by the parent.
- **Working-tree state at handoff:** clean after commit.

## Decision gates

- **Integration gate:** independent review + focused rerun on current beta.
- **Activation gate:** Hoster runtime-beta fast-forward and CLI smoke.
- **Promotion gate:** not requested.

## Decision record

- 2026-11-24 — Created; CLI adapter plus actionable import guidance chosen over
  changing writer semantics or Hoster state.
