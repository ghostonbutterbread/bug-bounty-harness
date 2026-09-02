# Hypothesis visibility modes — BBH integration dossier

## Scope and routing

- **Owner branch:** `feat/hypothesis-visibility-modes`
- **Worktree:** `/home/ryushe/worktrees/bbh-hypothesis-visibility-modes`
- **BBH base:** beta `0416cbd9ed8d40e33dee048e48901d5678904385`
- **Intended target:** `beta` only; no merge, push, or runtime activation occurred.
- **Published Bounty Core pin:** `f3d02453f26a4e221632466c26742dfb55368f28`
- **Implementation checkpoint:** `171e301df9ba13e53b7ccf0a1848c41ea1d95e4a` (`feat: expose hypothesis visibility review modes`)

BBH exposes only the reviewed Core APIs: `peer-surface-review` for an exact
surface plus URL and explicit peer-history intent, and `operator-app-review`
for a named operator request plus application-thinking intent. Both forward the
Core JSON envelope unchanged. Existing private `list`, counts-only
`continuation`, and exact public Lead `lead-followup` behavior is unchanged.

## Contract and evidence

- `requirements-bounty-core.txt` pins the full published Core SHA above and
  rejects superseded `fc361eca86f9c86acb357e1b9ce6426bc44aef83` in the immutable
  dependency regression.
- CLI integration tests use task-scoped temporary roots and the real CLI, not
  direct SQLite construction. They cover required review inputs/intents,
  private-list peer hiding, exact surface+URL exclusion of mismatches, bounded
  operator envelope results, and existing Lead privacy/relative-absolute alias
  compatibility.
- RED receipt under superseded Core: after adding the new tests while pinned to
  `fc361eca86f9c86acb357e1b9ce6426bc44aef83`, `agents/test_hypothesis_ledger.py`
  reported **7 passed, 2 failed** because both new CLI verbs were absent.
- GREEN receipt after `./setup.sh --install-python-deps` at the published pin:
  `uv pip freeze --python .venv/bin/python` reported
  `bounty-core @ git+https://github.com/ghostonbutterbread/bounty-core.git@f3d02453f26a4e221632466c26742dfb55368f28`;
  `.venv/bin/python -m pytest agents/test_hypothesis_ledger.py tests/test_runtime_dependencies.py -q`
  reported **11 passed**. Compile, `bash -n setup.sh`, and `git diff --check`
  also passed.

## Activation boundary and successor

This is source and installed-environment verification only. It did not touch
program targets, MapStore semantics, Attempts semantics, runtime selection, or
skill synchronization. Broad peer/app visibility remains forbidden as an
automatic or cold-start query; a later canonical AI-policy routing change owns
any cross-repository policy wording or activation decision.

## Resume/review point

Review implementation commit `171e301df9ba13e53b7ccf0a1848c41ea1d95e4a` and
final test/dossier handoff commit `376b663afece722f3b87fbe357025ade6482b58a`
together against BBH `beta`. Before integration, re-run the recorded
installed-environment commands from this worktree, verify the Core pin, and
preserve the no-runtime gate.
