# Single requirements manifest integration dossier

- **Status:** implemented; awaiting independent release gate
- **Owner:** delegated Hermes integration author; parent owns review/integration/publication
- **Branch / owning feature ref:** `fix/single-requirements`
- **Worktree:** `/home/ryushe/worktrees/bbh-single-requirements`
- **Base commit:** `b7e64c312e58b89edd8cf169dbd2b8b58f59a7d3`
- **Intended integration target:** `beta`
- **Latest immutable recovery checkpoint:** `2f18a903606d6f9439ba031f78b05282a2b4aa15`
- **Feature implementation commits:** `2f18a903606d6f9439ba031f78b05282a2b4aa15`
- **Handoff tip:** the following dossier-only commit on this owning feature ref;
  reviewer must inspect it as well as the immutable implementation checkpoint.
- **Inspiration:** explicit single-manifest packaging maintenance request; AGENTS.md, SCRIPT_POLICY.md, shared coding and branch lifecycle policies.

## Intent and implemented contract

Consolidate the split checkout manifests into root `requirements.txt`. Preserve
all seven unique dependency specifications verbatim, including the existing
Bounty Core revision `1bba64b557aa3b604092b5bad47689fcb40cc0f7`; remove the redundant
HTTPX entry. No dependency upgrade/downgrade is part of the change.

Setup installs both runtime and test dependencies from the canonical manifest
into the selected checkout's `.venv`. The old manifests are removed rather than
kept as compatibility aliases. Update setup help/diagnostics, both documentation
consumers, and the runtime dependency regression. Close the previously recorded
stale-test-pin defect in BUGFIXES.md without changing the installed Core pin.

The requested repair owner is beta; this feature is based on its fetched tip.
No stable or sibling branch is changed. Parent will merge the verified feature
into beta; affected consumers inherit it through normal future lane propagation,
not duplicated patches. Stable promotion is not authorized by this handoff.

## Evidence and review

Executed from this feature worktree:

- Baseline `python3 tests/test_runtime_dependencies.py`: 2 tests, 1 failure;
  the unchanged test expected an older Core pin (already recorded in BUGFIXES.md).
- New regressions before implementation: 2 failures, missing canonical manifest
  and setup selecting the removed split path. To recover this red receipt, copy
  the candidate test into a temporary archive of the base commit and run it there.
- `python3 tests/test_runtime_dependencies.py`: 2 passed after implementation.
- `.venv/bin/python -m pytest -q tests/test_runtime_dependencies.py tests/test_bbh_launcher.py tests/test_portable_shell_launchers.py`:
  **14 passed in 0.30s**.
- `bash -n setup.sh`: passed.
- `bash setup.sh --install-python-deps`: real successful fresh checkout-local
  installation, CPython 3.11.15, 20 packages including Bounty Core at the unchanged
  immutable pin. Only ignored local `.venv` and `config.env` were created.
- `uv pip check --python .venv/bin/python`: all 20 installed packages compatible.
- Import smoke: bounty_core, httpx, requests, yaml, bs4, websocket, pytest passed;
  interpreter and bounty_core resolved inside this feature worktree's `.venv`.
- Dependency set audit against `git show <base>:<old-manifest>`: seven unique
  entries exactly preserved, no additions/removals/version-spec changes.
- Reference-impact audit: all tracked files searched, including hidden paths;
  zero references to either former filename remain. Initial consumers were setup,
  runtime tests, the shared-module spec, launcher dossier, split include, and the
  BUGFIXES entry. No tracked GitHub/GitLab/Jenkins CI, tox/pyproject/Makefile/Dockerfile
  consumers exist. EyeWitness's external setup manifest and application-mapping
  recognition of generic manifests remain intentionally unchanged.
- `git diff --check`: passed.
- Refetched `origin/beta` before handoff: still the exact base above.
- Independent review: **not performed by this author**; parent arranges fresh reviewer.

## Boundaries, blockers, and deferred work

- Kanban is explicitly waived by the user because of the runtime guard; no guard
  bypass or tracker changes attempted.
- `gh` is unavailable on PATH, so the optional read-only repository permission
  query could not run. Git fetch worked. This work uses the explicitly delegated
  integration-author authority; publication remains the parent's responsibility.
- No security scans, target interactions, global package installation, runtime
  activation, stable promotion, merge, or push performed.
- Whole-repository tests are not claimed: verification is limited to packaging
  and adjacent offline launcher tests, plus the real dependency install.
- Missing release evidence: independent reviewer rerun of the focused pytest
  command, shell syntax and manifest/reference audit on the committed candidate.
  Trigger: parent assigns release gate. This blocks integration/publication until
  accepted; reviewer must fetch beta again and handle any advancement deliberately.

## Interruption / resume handoff

- **Exact resume point:** parent reads the committed dossier and candidate diff,
  assigns an independent reviewer, then owns beta integration/push and remote
  read-back. Author must not merge or push.
- **Working-tree state at handoff:** intended clean tracked tree; ignored local
  environment retained for reviewer reruns.
- **Successor:** reviewed beta integration; retire this temporary dossier on
  acceptance using the standard integration cleanup, preserving branch history.

## Decision gates

- **Integration:** fresh independent review and focused test rerun required.
- **Activation:** not performed; installation was confined to the feature checkout.
- **Promotion:** separate explicit authorization required.

## Decision record

**APPROVED by fresh independent release reviewer.** Reviewed candidate
`09810875d1cad505989acc343a85e9c2c15102f3`, implementation
`2f18a903606d6f9439ba031f78b05282a2b4aa15`, and the complete base-to-tip diff.
This decision supersedes the pending-review and parent-only publication entries
above: the current explicit delegation authorizes this reviewer to integrate and
push beta, and waives Kanban only. Stable promotion remains unauthorized.

Independent receipts:

- Dependency audit against both base manifests: all seven unique specifications
  preserved exactly, including the immutable Core pin; no tracked old-path references.
- Focused packaging and portable launcher suite: 14 passed in 0.31s.
- Fresh committed-tree archive in a path containing spaces, invoked from another
  directory: real setup installed 20 packages into its new local `.venv`.
- `uv pip check`: all 20 compatible. Imports for all seven direct dependencies
  succeeded; interpreter and Core resolved inside that fresh environment, and
  installed Core direct-URL metadata matched the unchanged pinned commit exactly.
- The same focused suite in the fresh archive: 14 passed in 0.30s.
- Shell syntax and `git diff --check`: passed. Temporary archive removed.
- Fetched beta equals the stated base; local beta is clean with no unique ahead
  commits. No findings requiring implementation changes.

No outstanding required release tests. Whole-repository tests and runtime
activation remain intentionally outside this packaging release scope. Next:
refetch beta, merge the approved feature into clean beta, remove this dossier in
that integration operation, rerun focused checks, push beta and verify its exact
remote SHA, then retire only this contained clean task branch/worktree.
