# Finding-report provider pin integration dossier

- **Status:** blocked pending independent review and unrelated baseline test repair
- **Owner/task:** t_d8c93d35 / PC-20261030-014914-14bbd8c8
- **Branch:** `fix/finding-report-provider-pin`
- **Worktree:** `/home/ryushe/worktrees/bbh-finding-report-provider-pin`
- **Fetched base:** `28f0fd8644412951d6c719bf08ba28c27b16fd59`
- **Intended integration target:** `origin/beta` (no merge or push authorized)
- **Latest immutable recovery checkpoint:** none yet; commit this dossier with the fix
- **Feature implementation commits:** none yet
- **Last updated:** 2026-10-29 (PDT)

## Intent and contract

Fix a stale finding-report pin assertion without changing the manifest or weakening
its evidence-only behavioral and unsafe-revision guards. The exact canonical
requirement is checked, the two original unsafe pins remain prohibited, and the
existing real registration tests still exercise packet and report behavior.
No real finding, target, release, activation, or stable action is in scope.
The pin update belongs to beta: BBH `4bc51020f4459a1aa4074a69b385d5143744dc1f`
changed the provider pin while the finding-report assertion last changed at
`f2de03a14055919648a82994cf66b045ca636920`. No descendant propagation or
integration is authorized in this task.

## Evidence and review

- BBH fetched `origin/beta` at the base above before branching and again after
  testing; exact manifest and `tests/test_runtime_dependencies.py` pin agree on
  Bounty Core `6c36ee88a60073e1b687ec32deeade24ffafdd4f`.
- Provider `origin/beta` fetched as `c10866524a7fb30ac811fce8ef050fd5d8c922cc`;
  `git merge-base --is-ancestor` proves old accepted
  `035c9a165fb6addfebb814d66b1b7f6143ab7e69` is an ancestor of the approved pin,
  and the pin is an ancestor of fetched provider beta. Provider diff from old to
  new leaves `bounty_core/ledger.py`, `bounty_core/reports.py`,
  `tests/test_evidence_only_packets.py` and `tests/test_packet_migration.py`
  unchanged. The entire provider package diff changes only `__init__.py`,
  `safety_cli.py`, and `safety_incidents.py`.
- Actual test interpreter was `/home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python`.
  With `PYTHONPATH` and `PYTHONHOME` unset and cwd the feature checkout,
  `bounty_core.__file__` resolved under that venv's `site-packages` and its
  distribution `direct_url.json` records the GitHub URL, requested revision and
  commit ID as the exact approved pin. All 18 provider `.py` files installed
  there matched the pinned Git archive by SHA-256. The initially inherited
  `PYTHONPATH` shadowed this distribution; it was removed for all receipts.
  This is an existing pinned test environment, not a new checkout-local install.
- Tests used disposable synthetic ledger roots and a libseccomp wrapper that
  rejects non-AF_UNIX socket creation (AF_INET denial verified), inherited by
  subprocesses; pytest auto-plugins disabled. Wrapper and fixtures are ephemeral
  under the profile scratch directory, not production or real data.
- RED before edit: `agents/test_finding_report.py` plus
  `tests/test_runtime_dependencies.py` returned **2 failed, 6 passed**: stale
  pin and unrelated `idna` expectation. GREEN after edit: finding-report suite
  **6 passed**. Synthetic manifest fixtures retaining the valid approved line
  plus each of the two prohibited hashes each failed specifically at
  `assertNotIn`; clean fixture passed.
- Provider tests extracted from the exact pinned Git object, run against the
  installed distribution with `--import-mode=importlib`: evidence-only packets,
  packet migration and reports **56 passed**, including preserved legacy
  reports, no new legacy report files, rejected foreign/symlink paths and invalid
  mode, and authored evidence preservation. Consumer CLI/ledger fixture tests
  run in `agents/test_finding_report.py` exercise existing report registration,
  wrong FID and outside packet rejection, evidence and final body preservation.
- Broader report-related ten files: **316 passed, 101 subtests passed**. Including
  the runtime dependency suite: **317 passed, 101 subtests passed, 1 failed**;
  unchanged beta's dependency expectation omits `idna>=3,<4` present in the
  manifest since `878bcd02`. This is unrelated to the Bounty Core pin and is
  recorded in `BUGFIXES.md`; do not delete the dependency to make the suite pass.
- Independent review: **not performed**, explicitly deferred to the parent.

## Blockers and deferred work

The dependency suite is not entirely green; the separate dependency-list owner
must reconcile the missing `idna` entry and rerun `tests/test_runtime_dependencies.py`.
A reviewer must independently check the source/provenance, negative compatibility
cases, candidate diff and suite, then fetch and reconcile beta if it moved. No
merge, push, stable promotion, runtime activation, or task closure is authorized.

## Interruption and decision gates

- **Owning feature branch:** `fix/finding-report-provider-pin`
- **Checkpoint / implementation:** none yet; next commit records fix and dossier.
- **Exact resume point:** review the committed candidate and resolve the unrelated
  dependency test under its own task before considering integration.
- **Activation / promotion:** separate explicit owner decisions, not this task.
