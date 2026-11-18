# Core safety pin integration dossier

- **Status:** implementation and disposable installed-dependency verification complete; independent review and integration remain parent-owned
- **Owner:** delegated BBH worker; parent owns review and integration
- **Branch / worktree:** `fix/core-safety-pin-9db8b23`, `/home/ryushe/worktrees/bbh-core-safety-pin-9db8b23`
- **Base:** freshly fetched `origin/beta` at `9df7bf9826f8420633f522c466bd7d506711bdb7`
- **Intended integration target:** `beta`
- **Implementation / immutable recovery checkpoint:** `066d8b567a953494dc99de71cde1c47c8951ff10`; this dossier is a later documentation-only commit.
- **Provider:** published Bounty Core `9db8b23d7405587bc123338ae0aa44d4d51c95a3`

## Intent and implemented contract

Pin the published provider safety revision without changing BBH runtime logic. Update both exact pin tests and add CLI regression coverage for benign security prose and rejected credential-bearing labels. The artifact lifecycle test exercises created, private, pending, deleted and verified states. BBH uses the changed public-artifact API only in `agents/public_artifacts.py`; its supported lifecycle and tested calls passed. Static resolution is not proof of all dynamic call semantics or compatibility with every historical record.

## Evidence and review

- A disposable Git-archive snapshot containing these exact code/test changes was installed with `./setup.sh --install-python-deps` from the actual public remote and no Core source overlay. `direct_url.json` recorded `https://github.com/ghostonbutterbread/bounty-core.git` and both requested and resolved commit `9db8b23d7405587bc123338ae0aa44d4d51c95a3`; imported `bounty_core` was under the snapshot's `.venv/lib/python3.11/site-packages/`.
- From the snapshot with isolated HOME/XDG/TMPDIR/storage and `PYTHONPATH` pointing only at the snapshot, installed interpreter: `python -m unittest agents.test_manual_hunter_atomic agents.test_manual_hunter_watch_atomic agents.test_sync_reports agents.test_sync_reports_atomic agents.test_report_source_cli agents.test_manual_hunter agents.test_report_checker agents.test_report_checker_exceptional agents.test_finding_report tests.test_runtime_dependencies -q` — **180 passed**, six expected class-inference warnings.
- Same environment, `python -m pytest -q agents/test_public_artifacts.py` — **6 passed**, including lifecycle, canonical URL rejection, benign labels, rejected credential assignments and URLs, and no secret in output or files.
- Actual `./scripts/bbh agents/manual_hunter.py synthetic_launcher --lane apk --root <scratch-storage> --source-root <scratch-input> --from-file <scratch-note>` created one finding and one evidence packet, both read back in disposable storage.
- A static AST inventory of `agents`, `scripts`, and `tests` resolved **74 unique** Core module/symbol imports against installed Core. Provider diff from the prior pin changed only `bounty_core/public_artifact_store.py` among provider runtime modules; no dynamic-call exhaustive compatibility claim is made.
- Network namespace creation (`unshare -n`) was denied by the host. Instead each verification process and descendants inherited a seccomp filter denying IPv4/IPv6 socket creation; both denials were tested. This is an IP-socket restriction, not a general-purpose filesystem or Unix-socket sandbox. No real target stores were used.
- Receipts (ephemeral): `/home/ryushe/.hermes/cache/scratch/bbh-core-safety-iNkixs0n/{install.log,focused.log,public.log,launcher.log,imports.log,network-proof.log}`. `git diff --check` passed before commit.
- Independent review: not performed; parent owns exact-range review and integration.

## Boundaries and handoff

- Existing environments are not updated by the pin. Before authorized activation, rerun the supported installer in the intended checkout and verify direct_url and import paths.
- Core now applies stricter history, identity, and secret-label validation; existing noncanonical legacy artifact history may require Core's explicit recovery workflow. It was not inventoried or migrated here. Atomic imports cannot automatically identify old unmarked partial reservations; existing ledger and crash limitations remain unchanged.
- Next: parent reviews `9df7bf9826f8420633f522c466bd7d506711bdb7..066d8b567a953494dc99de71cde1c47c8951ff10` and this documentation-only handoff, refreshes beta, reconciles any intervening changes, and runs required combined checks. Remove this branch-local dossier during accepted integration. No push, integration, promotion or runtime activation was performed.
