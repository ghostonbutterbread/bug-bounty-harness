# Attempts runtime invocation papercut handoff

- **Status:** feature, review pending
- **Owner:** Hermes bugfix
- **Owning branch/ref:** `fix/attempts-invocation-20261006`
- **Base:** `5b74b78e3e83591b541cda6726ee09097daf2925` (`origin/beta`)
- **Target:** `beta` (not `main`)
- **Recovery checkpoint:** the owning feature branch tip contains this implementation and dossier; inspect the reachable Git commit on handoff.
- **Changed paths:** `docs/attempt-recording-contract.md`, `tests/test_papercut_contract_docs.py` (this temporary dossier is retired at integration).

## Intent and ownership

Hoster read-only verification found that `agents.attempts` imports with the selected deployed checkout's `.venv/bin/python` at the pinned Core revision; bare system Python fails. Do not change the writer or Core dependency to fix an invocation mismatch. The canonical Attempts contract now shows how to obtain the active root from `bbh`, import from that root with its own virtualenv, and provision only that checkout if its dependencies are missing. It makes no claim that Hoster has been updated or an Attempt was written.

## Evidence

- RED: `tests/test_papercut_contract_docs.py::test_attempts_module_guidance_uses_selected_checkout_venv` failed on the missing lane/venv guidance.
- GREEN: `tests/test_papercut_contract_docs.py agents/test_attempts.py tests/test_runtime_dependencies.py` passed (13 tests); `git diff --check` clean.
- Local installed `bbh --root` selected the beta integration checkout; its `.venv/bin/python` imported `agents.attempts.append_attempt` from a separate scratch cwd and printed `attempts-ready` without writing an Attempt.
- Independent review: pending. Merge/ancestry: pending.

## Deferred and safety boundaries

- The Hoster runtime remains at an older checkout until explicitly synchronized and verified; source publication is not deployment. Recheck the selected Hoster `bbh --root`, its venv import, and actual caller invocation before closing operational Hoster reports.
- The task-proxy reservation issue is separate. Its existing exact `task-proxy-finish` path can finish a running reservation; legacy ownerless rows cannot be automatically proven terminal, so this branch does not introduce age-only cleanup or mutate Hoster leases.

## Interruption and decision gates

Obtain independent review of the committed diff and demonstrated invocation, reconcile advanced beta deliberately, rerun focused tests after integration, retire this dossier from beta, push beta and read back the remote ref. Do not promote to `main` or claim Hoster activation.
