# Attempts required-field guidance integration dossier

- **Owner:** Hermes bugfix; **status:** feature, review pending
- **Branch/ref:** `fix/attempts-required-fields-20261006`
- **Base:** `8bad30736c553c13791be07588d38afe96eafa3a` (`origin/beta`)
- **Target:** `beta` only; no stable promotion or Hoster activation
- **Immutable implementation checkpoint:** `729f1f63b686299c9cb2c54c039451291eda0762` on `fix/attempts-required-fields-20261006`; verify any later dossier-only commit at the current branch tip separately.

## Intent and contract

The open Hoster papercut `PC-20261002-223734-e8209f46` reports a rejected Attempt because `timestamp` was omitted. On current beta, `agents.attempts.append_attempt` rejects missing required fields; the writer does not synthesize `timestamp`. The canonical contract now says explicitly that callers must provide all five compatibility fields and can use `utc_timestamp()` for the timestamp. No writer behavior or validation is weakened.

## Evidence

- RED: a focused test reproduced the missing-timestamp `ValueError` and failed on absent explicit documentation.
- GREEN: `tests/test_papercut_contract_docs.py agents/test_attempts.py tests/test_runtime_dependencies.py` passed: 14 tests. `git diff --check` passed.
- Changed paths: `docs/attempt-recording-contract.md`, `tests/test_papercut_contract_docs.py` plus this temporary dossier.
- Independent review of `729f1f6` confirmed the required-field contract and 14 tests; it required this exact immutable checkpoint in the dossier before integration. Beta reconciliation and integration remain pending.

## Boundaries and handoff

This is a documentation correction, not evidence that previous rejected Attempts were backfilled or that Hoster workers now follow it. Reconcile current beta, merge into the clean integration checkout, rerun focused tests, retire this dossier from beta, push beta and verify remote read-back. Retain the Hoster papercut until its consumer has the guidance and a real writer call succeeds.
