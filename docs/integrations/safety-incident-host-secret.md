# Safety incident per-host secret integration dossier

- **Status:** feature; local verification complete, integration deferred
- **Owner:** Hermes / BBH CLI
- **Branch / owning ref:** `feat/safety-incident-host-secret`
- **Base commit:** `5993acc110972b2eae45b77a453ccb7ebb0e6b96` (selected Hoster beta runtime ancestor)
- **Intended integration target:** `beta` (currently `origin/beta` at `e6e12b4b64cab8af3e7939ee8e0d7099294f1f57`; reconcile later)
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** `3411333dd7d99529c3e087b6236defca37589832` on `feat/safety-incident-host-secret`
- **Feature implementation commit(s):** `3411333dd7d99529c3e087b6236defca37589832`
- **Inspiration / canonical references:** `AGENTS.md`, `SCRIPT_POLICY.md`, `docs/bbh-launcher.md`, Bounty Core pin `ce8718b6bfb39fb08533f506bd2bfe627b52e5da`

## Intent and contract

Only `scripts/safety_incident.py` loads the owner-only `$HOME/.config/bounty-core/safety-webhook-url` if `DISCORD_SAFETY_WEBHOOK_URL` is absent, after validated profile identity. Its regular, non-symlink, current-UID, non-group/other-accessible file is read with a 4096-byte bound. A single syntactically valid Discord endpoint is forwarded to pinned Bounty Core through the process environment, not arguments, JSON, or logs. An explicit environment setting wins. `--no-notify` avoids opening the file. Missing, insecure or invalid file yields a generic warning and provider `not-configured` receipt; incident logging remains durable. No provider-wide config change, dependency pin change, secret transfer, remote send, or live webhook verification.

## Evidence and review

- `./setup.sh --install-python-deps`: installed checkout-local pinned Bounty Core `ce8718b6...`.
- `.venv/bin/python -m pytest tests/test_safety_incident.py -q`: 10 passed, 12 subtests passed after exception-handling and output-redaction assertion edit.
- `.venv/bin/python -m pytest tests -q`: 230 passed, 174 subtests passed, 1 pre-existing unrelated failure (`tests/test_hoster_script_authority.py` expects removed AGENTS text).
- `.venv/bin/python -m pytest -q`: root collection error in unrelated `test_catalog.py` due to missing `bac_checks`; use repository `tests/` suite for this branch.
- Independent review: pending parent integration review.
- Merge/ancestry: fetched `origin/beta` `e6e12b4...`; this feature deliberately started at selected Hoster runtime ancestor `5993acc...`, not current beta, per delegated scope. Reconcile the advanced beta deliberately before integration; do not rewrite or merge/push from this task.

## Blockers and deferred work

- **Missing evidence:** independent review and integrated current-beta tests; provider formatted severity upgrade/pin belongs to parent follow-up.
- **Command / fixture:** compare feature diff with current beta, merge in clean integration worktree, rerun `.venv/bin/python -m pytest tests/test_safety_incident.py -q` and `.venv/bin/python -m pytest tests -q`; provision actual secret on Hoster only by authorized operator, then verify a controlled delivery separately.
- **Trigger:** parent explicitly begins beta integration / provider release and later Hoster activation.
- **Why deferred:** user forbids merge, push, remote secret transfer and live webhook; current beta advanced after selected runtime ancestor.
- **Next:** parent reviews commit and reconciles beta; then pins provider severity formatting separately.

## Interruption / resume handoff

- **Owning ref:** `feat/safety-incident-host-secret`
- **Latest recovery checkpoint:** `3411333dd7d99529c3e087b6236defca37589832` (verify any later dossier-only tip separately)
- **Feature implementation commit(s):** `3411333dd7d99529c3e087b6236defca37589832`
- **Exact resume:** review feature diff, reconcile onto current beta, verify, and integrate only with separate authorization.
- **Working-tree state at handoff:** clean after task commit.

## Decision gates

- **Integration:** no merge or push in this task; parent review and beta reconciliation required.
- **Activation:** no secret provisioning or live send in this task; operator-controlled per-host file and separate activation evidence required.
- **Promotion:** no stable promotion authorized.

## Decision record

- 2026-10-15 — selected runtime-ancestor exception recorded; narrow CLI fallback implemented and offline tests exercised.
- 2026-10-15 — implementation checkpoint `3411333dd7d99529c3e087b6236defca37589832`; offline suite 230 passed, 174 subtests with known unrelated Hoster-authority failure excluded.
