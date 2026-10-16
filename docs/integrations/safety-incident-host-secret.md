# Safety incident per-host secret integration dossier

- **Status:** feature; local verification complete, integration deferred
- **Owner:** Hermes / BBH CLI
- **Branch / owning ref:** `feat/safety-incident-host-secret`
- **Base commit:** `5993acc110972b2eae45b77a453ccb7ebb0e6b96` (selected Hoster beta runtime ancestor)
- **Intended integration target:** `beta` (currently `origin/beta` at `e6e12b4b64cab8af3e7939ee8e0d7099294f1f57`; reconcile later)
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** `4bc51020f4459a1aa4074a69b385d5143744dc1f` on `feat/safety-incident-host-secret`
- **Feature implementation commit(s):** `3411333dd7d99529c3e087b6236defca37589832`, `4bc51020f4459a1aa4074a69b385d5143744dc1f`
- **Inspiration / canonical references:** `AGENTS.md`, `SCRIPT_POLICY.md`, `docs/bbh-launcher.md`, published Bounty Core beta `6c36ee88a60073e1b687ec32deeade24ffafdd4f` (formatted severity alerts).

## Intent and contract

Only `scripts/safety_incident.py` loads the owner-only `$HOME/.config/bounty-core/safety-webhook-url` if `DISCORD_SAFETY_WEBHOOK_URL` is absent, after validated profile identity. Its regular, non-symlink, current-UID, non-group/other-accessible file is read with a 4096-byte bound. A single syntactically valid Discord endpoint is forwarded to pinned Bounty Core through the process environment, not arguments, JSON, or logs. An explicit environment setting wins. `--no-notify` avoids opening the file. Missing, insecure or invalid file yields a generic warning and provider `not-configured` receipt; incident logging remains durable. The pinned provider accepts optional `--severity` (defaults unknown), prints a saved incident summary before notification, then sends a bounded severity-colored embed. No live webhook delivery has been attempted from this branch.

## Evidence and review

- `./setup.sh --install-python-deps`: installed checkout-local pinned Bounty Core `ce8718b6...`.
- `.venv/bin/python -m pytest tests/test_safety_incident.py -q`: 10 passed, 12 subtests passed after exception-handling and output-redaction assertion edit.
- `.venv/bin/python -m pytest tests -q`: 230 passed, 174 subtests passed, 1 pre-existing unrelated failure (`tests/test_hoster_script_authority.py` expects removed AGENTS text).
- `.venv/bin/python -m pytest -q`: root collection error in unrelated `test_catalog.py` due to missing `bac_checks`; use repository `tests/` suite for this branch.
- Provider release/pin update: `requirements.txt` and dependency regression now require `6c36ee88a60073e1b687ec32deeade24ffafdd4f` and reject superseded `ce8718...`. Checkout-local installer and `direct_url.json` confirmed exact new SHA. CLI wrapper with `--severity critical --no-notify` verified stored severity, terminal saved-ID summary and no delivery in disposable profile/HOME. Focused 27 passed, 12 subtests; filtered `tests/` 231 passed, 1 deselected, 174 subtests; diff check clean.
- Independent loader-only review: approved 10 focused/12 subtests and 230 filtered/174 subtests; final pin+CLI diff still needs independent review before integration.
- Integrated current-beta and Hoster live-render/readback receipts: pending.
- Merge/ancestry: fetched `origin/beta` `e6e12b4...`; this feature deliberately started at selected Hoster runtime ancestor `5993acc...`, not current beta, per delegated scope. Reconcile the advanced beta deliberately before integration; do not rewrite or merge/push from this task.

## Blockers and deferred work

- **Missing evidence:** final independent review and integrated current-beta tests; controlled Hoster delivery/readback.
- **Command / fixture:** compare final feature diff with current beta, merge in clean integration worktree, rerun `.venv/bin/python -m pytest tests/test_safety_incident.py -q` and filtered `tests/` suite. Hoster owner-approved webhook is provisioned in an owner-only file (verified without revealing value); after reviewed runtime activation, send one clearly marked synthetic alert and read back exact Discord message.
- **Trigger:** final independent beta gate and selected Hoster runtime activation.
- **Why deferred:** source review and runtime activation must remain separate; live webhook delivery has not yet been exercised with this code.
- **Next:** parent obtains final independent review, reconciles beta, then deploys exact reviewed feature checkpoint without unreviewed beta commits.

## Interruption / resume handoff

- **Owning ref:** `feat/safety-incident-host-secret`
- **Latest recovery checkpoint:** `4bc51020f4459a1aa4074a69b385d5143744dc1f` (verify any later dossier-only tip separately)
- **Feature implementation commit(s):** `3411333dd7d99529c3e087b6236defca37589832`, `4bc51020f4459a1aa4074a69b385d5143744dc1f`
- **Exact resume:** final independent review of combined loader and provider pin; reconcile onto current beta, verify, then deploy selected runtime only to the published reviewed feature checkpoint.
- **Working-tree state at handoff:** clean after task commit.

## Decision gates

- **Integration:** no merge or push in this task; parent review and beta reconciliation required.
- **Activation:** Hoster owner-only secret file provisioned and privately read back; selected checkout/dependency update and one controlled Discord delivery/readback remain pending.
- **Promotion:** no stable promotion authorized.

## Decision record

- 2026-10-15 — selected runtime-ancestor exception recorded; narrow CLI fallback implemented and offline tests exercised.
- 2026-10-15 — implementation checkpoint `3411333dd7d99529c3e087b6236defca37589832`; offline suite 230 passed, 174 subtests with known unrelated Hoster-authority failure excluded.
