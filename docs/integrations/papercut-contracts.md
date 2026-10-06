# BBH papercut contracts integration dossier

- **Status:** review-ready
- **Owner:** Hermes bugfix
- **Branch:** `fix/papercuts-attempts-errors-20261005`
- **Base commit:** `140c096250ad246bd89a998bd8b5eadca7497136` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-06
- **Owning feature branch/ref:** `fix/papercuts-attempts-errors-20261005`
- **Latest immutable recovery checkpoint:** `2b558cd2a48ac497a7151feb59ef6179cab4940d`
- **Feature implementation commit(s):** `2b558cd2a48ac497a7151feb59ef6179cab4940d`
- **Inspiration / canonical references:** Shared PAPERCUTS.md entries PC-20261005-235010-e4aad741, PC-20261005-232908-685dca27, PC-20261005-232245-8b5dccda, PC-20261003-050323-735d3220, PC-20261006-025055-311ac47d.

## Intent

Verify reported papercuts against current beta before making narrow corrections. Preserve the actual Error Store/MapStore/manual-hunter CLI and Bounty Core contracts; do not invent structured tags or widen schemas. No target actions, stable promotion, remote runtime repair, or installation outside this worktree.

## Implemented contract

Error guidance treats signal/class as analysis only, documents actual Core layer/channel enums, and removes a goal-route instruction to tag unsupported fields. MapStore clarifies proof tag versus lifecycle status. Manual Hunter lists the current editable fields and excludes derived `severity_label`. The runtime dependency test now expects the already-pinned Bounty Core revision. A focused doc/CLI contract test guards the corrections. No runtime CLI or Core source behavior is changed.

The Attempts writer import incident does **not** reproduce in a properly provisioned current beta lane. It *did* reproduce here when tests initially used a different checkout's stale `.venv`; `./setup.sh --install-python-deps` in this feature worktree installed the pinned Core revision and restored imports. The missing Hoster runtime cannot be read locally, so its old reports are not closed by this patch.

## Evidence and review

- Tests and commands: feature `.venv/bin/python -m pytest -q tests/test_papercut_contract_docs.py tests/test_runtime_dependencies.py agents/test_error_store.py` → 7 passed; `agents/test_map_store.py -k status` → 7 passed, 64 deselected; `agents/test_manual_hunter.py -k edit_finding` → 4 passed, 20 deselected; `git diff --check` clean. A broader map-store run timed out at pre-existing `test_mapstore_url_projection_is_idempotent` after 33 passes; this unrelated I/O-heavy path is not changed here.
- Independent review: fresh reviewer verified the seven-file diff against current `origin/beta`, CLI/Core enums and editable fields, and the pinned dependency; focused contract/Error Store/MapStore selection passed 77 with one unrelated I/O-heavy MapStore case deselected, and four manual-hunter edit tests passed. The reviewer required this dossier correction before release. Two unchanged baseline tests (`test_hoster_script_authority.py`, `test_skill_command_lane_safety.py`) remain red and are not counted as green.
- Replay/cohort/fixture evidence: no live target actions. The first run using a stale foreign venv failed importing `bounty_core.provenance`; checkout-local setup installed `bounty-core` at `54ac5e8261edd313c815adde17d4fbb64fb4727d` and focused tests passed.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- **Missing test or evidence:** Hoster runtime installation and attempts writer import in the reported `runtime-beta-clean` checkout.
- **Command / fixture / environment needed:** on Hoster, read its manifest/installed Core revision, run checkout-local setup when mismatched, then import with that checkout's `.venv/bin/python` and inspect `bbh --root`.
- **Trigger to run it:** authorized Hoster maintenance access and a dedicated runtime-repair task.
- **Why it blocks integration, activation, or promotion:** does not block this local documentation/test fix; blocks any claim that the remote Attempts papercut is fixed.
- **Next completion step / successor reference:** keep remote Attempts entries open until verified there.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/papercuts-attempts-errors-20261005`
- **Latest immutable recovery checkpoint:** `2b558cd2a48ac497a7151feb59ef6179cab4940d`
- **Feature implementation commit(s):** `2b558cd2a48ac497a7151feb59ef6179cab4940d`
- **Exact resume point:** reconcile current beta, then integrate the reviewed change if focused checks remain green.
- **Working-tree state at handoff:** clean after the dossier-only review correction commit.

## Decision gates

- **Integration gate:** focused tests, independent review, clean current beta comparison and post-merge verification.
- **Activation / cohort gate:** not requested; no Hoster deployment claim.
- **Promotion gate:** no main/stable promotion.

## Decision record

- 2026-10-06 — validated local beta and repaired only reproduced documentation/test mismatch; remote Attempts environment remains unverified.
- 2026-10-06 — independent reviewer approved the contract changes but blocked release on stale dossier checkpoint metadata; corrected handoff before integration.
