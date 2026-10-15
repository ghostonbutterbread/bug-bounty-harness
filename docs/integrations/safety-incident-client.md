# Safety incident client integration dossier

- **Status:** feature (local handoff; not integrated)
- **Owner:** BBH consumer
- **Branch / owning ref:** `feat/safety-incident-client`
- **Base commit:** `de82c81bb455e459888c20370ad1d61a84f59368` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** `b649326` on `feat/safety-incident-client`; routing repair commit pending
- **Feature implementation commit(s):** `51f25a0`; routing repair pending
- **Provider:** Bounty Core beta `ce8718b6bfb39fb08533f506bd2bfe627b52e5da`, `bounty_core.safety_incidents.main`.

## Intent and implemented contract

`scripts/safety_incident.py` validates a required absolute `--profile` pointing at the selected lane's `context/target_profile.json` before either `record` or `notify`. It checks program/family/lane identity, canonical root against profile location and `resolve_storage(..., root_override=base_root).lane_root`, then forwards the derived base root explicitly to the pinned provider. Optional absolute `--root` must agree with that lane. Missing/inconsistent profile fails closed; no `~/Shared`, cwd, or environment-root inference. Record writes lane-local append-only JSONL and may attempt notification unless `--no-notify` is set. Stop/contain independently; use factual non-secret fields. This is explicit agent reporting, not interception or automatic detection. No live webhook or shared production data is touched by tests.

## Evidence and review

- Initial feature `51f25a0`: checkout-local provider pinned/install verified; focused 17 passed; full suite 221 passed, one existing `test_hoster_script_authority` failure. `b649326` recorded initial checkpoint.
- Independent review blocked forwarding-only client: omitting `--root` wrote to provider `~/Shared` despite `HARNESS_SHARED_BASE`. This repair requires the actual profile and derives an explicit base root at the BBH script boundary.
- `.venv/bin/python -m pytest tests/test_safety_incident.py tests/test_runtime_dependencies.py tests/test_bbh_launcher.py -q` — 21 passed, 6 subtests passed (before final absolute-root guard; final rerun below). Disposable nondefault base, deliberately wrong environment base, no notification; missing/wrong identity, canonical root, explicit root, misplaced profile and notify rejection tested.
- `.venv/bin/python -m pytest tests -q` — 225 passed, 168 subtests passed; one unchanged baseline failure: `tests/test_hoster_script_authority.py::test_hoster_script_authority_uses_current_capability_not_machine_lists` expects `Hoster is execution-only by default` in unchanged `AGENTS.md` (before final absolute-root guard; final rerun below).
- Final focused rerun: `.venv/bin/python -m pytest tests/test_safety_incident.py tests/test_runtime_dependencies.py tests/test_bbh_launcher.py -q` — 21 passed, 6 subtests passed. Full rerun: `.venv/bin/python -m pytest tests -q` — 225 passed, 168 subtests passed, same single unrelated `test_hoster_script_authority_uses_current_capability_not_machine_lists` failure. Excluding only that baseline test: `.venv/bin/python -m pytest tests -q -k 'not test_hoster_script_authority_uses_current_capability_not_machine_lists'` — 225 passed, 1 deselected, 168 subtests passed.
- Reference-impact search for `safety_incident.py`: updated live call sites `agents/index.md`, `docs/bbh-launcher.md`, `scripts/README.md`; remaining references are tests, this dossier, and the owning script.
- No post-repair independent review or integration/activation. Selected runtime must reinstall pinned provider after integration.

## Blockers and deferred work

- **Missing evidence:** clean full suite and independent integration review.
- **Command / fixture:** `.venv/bin/python -m pytest tests -q` after owner resolves existing AGENTS/test disagreement; review feature diff against fresh `origin/beta`.
- **Trigger:** before beta integration or activation.
- **Why:** unrelated baseline failure precludes a green full suite; activation must reinstall from manifest in the selected runtime.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/safety-incident-client`
- **Latest immutable recovery checkpoint:** `b649326`; routing repair commit pending
- **Feature implementation commit(s):** `51f25a0`; routing repair pending
- **Exact resume point:** inspect repair commit and diff against fresh `origin/beta`, obtain independent review, resolve baseline failure separately, then integrate only on authorization; never send a webhook for validation.
- **Working-tree state at handoff:** pending commit.

## Decision gates

- **Integration gate:** not claimed; baseline suite failure and independent review outstanding.
- **Activation / cohort gate:** reinstall pinned provider in selected checkout, rerun CLI smoke with disposable profile, nondefault shared base and `--no-notify`.
- **Promotion gate:** not requested or tested.

## Decision record

- 2026-10-15 — feature-only forwarding and isolated no-delivery CLI verification; no merge/push or runtime activation.
- 2026-10-15 — reviewer-blocking wrong-root defect repaired at owning BBH CLI boundary; feature-only, no webhook/merge/push.
