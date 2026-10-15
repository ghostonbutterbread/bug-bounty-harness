# Safety incident client integration dossier

- **Status:** independent release gate accepted for beta integration; not activated
- **Owner:** BBH consumer
- **Branch / owning ref:** `feat/safety-incident-client`
- **Base commit:** `de82c81bb455e459888c20370ad1d61a84f59368` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** `77d48a4c634054a16fbcbd92affa7e07e5f37675` on `feat/safety-incident-client`
- **Feature implementation commit(s):** `51f25a0`, `193f3c7a9c2c8e27f5aa3d82e2ff9ac3da96936c`, `77d48a4c634054a16fbcbd92affa7e07e5f37675`
- **Provider:** Bounty Core beta `ce8718b6bfb39fb08533f506bd2bfe627b52e5da`, `bounty_core.safety_incidents.main`.

## Intent and implemented contract

`scripts/safety_incident.py` validates a required absolute `--profile` pointing at the selected lane's `context/target_profile.json` before either `record` or `notify`. It checks program/family/lane identity, reads the profile's explicit absolute `base_root`, verifies its `canonical_root` against profile location and both roots returned by `resolve_storage(..., root_override=base_root)`, then forwards the verified base root explicitly to the pinned provider. Optional absolute `--root` must agree with that lane. Missing/inconsistent profile fails closed; no `~/Shared`, cwd, or environment-root inference. Record writes lane-local append-only JSONL and may attempt notification unless `--no-notify` is set. Stop/contain independently; use factual non-secret fields. This is explicit agent reporting, not interception or automatic detection. No live webhook or shared production data is touched by tests.

## Evidence and review

- Initial feature `51f25a0`: checkout-local provider pinned/install verified; focused 17 passed; full suite 221 passed, one existing `test_hoster_script_authority` failure. `b649326` recorded initial checkpoint.
- Independent review blocked forwarding-only client: omitting `--root` wrote to provider `~/Shared` despite `HARNESS_SHARED_BASE`. This repair requires the actual profile and derives an explicit base root at the BBH script boundary.
- `.venv/bin/python -m pytest tests/test_safety_incident.py tests/test_runtime_dependencies.py tests/test_bbh_launcher.py -q` — 21 passed, 6 subtests passed (before final absolute-root guard; final rerun below). Disposable nondefault base, deliberately wrong environment base, no notification; missing/wrong identity, canonical root, explicit root, misplaced profile and notify rejection tested.
- `.venv/bin/python -m pytest tests -q` — 225 passed, 168 subtests passed; one unchanged baseline failure: `tests/test_hoster_script_authority.py::test_hoster_script_authority_uses_current_capability_not_machine_lists` expects `Hoster is execution-only by default` in unchanged `AGENTS.md` (before final absolute-root guard; final rerun below).
- Final focused rerun: `.venv/bin/python -m pytest tests/test_safety_incident.py tests/test_runtime_dependencies.py tests/test_bbh_launcher.py -q` — 21 passed, 6 subtests passed. Full rerun: `.venv/bin/python -m pytest tests -q` — 225 passed, 168 subtests passed, same single unrelated `test_hoster_script_authority_uses_current_capability_not_machine_lists` failure. Excluding only that baseline test: `.venv/bin/python -m pytest tests -q -k 'not test_hoster_script_authority_uses_current_capability_not_machine_lists'` — 225 passed, 1 deselected, 168 subtests passed.
- Reference-impact search for `safety_incident.py`: updated live call sites `agents/index.md`, `docs/bbh-launcher.md`, `scripts/README.md`; remaining references are tests, this dossier, and the owning script.
- Follow-up root-source correction: require the profile's `base_root` field and compare both resolved base/lane roots; reject a mismatched base root even when the profile location itself is plausible. `.venv/bin/python -m pytest -q tests/test_safety_incident.py tests/test_runtime_dependencies.py tests/test_bbh_launcher.py` — 21 passed, 7 subtests; filtered full suite — 225 passed, 1 deselected, 169 subtests. `git diff --check` clean.
- Fresh independent release gate at `b5eedaca4e3ddb20df9c820d334fe6ec22e8c1e2`: verified profile location, identity, absolute `base_root`, canonical root, and both storage roots in the source; tested duplicate program/profile/root flags, flags after command, abbreviated flags and `--` forwarding with a provider spy. Invalid duplicates were rejected before provider invocation; `--` leaves arguments to provider's strict parser, which rejects unrecognized flags. No exception values or profile data are printed on validation failure. Installed Bounty Core `direct_url.json` points at `ce8718b6bfb39fb08533f506bd2bfe627b52e5da`, matching `requirements.txt` and the runtime-dependency test. Focused: 21 passed, 7 subtests; full: 225 passed, 169 subtests, one unchanged `AGENTS.md` baseline failure; filtered full: 225 passed, 1 deselected, 169 subtests. No webhook or actual shared data touched. Selected runtime still needs reinstall after beta publication.

## Blockers and deferred work

- **Missing evidence:** clean full suite; independent review accepted but the baseline `AGENTS.md`/test disagreement remains unresolved.
- **Command / fixture:** `.venv/bin/python -m pytest tests -q` after owner resolves existing AGENTS/test disagreement.
- **Trigger:** before claiming a green full suite or stable promotion.
- **Why:** unrelated baseline failure precludes a green full suite; activation must reinstall from manifest in the selected runtime.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/safety-incident-client`
- **Latest immutable recovery checkpoint:** `77d48a4c634054a16fbcbd92affa7e07e5f37675` on `feat/safety-incident-client`; verify any later dossier-only handoff commit separately
- **Feature implementation commit(s):** `51f25a0`, `193f3c7a9c2c8e27f5aa3d82e2ff9ac3da96936c`, `77d48a4c634054a16fbcbd92affa7e07e5f37675`
- **Exact resume point:** inspect final root-source correction and diff against fresh `origin/beta`, obtain independent review, confirm baseline failure remains unchanged, then integrate if accepted; never send a webhook for validation.
- **Working-tree state at handoff:** clean after dossier handoff commit.

## Decision gates

- **Integration gate:** accepted for beta with one independently verified unrelated baseline full-suite failure; focused and filtered full suite pass. Recheck after merge in clean named-beta integration checkout.
- **Activation / cohort gate:** not claimed; reinstall pinned provider in selected active checkout and rerun CLI smoke with disposable profile, nondefault shared base and `--no-notify`.
- **Promotion gate:** not requested or tested.

## Decision record

- 2026-10-15 — feature-only forwarding and isolated no-delivery CLI verification; no merge/push or runtime activation.
- 2026-10-15 — reviewer-blocking wrong-root defect repaired at owning BBH CLI boundary; feature-only, no webhook/merge/push.
- 2026-10-15 — fresh independent review accepted beta integration against `de82c81bb455e459888c20370ad1d61a84f59368`; full suite has one unchanged AGENTS baseline failure, focused and filtered suite green. No activation or promotion authorized.
