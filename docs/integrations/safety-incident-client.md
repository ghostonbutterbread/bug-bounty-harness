# Safety incident client integration dossier

- **Status:** feature (local handoff; not integrated)
- **Owner:** BBH consumer
- **Branch / owning ref:** `feat/safety-incident-client`
- **Base commit:** `de82c81bb455e459888c20370ad1d61a84f59368` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** none yet (single task commit pending)
- **Feature implementation commit(s):** none yet (single task commit pending)
- **Inspiration / canonical references:** Bounty Core beta `ce8718b6bfb39fb08533f506bd2bfe627b52e5da`, `bounty_core.safety_incidents.main`.

## Intent and implemented contract

Expose Bounty Core's explicit agent-reported incident CLI from the selected BBH checkout. `scripts/safety_incident.py` delegates to the pinned provider without a parallel implementation. An explicit `--program`, `--lane`, and optional `--root` select storage; `record` writes lane-local append-only JSONL and may attempt notification unless `--no-notify` is set. Fields must be factual and non-secret. Stop/contain independently. This does not intercept requests, detect incidents automatically, or establish complete coverage. No live webhook or shared production data is touched by tests.

## Evidence and review

- `./setup.sh --install-python-deps` installed Bounty Core from the pinned commit into this checkout's `.venv`.
- RED: `tests/test_safety_incident.py` failed with `bbh: BBH script is missing from this checkout` before wrapper creation.
- GREEN: `.venv/bin/python -m pytest tests/test_safety_incident.py tests/test_runtime_dependencies.py tests/test_bbh_launcher.py -q` — 17 passed. The safety test invokes checkout-local `scripts/bbh`, isolates `--root` in a disposable directory, uses `--no-notify`, checks JSONL and provider readback and no notification file.
- `.venv/bin/python -m pytest tests -q` — 221 passed, 162 subtests passed, one unrelated existing failure in `tests/test_hoster_script_authority.py`: it expects `Hoster is execution-only by default` in unchanged `AGENTS.md`; the phrase is absent in base `HEAD:AGENTS.md`. No unrelated policy edit made. Excluding only that baseline failure with `-k 'not test_hoster_script_authority_uses_current_capability_not_machine_lists'` yields 221 passed, 1 deselected, 162 subtests passed.
- Checkout-local installed `bounty-core` direct URL metadata confirms commit `ce8718b6bfb39fb08533f506bd2bfe627b52e5da`; `scripts/bbh --print-command scripts/safety_incident.py` resolves this worktree.
- Independent review: not performed here; requested handoff is feature commit only, no merge/push.
- Integration diff and activation: not performed; selected runtime must reinstall after integration/pin change.

## Blockers and deferred work

- **Missing evidence:** clean full suite and independent integration review.
- **Command / fixture:** `.venv/bin/python -m pytest tests -q` after the owner resolves the existing AGENTS/test disagreement; then review feature diff against fresh `origin/beta`.
- **Trigger:** before any beta integration or activation.
- **Why:** existing unrelated suite failure precludes claiming a green full suite; activation must reinstall from manifest in the selected runtime.
- **Next completion step:** owner reviews branch and resolves baseline failure separately before integration.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/safety-incident-client`
- **Latest immutable recovery checkpoint:** pending task commit
- **Feature implementation commit(s):** pending task commit
- **Exact resume point:** review feature diff, reconcile current beta, resolve full-suite baseline failure, integrate only on authorization.
- **Working-tree state at handoff:** clean after task commit.

## Decision gates

- **Integration gate:** not claimed; baseline suite failure and independent review outstanding.
- **Activation / cohort gate:** selected checkout must reinstall pinned provider, then rerun CLI smoke with an explicit disposable root and `--no-notify`.
- **Promotion gate:** not requested or tested.

## Decision record

- 2026-10-15 — implemented feature-only forwarding and isolated no-delivery CLI verification; no merge/push or runtime activation.
