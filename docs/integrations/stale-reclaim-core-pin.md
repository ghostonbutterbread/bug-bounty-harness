# Published Core stale-reclaim repair integration dossier

- **Status:** review-ready
- **Owner:** BBH integration agent
- **Branch:** `fix/stale-reclaim-core-pin`
- **Base commit:** `2fe9eecbdd0a8b13ce4540eac2c72474aa72468c`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-01
- **Owning feature branch/ref:** `fix/stale-reclaim-core-pin`
- **Latest immutable recovery checkpoint:** `2fe9eecbdd0a8b13ce4540eac2c72474aa72468c`
- **Feature implementation commit(s):** recorded by the final branch tip
- **Inspiration / canonical references:** published Core `origin/beta` `fc361eca86f9c86acb357e1b9ce6426bc44aef83`; accepted stale-reclaim repair `2da1e22d381e6c8c4fad1b2bfdb21692ae398d04`.

## Intent

Make each BBH checkout install the independently published Bounty Core stale-reclaim repair from its exact immutable Core `beta` commit. Do not alter Core, policies, runtime activation, or the separately pending surface/app visibility design.

## Implemented contract

`requirements-bounty-core.txt` pins Bounty Core exactly to `fc361eca86f9c86acb357e1b9ce6426bc44aef83`. The runtime-dependency regression rejects the superseded `04b5149f617dafe7837726faec4d1bc5cf5471b6` pin and requires the published SHA. Operators install only into the selected BBH checkout with:

```bash
./setup.sh --install-python-deps
uv pip freeze --python .venv/bin/python | grep '^bounty-core @'
```

The installed direct URL must end in `@fc361eca86f9c86acb357e1b9ce6426bc44aef83`.

## Evidence and review

- Published Core receipt: `git ls-remote https://github.com/ghostonbutterbread/bounty-core.git refs/heads/beta` returns `fc361eca86f9c86acb357e1b9ce6426bc44aef83`.
- Test receipts: RED `PYTHONPATH=$PWD python3 -m unittest -v tests.test_runtime_dependencies` failed because the old manifest did not match `fc361...`; GREEN `PYTHONPATH=$PWD .venv/bin/python -m unittest -v tests.test_runtime_dependencies` passed (2 tests). Installed-environment suite `.venv/bin/python -m pytest -q tests/test_runtime_dependencies.py agents/test_map_store.py agents/test_hypothesis_ledger.py agents/test_leads_cli.py` passed (77 tests). Static checks `.venv/bin/python -m compileall -q agents tests`, `bash -n setup.sh`, and `git diff --check` passed.
- No-runtime gate: this branch does not change lane selection, shared launchers, services, timers, skill synchronization, or any active runtime checkout. Installation and activation remain operator-controlled.
- Merge/ancestry evidence: BBH base is `2fe9eecbdd0a8b13ce4540eac2c72474aa72468c`; target is `beta`.
- Reference-impact audit: the old SHA remains only in this dossier and the regression's rejection constant; the live launcher/operator documentation and runtime manifest use the published SHA.

## Blockers and deferred work

- **Missing test or evidence:** none for the dependency pin.
- **Command / fixture / environment needed:** a network-capable checkout-local `uv` install for final provenance verification.
- **Trigger to run it:** before beta integration and before any checkout is selected for runtime use.
- **Why it blocks integration, activation, or promotion:** it does not block code review; it is required installation evidence for a particular checkout.
- **Next completion step / successor reference:** the separately owned surface/app visibility design remains out of scope.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/stale-reclaim-core-pin`
- **Latest immutable recovery checkpoint:** `2fe9eecbdd0a8b13ce4540eac2c72474aa72468c`
- **Feature implementation commit(s):** inspect the current branch tip after this dossier's coherent commit.
- **Exact resume point:** inspect the branch tip, run the commands in Evidence and review, inspect the staged diff, and merge only through the clean `beta` worktree after explicit review.
- **Working-tree state at handoff:** clean after the final coherent commit.

## Decision gates

- **Integration gate:** exact manifest pin, regression, install provenance, required installed-environment suites, compile/diff checks, and staged-diff review pass.
- **Activation / cohort gate:** explicit operator selection of a BBH checkout and local setup rerun; no runtime action is authorized by this branch.
- **Promotion gate:** independent review and normal beta promotion policy.

## Decision record

- 2026-09-01 — created for the published Core stale-reclaim repair pin; Core and runtime changes explicitly excluded.
