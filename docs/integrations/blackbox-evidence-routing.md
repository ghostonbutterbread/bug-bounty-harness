# Black-box evidence routing integration dossier

- **Status:** feature
- **Owner:** Hermes Agent
- **Branch:** `feat/blackbox-evidence-routing`
- **Base commit:** `7e2efe78d651ff1041c762724121e50c0065d983`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-02
- **Owning feature branch/ref:** `feat/blackbox-evidence-routing`
- **Latest immutable recovery checkpoint:** `3192862bbbbcbe2f79c6ee12b3cbc86a2c6baf83`
- **Feature implementation commit(s):** `9dbbe1933438567ca5333a26386e5460a4aacb0a`, `934d20e84184a76941ca78456613ad453b5267b8`, `b5c63962ac3118f9ae24a63d0aa004acbe4a6d11`, `2644bc47f70fc68bf589751c240e857bf9915986`, `008da96dd007b29aa016f3093c8256080deef811`, `33e0a866f28ca0392ce4a26ef3485b29e484db08`, `2b8030ce2c76407fdb1f6babb9a8f661d1eaa132`, `3192862bbbbcbe2f79c6ee12b3cbc86a2c6baf83`
- **Inspiration / canonical references:** `Shared/skill_seeds/2026-09-01-current-run-provenance-slices.md`; `Shared/skill_seeds/2026-09-01-lead-scoped-hypothesis-context.md`; published Bounty Core `04b5149f617dafe7837726faec4d1bc5cf5471b6`; accepted AI Policies `9f84af0c14c4d7f594107e7416675a64df2d8a81`

## Intent

Add a bounded current-run provenance slice to shared MapStore facts so an active agent can recover only observations it authored in its current run without replacing normal shared factual queries or reading private peer hypotheses.

## Implemented contract

- `MapStore.query()` accepts additive exact `agent_id` and `run_id` filters.
- `map_store.py query` exposes those filters as `--agent-id` and `--run-id`.
- The filters compose with existing URL, surface, tag, status, time, limit, intent, and archived-state behavior; returned entries remain deterministically newest first.
- MapStore provenance remains factual and shared. This does not create a private MapStore store, a filesystem scan fallback, a broad historical preload, or any Hypothesis Ledger visibility bypass.
- BBH accepts an opaque `--lead-id` at creation, owner-only `release`, and explicit `lead-followup --lead-id` retrieval. Ordinary `list` remains owner/run private; the wrapper validates the exact public Lead card before Core retrieval and does not expose a broad peer queue.
- `leads.py create` retains legacy absolute-path stdout by default and emits the portable MapStore-relative Lead ID with `--relative-id`; `lead-followup` and `update-status` accept either exact form. Lead follow-up validates one public card, queries Core with both canonical forms, and deduplicates eligible context so existing absolute links and portable relative links interoperate; arbitrary, unrelated, or nonexistent IDs fail before Ledger retrieval.

## Evidence and review

- Tests and commands:
  - `PYTHONPATH=. uv run --python .venv/bin/python --with pytest python -m pytest tests/test_runtime_dependencies.py agents/test_map_store.py agents/test_hypothesis_ledger.py agents/test_leads_cli.py -q` — 77 passed with the installed manifest pin.
  - `./setup.sh --install-python-deps` — installed `bounty-core @ git+https://github.com/ghostonbutterbread/bounty-core.git@04b5149f617dafe7837726faec4d1bc5cf5471b6` into the checkout-local `.venv`; `uv pip freeze --python .venv/bin/python` verified the exact revision.
  - `bash -n setup.sh` and `git diff --check` — passed.
- Independent review: Core `5089b10` accepted and is reachable through published Core `beta` revision `04b5149f617dafe7837726faec4d1bc5cf5471b6`. BBH re-review accepted the implementation conditionally: it confirmed alias ordering/privacy/provenance behavior and required this portable pin/receipt before beta integration. Fresh final review remains required after this pin checkpoint.
- Replay/cohort/fixture evidence: real temporary shared-storage fixture; no target activity.
- Merge/ancestry evidence: Core `origin/beta` at `04b5149f617dafe7837726faec4d1bc5cf5471b6` contains accepted `5089b10`; BBH beta merge remains pending.

## Blockers and deferred work

- **Missing test or evidence:** Fresh independent BBH review of this immutable-pin checkpoint, then clean beta merge verification.
- **Command / fixture / environment needed:** Checkout-local `.venv` after `./setup.sh --install-python-deps` with the manifest pin.
- **Trigger to run it:** now; do not merge until review accepts the pin/portable dossier receipt.
- **Why it blocks integration, activation, or promotion:** the manifest pin and receipt affect BBH's runtime dependency contract and must be independently reviewed.
- **Next completion step / successor reference:** accept final BBH review, merge into clean current `beta`, rerun the isolated suite from beta, and retain runtime activation as a separate decision.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/blackbox-evidence-routing`
- **Latest immutable recovery checkpoint:** `3192862bbbbcbe2f79c6ee12b3cbc86a2c6baf83`
- **Feature implementation commit(s):** `9dbbe1933438567ca5333a26386e5460a4aacb0a`, `934d20e84184a76941ca78456613ad453b5267b8`, `b5c63962ac3118f9ae24a63d0aa004acbe4a6d11`, `2644bc47f70fc68bf589751c240e857bf9915986`, `008da96dd007b29aa016f3093c8256080deef811`, `33e0a866f28ca0392ce4a26ef3485b29e484db08`, `2b8030ce2c76407fdb1f6babb9a8f661d1eaa132`, `3192862bbbbcbe2f79c6ee12b3cbc86a2c6baf83`
- **Exact resume point:** obtain final BBH review of immutable Core pin `04b5149f617dafe7837726faec4d1bc5cf5471b6` and this portable receipt; then merge into clean beta and rerun the beta suite.
- **Working-tree state at handoff:** immutable pin is committed at `3192862`; this dossier update is the final review handoff.

## Decision gates

- **Integration gate:** feature code is committed, full affected suites pass in an isolated environment, explicit Core revision is selected, and independent review reconciles dossier/diff/test receipts.
- **Activation / cohort gate:** no runtime activation in this slice.
- **Promotion gate:** merge only into clean current `beta` through normal reviewed branch lifecycle; never directly into `main`.

## Decision record

- 2026-09-02 — created with current-run MapStore provenance query and CLI contract; 67 focused MapStore tests passed.
