# XSS sink census expansion integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `feat/xss-sink-census-expansion`
- **Base commit:** `baf6065b9ce06033df3a4fb8f71f323e782694dc`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-05
- **Owning feature branch/ref:** `feat/xss-sink-census-expansion`
- **Latest immutable recovery checkpoint:** `5475d03ea08552f8dcb0c4dbf7b9b7b73a2f86a9` (approved implementation tip; final dossier-only decision follows)
- **Feature implementation commit(s):** `0a91d65`, `dd1580b`, `981e7a8`, `e12ba55`, `4a12fff`, `5475d03`
- **Inspiration / canonical references:** PortSwigger Academy and DOM Invader, CodeQL, Dalfox, Semgrep, XSStrike, OWASP, framework docs; details in `docs/xss-sink-inventory.md`.

## Intent

Expand BBH's existing `agents/js_analyzer.py` deterministic JS sink-farming vocabulary while preserving existing `sinks` labels and the non-exhaustive coverage contract. No live target testing, browser confirmation, or change to XSS finding statuses.

## Implemented contract

Static bundle inventory emits additional sorted category labels for HTML parsers, iframe srcdoc, event attributes, jQuery HTML/URL helpers and review candidates, framework raw HTML/trust bypass, script text/URL/import, and URL navigation. Output remains heuristic `exhaustive: false`; a detected name is not taint or execution proof. Historical six labels remain.

## Evidence and review

- Tests and commands: checkout-local `./setup.sh --install-python-deps`; after merging corrected and current local beta, `.venv/bin/python -m pytest agents/test_js_analyzer.py tests/test_script_policy.py -q` → 141 passed and `-k xss_sink_inventory` → 91 passed / 26 deselected; `git diff --check` clean. A prior test attempt timed out at 120s, then passed with a 360s timeout.
- Independent review: first reviewer findings (untyped jQuery/native DOM matches, unqualified `open`, overstated source-map coverage), second reviewer findings (`$.parseHTML`, qualified global eval, generic on-prefixed fields), third reviewer finding (equality reads counted as writes), and fourth reviewer findings (jQuery getters and receiver-agnostic attributes) were all addressed. Final independent reviewer approved implementation tip `5475d03` after 91 focused / 141 combined tests and setter/getter/assignment probes; no remaining actionable regression.
- Replay/cohort/fixture evidence: 91 parametrized positive/negative sink fixtures plus an exact empty-bucket regression for native DOM, getter calls, unrelated APIs and equality comparisons in `agents/test_js_analyzer.py`.
- Merge/ancestry evidence: fetched `origin/beta` at `baf6065b9ce06033df3a4fb8f71f323e782694dc` before branching, then reconciled `869929d8e147fa9b6f35b0fd89d2e57ed69ab769`. Separate Chromium index repair merged to local beta at `d5cd501fe99d1bb9fd11c278a9d0eb67b5f344f8`; corrected beta merged into this feature at `bd5571c6f00a19723c5bb1ecc3143dad17222fb5`. Later local beta guidance at `f04592918ad294c9cf8e272469d8bd202fa8e7b3` merged into feature at `64c26064f270a347a9bb843d97cbd9f09afcb36d`, no conflicts; combined 141 tests pass.

## Blockers and deferred work

The pre-existing Chromium index failure is resolved on local beta and the combined test suite is green. Remote beta still trails a clean local integration checkout with other task-owned commits; local integration must not be called publication or runtime activation. This static inventory does not claim runtime source-to-sink analysis or browser execution.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/xss-sink-census-expansion`
- **Latest immutable recovery checkpoint:** `5475d03ea08552f8dcb0c4dbf7b9b7b73a2f86a9` (approved implementation tip; final dossier-only decision follows)
- **Feature implementation commit(s):** `0a91d65`, `dd1580b`, `981e7a8`, `e12ba55`, `4a12fff`, `5475d03`
- **Exact resume point:** release-gate agent reruns tests on reviewed feature, merges into clean current local `beta`, retires this dossier from beta, verifies integrated checks and readback, then reports local/published/activated state separately. Do not push without explicit coordination for the nine unrelated local-beta commits.
- **Working-tree state at handoff:** clean after the final dossier-only decision commit.

## Decision gates

- **Integration gate:** combined tests, independent review, current-beta reconciliation and beta smoke.
- **Activation / cohort gate:** not in scope; do not claim runtime deployment from a beta merge.
- **Promotion gate:** stable/main requires separate owner direction.

## Decision record

- 2026-10-05 — created from current origin/beta for an offline sink-inventory expansion.
- 2026-10-05 — resolved separate Chromium index prerequisite on local beta, removed its stale BUGFIXES entry from this feature, and verified combined tests after reconciliation.
- 2026-10-05 — final independent review approved `5475d03` with 91 focused / 141 combined tests and no actionable signal-quality findings. Accept for local `beta` merge after release-gate rerun. Retire this dossier from beta in the integration operation; retain it in feature history. Explicitly deferred: remote publication and runtime activation (local beta includes nine other unpublished commits).
