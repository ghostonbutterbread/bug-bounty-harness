# Public HackerOne ATO disclosure premises — integration dossier

- **Status:** thirteen primary-report premises on feature branch; independent re-review accepted corrected implementation for beta integration. Corpus is not exhaustive.
- **Owner:** Hermes / Kanban `t_921f8fc5`
- **Owning feature branch/ref:** `docs/h1-ato-disclosures-20260929`
- **Worktree:** `/home/ryushe/projects/bug_bounty_harness/h1-ato-disclosures-20260929`
- **Base beta commit:** `8a64ae0441130694b9a7faffa65ed8801adf946b`
- **Target:** `beta` (not `main`)
- **Latest immutable recovery checkpoint:** `1ff4ad50e7918caafec9516d44fd2a8f5582cd56` (corrected implementation; dossier-only handoff commit follows)
- **Implementation commit(s):** `f743b186e8223da1881f1d03d2ff90e78f24450a`, `1ff4ad50e7918caafec9516d44fd2a8f5582cd56`

## Intent and source method

Add distinct, evidence-grounded ATO recognition questions from publicly disclosed HackerOne reports without replacing the existing app-observation-first router or limiting hypothesis coverage. Research only; no live target probes or account operations. Primary report text, not the report title, supports a claim. Report status and published claims are not independent validation of every asserted exploit step.

On 2026-09-30, public Hacktivity search `account takeover AND disclosed:true` displayed 642 matching items; six verified pages yielded 150 distinct report IDs before subsequent pages returned a site error. The separate `ATO AND disclosed:true` query displayed 25 items; combined browser-search IDs numbered 168 after deduplication. These are text-search hits, including unrelated XSS, site takeover, and speculative impact, not a complete ATO set. A third-party GitHub catalog (`ajaysenr/HackerOne-Disclosed-Reports`, README and `index.json` fetched by safe-fetch) contained 12,542 metadata rows, 9,839 marked full-content and 2,703 no-content; a deterministic title filter found 206 ATO-like rows (147 marked full, 59 no-content) and 667 rows across broader identity/auth terms. It is a **seed index, not the source of method claims**; its newest indexed disclosure was 2026-09-07 despite the README reporting an update on September 29, and it missed a directly verified September 24 HackerOne disclosure. Neither index, search term, report body availability, nor HackerOne's public search establishes exhaustive coverage of all disclosed ATO cases.

Thirteen canonical HackerOne report bodies were read through the public browser and selected for unique or sharpened mechanisms: #4000185, #1004536, #685007, #855618, #143717, #3178999, #3734676, #3723458, #910300, #1923672, #915110, #810880, #976603. Each added question must cite its canonical report and require owned-account final-state proof; do not reproduce raw tokens, personal data, target-specific payloads, or claims of universal vulnerability. Lower-quality/disclosed-but-informative/duplicate or title-only cases were not promoted as evidence. The public source index is `https://github.com/ajaysenr/HackerOne-Disclosed-Reports`, with canonical report URLs `https://hackerone.com/reports/<id>`; sanitized source receipt SHA256 for `index.json`: `463cd1a2a880b152fd4361c839c6f1bfa0818388cc2047e9c5fc40051b`. Temporary local derived seed set: `/home/ryushe/.hermes/cache/scratch/h1-ato-index-derived-20260930.json` (not a repo artifact).

## Implemented contract / decisions

The root idea map now routes conditional signup/passwordless, SCIM, cross-domain session handoff, mobile magic-link, and invite-as-login clues. Five existing topical references hold thirteen short case-backed questions in their owning flow; reset token and mobile-link mechanics remain under `/password-reset`. Token/OTP reuse is not, by itself, cross-account ATO; client-side success without server-side read-back is not proof. Disclosures are hypotheses conditional on observed app behavior, not a universal checklist. No numerical test cap or mandatory all-reference load was introduced.

## Evidence and review

- Existing reference IDs `[1]`–`[26]` were mechanically reconstructed from the live skill; canonical H1 report URLs assigned `[27]`–`[39]` in task ledger `/home/ryushe/.hermes/cache/scratch/h1-ato-sources-20260930.json`.
- Mechanical validation: all 39 IDs map consistently to one URL, with all 13 new report IDs cited and defined in the correct owner; root routes for four ATO references plus `/password-reset` resolve; `git diff --check` passed. `pytest -q tests/test_business_logic_skill.py tests/test_security_reporting_skill.py`: **3 passed, 24 subtests passed**, but those suites do **not** exercise these ATO reference claims; primary-report review plus citation/path and route assertions are the relevant validation. A broader command including `tests/test_skill_command_lane_safety.py` had one pre-existing unrelated failure on `docs/integrations/broad-goal-map-reconciliation.md:24`, a command line untouched by this feature. Strict `sources.py verify` on each modular reference warns about ledger IDs intentionally cited by *other* references, so the custom cross-reference check validates the shared 39-ID ledger without suppressing that tool warning.
- Independent reviewer verdict on implementation `f743b18`: **No integration yet.** Four blocking source-precondition corrections: Shopify legacy merge/eligibility, SSO DoS vs new/removed-member provisioning and existing-member Join, factor setup requiring known ID and no prior factor, and telemetry exposure vs attacker event-read prerequisite. One optional clarification distinguishes Mozilla's local-source code-replay PoC from a demonstrated victim-code theft. Corrected in implementation `1ff4ad50e7918caafec9516d44fd2a8f5582cd56`; fresh `git diff --check`, per-document citation mapping, route and qualification assertions passed, and focused `pytest` returned 3 passed/24 subtests. The required fresh verdict is recorded below.
- Fresh independent re-review of `8a64ae0..1ff4ad5`: **Yes, safe to take through the beta gate.** All four original report-precondition blockers and the optional OAuth qualification resolved; all thirteen primary report claims and 39 source mappings checked, `git diff --check` and focused pytest passed. Reviewer found the same pre-existing lane-safety failure on a file unchanged at the base commit. The reviewer performed no merge/push.
- Pending: current-beta merge excluding this dossier, post-merge focused checks, push and remote readback, active skill projection.

## Blockers and deferred work

Exhaustive review of every disclosed HackerOne ATO report is **not proven**: public search paginated only six pages of a 642-hit text query before server errors; a third-party catalog has 2,703 no-content rows and a freshness gap. Do not claim a full-platform census or infer mechanisms from inaccessible/title-only reports. This limits corpus coverage, not the ability to add the thirteen verified source-backed patterns. A future refresh should prefer an authorized complete export or a reliable public index with verifiable coverage.

Two follow-up 28-report shards were checked against their input IDs: eight canonical bodies were readable and yielded no distinct new premise, while 48 were inaccessible after HackerOne Cloudflare Error 1015. An archive listing for one blocked report existed, but archive retrieval returned 429; no alternate relay or bypass was used. Three further 25–28-report shards remain unexamined; pause direct public requests during rate limiting rather than declaring a title-only census. A separate directly verified pending-session SMS report (#1245762) is a follow-up candidate, not part of the accepted thirteen-case implementation.

## Interruption / resume handoff

- **Branch/ref:** `docs/h1-ato-disclosures-20260929`, base `8a64ae0441130694b9a7faffa65ed8801adf946b`, target `beta`.
- **Checkpoint:** corrected implementation commit `1ff4ad50e7918caafec9516d44fd2a8f5582cd56` (verify its ancestry and the later dossier-only branch tip).
- **Exact next action:** merge only the reviewed implementation into the clean beta integration worktree (exclude this dossier); run post-merge checks, push/read back beta, verify active projection. Continue the separate, rate-aware public report research later; do not claim every disclosed report reviewed.
- **Working tree:** dossier-only handoff to be committed separately; do not merge this branch-local file into beta.
