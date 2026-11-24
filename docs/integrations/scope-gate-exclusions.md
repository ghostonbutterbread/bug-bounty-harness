# Scope gate exclusions integration dossier

- **Status:** review loop 2 applied; narrow re-review pending
- **Owner:** Hermes (delegated bugfix subagent)
- **Branch:** `fix/scope-gate-exclusions`
- **Worktree:** `/home/ryushe/worktrees/bbh-fix-scope-gate-exclusions`
- **Base commit:** `643411a8ced41290c94c4a8ef1e509b0303d964b` (origin/beta; work
  started on `3f72ed81` and was fast-forwarded before the first commit)
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-24
- **Owning feature branch/ref:** `fix/scope-gate-exclusions`
- **Latest immutable recovery checkpoint:** `71104206fedf11ab818f6e96bab3349b3aa56e9a`
  (loop-2 fixes). origin/beta `243a97bd` merged at `a0263a3f`; origin/beta
  `b3c6aced` merged at `6f192797` (append-only BUGFIXES.md conflict, both sides
  kept; no scope/fuzz files changed; focused set 417 passed on the merged tree)
- **Feature implementation commit(s):** `bfaf8851105c98706c1e3800556904409382ad11`,
  `7bba01fe11a45e5c2d0ac8491feae7c54e7778f3`, `71104206fedf11ab818f6e96bab3349b3aa56e9a`
- **Inspiration / canonical references:** BUGFIXES.md entries "ScopeManager does
  not load explicit exclusions", "urlparse accepts a backslash-userinfo host that
  Go tooling rejects", "Suffix scope checks outside the subdomain agent use
  unparsed hosts".

## Intent

No BBH host gate may judge an explicitly excluded or ambiguously spelled
authority in scope. Reuse ScopeValidator's parser and exclusion loader rather
than adding another parser. Allow semantics of each gate stay unchanged.

## Implemented contract

- `ScopeManager.is_in_scope`: host via `scope_validator._extract_host` (empty →
  refuse); refuses whatever an internal `ScopeValidator` (same canonical and
  legacy roots) reports `is_out_of_scope`; allow entries compared via
  `_safe_host`. `domains`/`urls` and allow files unchanged. Construction now
  raises `ScopeFileReadError` subclasses for unreadable/unparsable scope files.
- `ScopeValidator.__init__`: optional `legacy_recon_base` (default unchanged).
- `HarnessConstraints.is_in_scope`: http(s) only, port 80/443 only (as before),
  strict host, `_safe_host` domain entries; scope-module import failure
  propagates.
- `asset_intelligence.scope_matches`/`classify_scope`: labels via new
  `scope_host` (strict parser; bare values read as an http authority; `*.`
  values by base). Labels only; no requests.
- Loop 1 (`7bba01fe`): `run_campaign.run_fuzz` passes the campaign's recorded
  `program_config.program` to `FuzzAgent`, so ScopeValidator (with exclusions)
  checks each fuzz target; no valid program → exit 1 before building the agent;
  `FuzzAgent` without a program raises `ValueError` instead of allowing all.
  HarnessConstraints and asset labels compare schemes case-insensitively.
  Unparseable URL/domain-shaped asset values are labelled out-of-scope when
  exclusions exist (entity names/fingerprints keep prior labels).
  `program_init.main` reports unreadable scope files (`OSError`) as `error:` +
  hint, exit 2.
- Loop 2 (`71104206`): `FuzzAgent._run_target` admits a wordlist entry only if
  its concrete URL (`<target path>/<entry>`) passes the program's ScopeValidator
  (allows and exclusions; path exclusions case-insensitive), checked lazily up
  to the batch size; nothing admitted → `[SKIP]` message, no ffuf call. The ffuf
  `-u` template and finding URLs come from the target's path with
  query/fragment dropped. `FuzzAgent.run` raises on an empty saved scope
  (run_fuzz exits 1). run_fuzz hint suggests a new campaign id (`--force`
  resets state); program_init OSError message covers scope fetch and writes.
- Exactly what is gated in fuzzing: the target (ScopeValidator + HarnessConstraints
  domain/rate/budget) and every URL BBH hands to ffuf (ScopeValidator). Not
  gated: anything ffuf does after sending, notably `-r` redirect following.
- Non-claims: no change to request containment, redirects, or `domains`/`urls`
  seeding in `scripts/program_init.py`. Open BUGFIXES.md entries: ffuf redirect
  following not contained; asset-label URL-path exclusion spellings and exotic
  host spellings (labels only); ScopeManager URL allows ignore the port;
  ScopeManager mixes canonical and legacy allow files; HarnessConstraints `*.`
  entries never match; ScopeValidator accepts only lowercase http(s) schemes.

## Evidence and review

- Tests and commands: `PYTHONPATH=<wt>:<wt>/agents .venv/bin/python -m pytest
  -q -p no:cacheprovider --basetemp=<scratch> tests/test_scope_gate_exclusions.py`
  → 107 passed on branch; the same file on unchanged base → 68 failed / 39 passed.
  Combined scope selection (21 modules: tests/test_scope_*.py,
  agents/test_scope*.py, tests/test_subdomain*.py, recon asset/Recon-Ry/bus,
  url_ingest, bypass scope, program_init, portable imports): base `643411a8`
  264 failed / 1755 passed; branch 264 failed / 1862 passed. Failure sets are
  identical: all 264 are `tests/test_recon_ry_start_ports.py`
  `KeyError: 'scope_validator'`, a pre-existing test-isolation defect recorded
  in BUGFIXES.md (the file alone passes 608).
- Loop 1 tests: `tests/test_scope_gate_exclusions.py` 114 passed (6 fail on
  pre-loop tip `a0263a3f`); 21-module selection base `243a97bd` 264 failed /
  1755 passed, branch 264 failed / 1869 passed, identical failure sets.
- Independent review of `2e49e44a`: BLOCK (documentation only: false
  fuzz_runner claim hid the no-program fuzz path). Loop 1 applied in `7bba01fe`.
- Narrow re-review of `a0263a3f..7bba01fe`: BLOCK (path exclusions and
  query/fragment templates still reached ffuf; wording overclaimed). Loop 2
  applied in `71104206`; narrow re-review of `5cb9eb19..71104206` pending.
- Loop 2 tests (ffuf stubbed, no network): `tests/test_scope_gate_exclusions.py`
  120 passed (6 fail on pre-loop-2 tip `5cb9eb19`). Focused set (new file +
  test_scope_import_safety, test_program_init, agents/test_recon_asset_intelligence,
  agents/test_scope_validator): base `243a97bd` 297 passed; branch 417 passed.
  21-module selection: base `243a97bd` 264 failed / 1755 passed; branch 264
  failed / 1875 passed; failure sets identical (start-port isolation only).
- Expected conflict: blocked sibling t_4e62917b redesigns the same
  `run_campaign.py`/`fuzz_runner.py` path.
- Merge/ancestry evidence: base `643411a8` is the fetched origin/beta tip at
  commit time.

## Blockers and deferred work

- None blocking integration. Deferred, recorded in BUGFIXES.md: start-port suite
  isolation; HarnessConstraints `*.` entries; ffuf `-r` redirect containment;
  ScopeManager port/legacy-allow disagreements; asset-label spellings;
  lowercase-only schemes in ScopeValidator.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/scope-gate-exclusions`
- **Latest immutable recovery checkpoint:** `71104206fedf11ab818f6e96bab3349b3aa56e9a`
  (loop-2 fixes and tests). The branch tip is a later dossier-only commit.
- **Feature implementation commit(s):** `bfaf8851105c98706c1e3800556904409382ad11`,
  `7bba01fe11a45e5c2d0ac8491feae7c54e7778f3`, `71104206fedf11ab818f6e96bab3349b3aa56e9a`
- **Exact resume point:** narrow re-review of `5cb9eb19..71104206`, then merge
  into a clean beta worktree and rerun the scope selection.
- **Working-tree state at handoff:** clean.

## Decision gates

- **Integration gate:** independent review of the implementation commit.
- **Activation / cohort gate:** none (library behavior).
- **Promotion gate:** normal beta → main promotion.

## Decision record

- 2026-11-24 — created; review-ready.
- 2026-11-24 — independent review BLOCK (docs); loop 1 `7bba01fe` applied.
- 2026-11-24 — narrow re-review BLOCK (per-URL fuzz gating); loop 2 `71104206` applied.
