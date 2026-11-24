# Scope gate exclusions integration dossier

- **Status:** review-ready
- **Owner:** Hermes (delegated bugfix subagent)
- **Branch:** `fix/scope-gate-exclusions`
- **Worktree:** `/home/ryushe/worktrees/bbh-fix-scope-gate-exclusions`
- **Base commit:** `643411a8ced41290c94c4a8ef1e509b0303d964b` (origin/beta; work
  started on `3f72ed81` and was fast-forwarded before the first commit)
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-24
- **Owning feature branch/ref:** `fix/scope-gate-exclusions`
- **Latest immutable recovery checkpoint:** `bfaf8851105c98706c1e3800556904409382ad11`
- **Feature implementation commit(s):** `bfaf8851105c98706c1e3800556904409382ad11`
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
- Non-claims: no change to request containment, redirects, `domains`/`urls`
  seeding in `scripts/program_init.py`, ScopeManager URL-allow port handling, or
  HarnessConstraints wildcard entries (recorded in BUGFIXES.md).

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
- Independent review: pending (parent-assigned).
- Merge/ancestry evidence: base `643411a8` is the fetched origin/beta tip at
  commit time.

## Blockers and deferred work

- None blocking integration. Deferred, recorded in BUGFIXES.md: start-port suite
  isolation; HarnessConstraints `*.` entries.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/scope-gate-exclusions`
- **Latest immutable recovery checkpoint:** `bfaf8851105c98706c1e3800556904409382ad11` (implementation, tests,
  BUGFIXES.md). The branch tip is a later dossier-only commit.
- **Feature implementation commit(s):** `bfaf8851105c98706c1e3800556904409382ad11`
- **Exact resume point:** independent review, then merge into a clean beta
  worktree and rerun the scope selection.
- **Working-tree state at handoff:** clean.

## Decision gates

- **Integration gate:** independent review of the implementation commit.
- **Activation / cohort gate:** none (library behavior).
- **Promotion gate:** normal beta → main promotion.

## Decision record

- 2026-11-24 — created; review-ready.
