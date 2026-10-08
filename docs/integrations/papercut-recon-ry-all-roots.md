# Recon-Ry staged wildcard roots repair

- **Status:** review-ready
- **Owner:** Hermes bugfix
- **Branch / owning ref:** `fix/papercut-recon-ry-all-roots`
- **Base commit:** `4e005929127d05785e704847bc80486cbd0c6297`
- **Intended integration target:** `beta`
- **Latest immutable recovery checkpoint:** `4c72c9f` (initial implementation before security follow-up)
- **Feature implementation commit(s):** `4c72c9f` (security follow-up pending)
- **Inspiration:** `PC-20261006-231217-41f204eb`

## Intent and implemented contract

BBH still requires and validates `start --url` against saved scope, stages all wildcard roots to `wild.txt`, and passes the generated scope files. For enumeration profiles `full`, `subs`, `fast` with nonempty staged wildcard roots, omit `--url` **only from the core Recon-Ry command** so core's `subdomain_enum` consumes every staged root. Preserve `--url` for exact-host and URL-only profiles, unscoped/no-wildcard launches, and credential-isolated runs. No live recon or target writes performed.

## Evidence and review

- RED: Synthetic two-root dry-run test failed because the generated core command contained `--url first.example`, which core `src/stages.sh` prefers over `wild.txt`.
- GREEN: `python3 -m pytest -q agents/test_recon_ry.py agents/test_scope_seed_files.py` → 20 passed. Verifies all roots staged, scope files preserved, exact/URL-only profiles keep URL, and existing unscoped behavior.
- Independent review: initial review found a release-blocking manual-header isolation gap. Added `--header` to the credential-material gate and changed the synthetic two-root test to prove sibling seeds are not staged; focused suite 20 passed. Re-review of amended behavior pending.
- Merge / ancestry evidence: pending.

## Blockers and deferred work

Security re-review of header handling is required before beta integration. A **live Hoster run is not part of this task**. Before activation or any claim about real multi-root coverage, verify that the Hoster Recon-Ry checkout includes the all-roots and wildcard-root scope fixes already present in canonical `origin/main` (`b8c92fc`, `af4ea42`), then run a scoped authorized disposable or approved program smoke with staged roots. Do not claim runtime repair from local tests alone.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/papercut-recon-ry-all-roots`
- **Latest immutable recovery checkpoint:** `4c72c9f` (initial implementation before security follow-up)
- **Feature implementation commit(s):** `4c72c9f` (security follow-up pending)
- **Exact resume point:** Independently review amended header isolation including whether a full profile may still fan headers to discovered hosts, reconcile current beta and test before integration.
- **Working-tree state at handoff:** clean after committing this security follow-up and dossier.

## Decision gates

- **Integration gate:** tests green, independent review accepted, current beta reconciled.
- **Activation gate:** Hoster core version and approved scoped smoke above.
- **Promotion gate:** stable promotion separately authorized.

## Decision record

- 2026-10-08 — Reproduced one-root command precedence in synthetic dry-run; implemented wrapper-only invocation repair.
- 2026-10-08 — Initial reviewer found manual `--header` bypass of credential-isolation gate; follow-up gates headers and tests staged-seed isolation, pending re-review.
