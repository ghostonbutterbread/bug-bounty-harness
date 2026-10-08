# Recon-Ry staged wildcard roots repair

- **Status:** review-ready
- **Owner:** Hermes bugfix
- **Branch / owning ref:** `fix/papercut-recon-ry-all-roots`
- **Base commit:** `4e005929127d05785e704847bc80486cbd0c6297`
- **Intended integration target:** `beta`
- **Latest immutable recovery checkpoint:** `cf5a37d` (start credential gate; queue follow-up pending)
- **Feature implementation commit(s):** `4c72c9f`, `30970bd`, `93559a8`, `cf5a37d` (queue follow-up pending)
- **Inspiration:** `PC-20261006-231217-41f204eb`

## Intent and implemented contract

BBH still requires and validates `start --url` against saved scope, stages all eligible wildcard roots to `wild.txt` (excluding roots fully denied by wildcard exclusions), and passes the generated scope files. For **unauthenticated** enumeration profiles `full`, `subs`, `fast` with nonempty staged wildcard roots, omit `--url` **only from the core Recon-Ry command** so core's `subdomain_enum` consumes every staged root. Preserve `--url` for exact-host and URL-only profiles and unscoped/no-wildcard launches. Any `--auth`, `--auth-seed-file`, `--header`, or `--cookie` requires `--profile exact-urls`: full and other profiles can discover sibling hosts and forward manual headers there, even when their initial `wild.txt` is empty. Exact-host mode stages only the requested URL. Subtree exclusions beneath an otherwise permitted root still depend on Recon-Ry's scope filters for tool inputs and promoted results; passive enumeration of the permitted parent may observe excluded descendants. No live recon or target writes performed.

## Evidence and review

- RED: Synthetic two-root dry-run test failed because the generated core command contained `--url first.example`, which core `src/stages.sh` prefers over `wild.txt`.
- GREEN before security follow-up: `python3 -m pytest -q agents/test_recon_ry.py agents/test_scope_seed_files.py` → 20 passed. Verifies multiple roots staged, scope files preserved, exact/URL-only profiles keep URL, and existing unscoped behavior.
- Independent review: initial review found release-blocking manual-header isolation and fully excluded wildcard-root staging gaps. A second review found that emptied `wild.txt` still permits `full` to discover sibling hosts, and `RECON_RY_AUTH_HOST` does not gate manual headers. A third review found the `queue` command reused one auth seed across every queued host, and `queue --cookie` crashed because it had no `args.url`. Follow-ups now reject credentialed non-exact `start` and all credentialed `queue` invocations before auth resolution or remote staging; unauthenticated queue still works. The new synthetic regressions were RED before their guards, then the focused suite was GREEN: `python3 -m pytest -q agents/test_recon_ry.py agents/test_scope_seed_files.py tests/test_recon_ry_scope_files.py` → 59 passed, 1 skipped. Further independent re-review pending.
- Merge / ancestry evidence: pending.

## Blockers and deferred work

Security re-review of both `start` and `queue` credential gates and excluded-root handling is required before beta integration. The exact-urls-header core profile applies exact-host filters, but these are not a proven request-level egress guarantee for every third-party tool, so no claim of absolute host confinement or live activation is made. A **live Hoster run is not part of this task**. Before activation or any claim about real multi-root coverage, verify that the Hoster Recon-Ry checkout includes the all-roots and wildcard-root scope fixes already present in canonical `origin/main` (`b8c92fc`, `af4ea42`), then run a scoped authorized disposable or approved program smoke with staged roots. Do not claim runtime repair from local tests alone.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/papercut-recon-ry-all-roots`
- **Latest immutable recovery checkpoint:** `cf5a37d` (start credential gate; queue follow-up pending)
- **Feature implementation commit(s):** `4c72c9f`, `30970bd`, `93559a8`, `cf5a37d` (queue follow-up pending)
- **Exact resume point:** Independently re-review `start` and `queue` credential guards, reconcile current beta and test before integration.
- **Working-tree state at handoff:** clean after follow-up commit.

## Decision gates

- **Integration gate:** tests green, independent review accepted, current beta reconciled.
- **Activation gate:** Hoster core version and approved scoped smoke above.
- **Promotion gate:** stable promotion separately authorized.

## Decision record

- 2026-10-08 — Reproduced one-root command precedence in synthetic dry-run; implemented wrapper-only invocation repair.
- 2026-10-08 — Initial reviewer found manual `--header` bypass of credential-isolation gate; follow-up gates headers and tests staged-seed isolation, pending re-review.
- 2026-10-08 — Reviewer also found fully excluded wildcard roots would still be enumerated; follow-up prevents such roots from entering `wild.txt` and adds a dry-run regression.
- 2026-10-08 — Security re-review showed seed-only isolation is insufficient: full profile discovers sibling hosts and forwards manual headers. Credentialed launches now require exact-urls, with synthetic coverage for every wider profile and credential input.
- 2026-10-08 — Third review found queue reused a credential seed across hosts and `queue --cookie` crashed; all credentialed queue invocations now fail closed with a single-host start alternative.
