# Recon-Ry staged wildcard roots repair

- **Status:** local security review passed; beta integration pending
- **Owner:** Hermes bugfix
- **Branch / owning ref:** `fix/papercut-recon-ry-all-roots`
- **Base commit:** `4e005929127d05785e704847bc80486cbd0c6297`
- **Intended integration target:** `beta`
- **Latest immutable recovery checkpoint:** `924c370` (saved-scope filter fix; later handoff-only commit updates parser help/dossier)
- **Feature implementation commit(s):** `4c72c9f`, `30970bd`, `93559a8`, `cf5a37d`, `e987f59`, `305ae9d`, `fed8921`, `924c370`
- **Inspiration:** `PC-20261006-231217-41f204eb`

## Intent and implemented contract

BBH still requires and validates `start --url` against saved scope, stages all eligible wildcard roots to `wild.txt` (excluding roots fully denied by wildcard exclusions), and passes the generated scope files. For **unauthenticated** enumeration profiles `full`, `subs`, `fast` with nonempty staged wildcard roots, omit `--url` **only from the core Recon-Ry command** so core's `subdomain_enum` consumes every staged root. If saved scope exists but no eligible wildcard root remains, wildcard-dependent profiles fail closed rather than enumerating from an exact seed URL. Preserve `--url` for exact-host and URL-only profiles and for explicitly approved runs without saved scope. Any `--auth`, `--auth-seed-file`, `--header`, or `--cookie` requires single-host `start --profile exact-urls`; credentialed `queue` requests are rejected because a shared seed would cross hosts. Exact-host mode stages only the requested URL. Subtree exclusions beneath an otherwise permitted root still depend on Recon-Ry's scope filters for tool inputs and promoted results; passive enumeration of the permitted parent may observe excluded descendants. No live recon or target writes performed.

## Evidence and review

- RED: Synthetic two-root dry-run test failed because the generated core command contained `--url first.example`, which core `src/stages.sh` prefers over `wild.txt`.
- GREEN before security follow-up: `python3 -m pytest -q agents/test_recon_ry.py agents/test_scope_seed_files.py` → 20 passed. Verifies multiple roots staged, scope files preserved, exact/URL-only profiles keep URL, and existing unscoped behavior.
- Independent review: first reviews found manual-header isolation and fully excluded wildcard-root staging gaps. A second found that an empty `wild.txt` still permits `full` to discover sibling hosts. A third found `queue` reused one auth seed across every queued host (and `queue --cookie` crashed). A fourth found that, when all saved wildcard roots are excluded, an exact-host `--url` still falls back to out-of-scope subdomain enumeration. The post-reconciliation release review found `--allow-unscoped` suppressed a saved exclusion filter while all wildcard roots were staged. Follow-ups reject credentialed non-exact `start`, all credentialed `queue` requests, wildcard-dependent starts without eligible roots, and any saved wildcard scope that cannot yield a host filter; `--allow-unscoped` never disables a saved filter. Each new synthetic regression was RED before its guard. Independent security re-review of `924c370` reproduced the old failure at `9ce7b69` and confirmed saved allow/deny filters, approved unsaved URL fallback, eligible and fully excluded roots, and credential guards. Focused suite: `python3 -m pytest -q agents/test_recon_ry.py agents/test_scope_seed_files.py tests/test_recon_ry_scope_files.py` → 69 passed, 1 skipped. Reviewer requested only handoff/parser-help corrections, made after the reviewed code checkpoint.
- Reference-impact audit: `skills/recon-ry/SKILL.md`, `prompts/recon-ry-playbook.md`, and the queue parser still advertised credentialed `urls` or shared-header queue behavior. Updated examples and help to the exact-host start contract; bounded repository search found no other credentialed wrapper command examples. Recheck after beta integration.
- Merge / ancestry evidence: pending.

## Blockers and deferred work

The accepted review applies to the tested local wrapper; exact-urls-header core profile filters are not a proven request-level egress guarantee for every third-party tool, so no claim of absolute host confinement or live activation is made. A **live Hoster run is not part of this task**. Before activation or any claim about real multi-root coverage, verify that the Hoster Recon-Ry checkout includes the all-roots and wildcard-root scope fixes already present in canonical `origin/main` (`b8c92fc`, `af4ea42`), then run a scoped authorized disposable or approved program smoke with staged roots. Do not claim runtime repair from local tests alone.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/papercut-recon-ry-all-roots`
- **Latest immutable recovery checkpoint:** `924c370` (saved-scope filter fix; later handoff-only commit updates parser help/dossier)
- **Feature implementation commit(s):** `4c72c9f`, `30970bd`, `93559a8`, `cf5a37d`, `e987f59`, `305ae9d`, `fed8921`, `924c370`
- **Exact resume point:** Fetch beta, verify final tip/ancestry and focused tests, then integrate from a clean beta checkout. Keep Hoster activation deferred.
- **Working-tree state at handoff:** clean after handoff/parser-help commit (checkpoint `924c370` is its parent).

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
- 2026-10-08 — Fourth review found an exact host became an enumeration root when all saved wildcards were excluded; a new gate rejects wildcard-dependent profiles without an eligible staged root in nonempty saved scope.
- 2026-10-08 — Independent re-review accepted the local wrapper fix; reference-impact audit found and corrected stale authenticated-`urls` guidance and queue help before integration.
- 2026-10-08 — Post-reconciliation release review blocked: `--allow-unscoped` suppressed saved scope and exclusions. Follow-up always stages usable saved host filters, and refuses wildcard-dependent runs when a nonempty saved scope cannot produce one.
