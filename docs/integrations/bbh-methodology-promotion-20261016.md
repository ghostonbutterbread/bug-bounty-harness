# BBH methodology promotion — branch-local dossier

- **Status:** production changes reviewed and published to BBH `beta`; Ghost
  consumer smoke passed, Hoster source/projections verified; fresh Hoster-agent
  load remains unavailable on its current CLI runtime.
- **Owner:** Hermes / task `t_f4a4869b`
- **Feature branch:** `feat/bbh-methodology-promotion-20261016`
- **Base:** `288e88e17331618438681caf946d7c7e2cc19d2b`
- **Production commits:** `e9d90f0dbe355796d563c5a8393d0f48e69fefe4`,
  `646adb4c9fb15db4a5b978dd11dbb96b32dbc8d8`
- **Selected beta source and published remote ref:**
  `646adb4c9fb15db4a5b978dd11dbb96b32dbc8d8`
- **Last updated:** 2026-10-16 (PDT)

## Owner map and before/after

- **Observed capability mapping:** formerly an active Ghost-local mapper;
  `/live-map` now conditionally promotes a concrete, observed capability
  through `/map-store` into a named Application Behavior. Runtime route JSONL,
  URL facts, behavior facts, private hypotheses, and Leads remain distinct.
- **Scanner startup:** formerly an active Ghost-local skill; `/bounty-tools`
  now preflights real executable, scoped input, rates and first useful signal,
  with XSS source/sink proof qualified separately. It does not claim a
  synchronous `tool-run` exposes mid-run status.
- **Paid-program selection:** formerly an active Ghost-local `program-finder`;
  BBH now has `/program-finder` for public, source-backed shortlists before a
  target is chosen. A shortlist neither supplies scope nor authorizes testing.
  The BountyLens registry example now uses an allowed public programs read.
- **Write-up synthesis:** formerly an active Ghost-local skill; an on-demand
  functionality-first reference under `/research-knowledge-management` now
  separates readable cases, snippets, target facts, and specialist questions.
- **Recon automation:** formerly an active Ghost-local sketch; BBH keeps only
  a **proposed/offline-review-only** maintenance design reference under
  `/bounty-tools`. No persistent queue, cron, scanner, worker, or live
  qualification was implemented or activated.

The five complete superseded Ghost-local directories were preserved under
`~/.hermes/archived-skills/2026-10-17-bbh-methodology-promotion/`; no
source copy was discarded as byte-identical. The earlier `error-intelligence`
and `program-severity-scoring` duplicate archive remains separate.

## Tests, review, and publication

- Three owner-specific read-only semantic comparisons: `deleg_a7022d57`.
- Initial independent exact-tree review (`deleg_291bcf30`) returned two
  NO-GO examples: a MapStore observation path that could not exist and a
  forbidden BountyLens sessions read. Both were corrected and gained CLI or
  registry regression checks. Independent fix re-review (`deleg_e1fc3674`)
  returned GO for the exact production tree at `646adb4`.
- Feature and clean beta-integration checkouts each passed the selected
  offline suite: **411 tests, 186 subtests**. The MapStore CLI example now
  writes an observation, derives its actual MapStore-relative path, and uses
  that path in Behavior creation; no live target or BountyLens API request.
- `git diff --check` passed. The feature-only dossier is not on beta.
- The feature branch and beta were pushed; `git ls-remote` read back beta at
  `646adb4`. Aiskillsync's configured Ghost beta checkout is clean at this
  ref. No unrelated checkout commits were pushed.

## Consumer projection and limits

- Ghost security profile: four new `/program-finder` links; existing owner
  links resolve to the reviewed beta checkout. Bounty profile: new
  `/program-finder` and previously missing `/program-severity-scoring` links.
  Focused repeat dry-runs were no-ops; source/reference readback and fresh
  default and bounty one-shot loads succeeded. Complete local prototype trees
  were moved to the archive after this verification.
- Hoster security profile: configured clean beta source fast-forwarded to
  `646adb4`; five new `/program-finder` links (Hermes, Claude, Codex,
  OpenCode, Pi). The seven checked owner links and two new packaged references
  resolve to the intended checkout; six sampled file hashes match Ghost's
  reviewed beta source. Focused repeat dry-run was a no-op, and the Hoster
  checkout ran four static methodology tests successfully.
- **Unverified:** Hoster fresh *agent* load. Its noninteractive SSH PATH did
  not expose `hermes`, `pi`, or `claude` and Node reported v18.19.1; source,
  symlink, and static-test receipts are not an agent-consumer smoke. Do not
  restart an existing Hoster workspace merely to demonstrate it.
- Hoster entry cleanup sidecar `deleg_930baed4`: inspect-only success,
  0 scopes inspected, 0 stopped, 0 retained; `--apply` was not run. The
  synced helper's read-only receipt was independently checked and contained
  `{"apply":false,"scopes":[],"stopped":[]}`.

## Decision gates

No promotion to `main`, activation of a recurring recon worker, live-target
probe, or restart of an existing agent was requested or performed. Current
sessions may retain prior skill text; new Ghost sessions loaded the reviewed
source. Preserve the Hoster fresh-agent-load gap until its runtime is usable.
