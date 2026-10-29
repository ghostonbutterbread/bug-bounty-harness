# Recon-Ry scope handoff safety integration dossier

- **Status:** blocked; red regression checkpoint, not review-ready
- **Task / owner:** t_5647b0ee / delegated BBH subagent; parent PC-20261029-173518-f2809a3c
- **Branch:** `fix/recon-ry-scope-handoff-t5647b0ee`
- **Worktree:** `/home/ryushe/worktrees/bbh-recon-ry-scope-handoff`
- **Fetched base commit:** `52252b96c6d6eb9ebd44f81b9646e6be3ab4214b`
- **Intended integration target:** `origin/beta` (parent controls integration)
- **Last updated:** 2026-10-29
- **Latest immutable recovery checkpoint:** `620e321526b2fb2dcf63ef81e55198f3e7ae4493` (red test and dossier; verify later dossier-only commits separately)
- **Feature implementation commits:** none
- **References:** BBH `AGENTS.md`; local Recon-Ry `6777eea`, `docs/defensive-maintenance.md` lines 18–42; separate validator fix `fix/scope-path-normalization` is outside this branch.

## Intent and mode map

Stop the BBH wrapper from handing Recon-Ry scope that widens URL grants or drops URL denies, without falsely presenting host filtering as request-level enforcement. No real program data, target traffic, Hoster launch, validator changes, integration, push, or activation are authorized by this task.

- `start` defaults to `snap`; accepts arbitrary `--profile`. The wildcard-dependent `full`, `snap`, `subs`, `fast`, `urls` are checked for saved wildcards; `full`, `snap`, `subs`, `fast` suppress the explicit URL when wildcard seeds exist. `urls`, other named/custom profiles, and exact retain the explicit URL. Seeds and host filter are assembled for every profile; only `exact-urls` replaces seeds with the selected URL. Authenticated exact runs select `exact-urls-header`; other credentialed starts are refused.
- `queue` accepts only `exact-urls`, no credentials, validates each supplied root URL, strips ports on normalization, and calls Recon-Ry directly per host without the wrapper-generated scope files. Both single and queue use `validate_start_scope`, whose URL validator does not prove host-wide authorization.
- `status` and `ingest` are not recon launch modes; ingest may probe promoted URLs and was not run.
- Recon-Ry `full` and `exact-urls` include EyeWitness; `snap` and both exact profiles include parameter discovery. Stage configuration and actual installed Hoster version remain unverified.

## Evidence

- Synthetic offline red test: `/home/ryushe/projects/bug_bounty_harness/.venv/bin/python -m pytest -q tests/test_recon_ry_handoff_safety.py` → **1 failed** (expected: exact launch rejects a host with `/private` exclusion; observed: dry-run produces an exact launch for `/public` and stages only `*.example.test` as allow, omitting the deny). Test blocks socket creation and subprocess calls, isolates scope to `tmp_path`, and uses `example.test`; no target network or remote call occurred. The wrapper import resolved to this worktree; pytest/bounty_core came from the existing main checkout venv, whose dependency pin has not been validated for this worktree.
- `agents/recon_ry.py:301–304` throws away deferred denies; `agents/scope_seed_files.py:175–185` reduces root URLs to hosts. Queue normalization removes the submitted port.
- Local Recon-Ry `src/scope.sh:102–138` filters selected tool inputs, while `scope_filter.py:125–132` makes Katana's crawl regex host-only. Recon-Ry's own `docs/defensive-maintenance.md:33–42` states these mechanisms do not establish request-level containment for third-party crawlers, browser subresources, redirects or nested parameter tools. This is an explicit upstream release blocker, not evidence that all such traffic necessarily escapes. Its profile/config is local evidence only, not proof of Hoster's installed version.

## Blocker and deferred coverage

A host deny or removal from wildcard seed/input files does not prevent an allowed host's browser subresource, redirect, or nested tool from contacting the denied host. Conversely, removing every unrelated allowed host to eliminate that possibility would violate the requested preservation of safe host coverage and still would not prove egress containment. The BBH wrapper owns scope and handoff, not Recon-Ry stages/adapters or egress (BBH `AGENTS.md:14–38`). Thus the requested fail-closed property and compatible independent-host coverage cannot both be proven by a narrow BBH-only host-file change. Post-output filtering is not a remedy. Do not launch affected saved-scope programs under this candidate or claim this regression fixes them.

**Missing evidence:** isolated adapter/egress tests for enabled Recon-Ry profiles, including cross-host redirect and browser subresource attempts into a denied host and same-host disallowed scheme/port/path, plus nested parameter consumers and resumed input. **Environment:** disposable synthetic local fixtures, network disabled except explicitly isolated loopback fixtures; no real targets or Hoster. **Trigger:** owner authorizes a Recon-Ry-owned request-level confinement design or decides a narrower explicitly qualified handoff contract and which profiles can safely remain available. **Next step:** parent chooses that boundary, coordinates upstream Recon-Ry work if needed, then resumes BBH repair with TDD for mixed wildcards, deny classes, seeds, queue, exact, URL-only grants, host deny, CIDR, and overbroad allowance. Independent review, full offline tests, fetched-beta recheck, and parent-controlled integration remain pending.

## Interruption / decision gates

- **Resume:** inspect current branch tip, reproduce the red test, resolve the above request-level/compatibility blocker before production changes.
- **Integration / activation / promotion:** blocked; no implementation, review, deployment, or release claim.
- **Stable/descendant propagation:** not assessed; repair owner and affected descendants must be audited once the confinement boundary is decided. Repository instructions require each feature to start at fetched beta.
