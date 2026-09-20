# Artifact contract repair — integration dossier

- Status: implemented; independent review and beta integration pending.
- Owner/task: parent Hermes agent, `t_3697fb9c`.
- Worktree: `/home/ryushe/worktrees/bbh-artifact-contract`.
- Feature branch: `fix/artifact-contract`.
- Base and fetched target: `origin/beta` at
  `538342259157bd692e5c5ff6a4fe40ae039a4c57`.
- Intended integration target: `beta`, never main/stable.
- Implementation checkpoint: pending local commit (recorded in follow-up handoff).
- Publication, independent release review, integration and cleanup: parent-owned;
  this implementation subagent must not push or merge.

## Intent and boundary

Repair offline artifact typing at `agents/recon/promote_run.py`, not scanning
or discovery behavior. The historical Shared seed packet is background only;
the current task's bounded contract supersedes its broader proposals. No target
access, new offensive automation, scan coverage expansion, stored-data migration,
producer changes, runtime activation, or mutation of another checkout.

## Implemented contract

- Case-insensitive exact supported filenames replace substring/stem matching.
  Unknown names, backups and structured metadata are not inferred to be queues.
- `wild.txt` is scope-maintained wildcard roots, never discovery promotion.
  Existing explicit `append --kind wild` and scope/wildcard validation are untouched.
- `hosts.jsonl`, `httpx.jsonl`, `httpx_ip_raw.txt`, `waf_hosts.txt`, and
  `unprotected_hosts.txt` do not enter plain-text queues.
- Hostname inventory is independent of HTTP liveness; `alive.txt` retains its
  existing positive live-URL role. No liveness implementation changed.
- Parameters remain full HTTP(S) query URLs; raw takes precedence over the
  derived `params.txt` fallback. Bare names belong in separate mining artifacts.
- Port parsing remains JSON-aware. Existing `naabu.jsonl`/`ports.jsonl` and
  text port artifacts still go through the separate port parser.
- `dirs_status/` remains recursive, including historical status directories.
  A regression proved its bypass could admit the six explicitly excluded
  scope/metadata filenames, so only those names are excluded there too.
  Ordinary status results and the historical-content contract are unchanged.

## Producer and compatibility inspection

Inspected BBH `agents/recon_ry.py` artifact copying, `agents/url_ingest.py`
aliases, `agents/recon/asset_intelligence.py` known inputs, existing promotion,
port, mirror, watcher, wrapper and URL-ingest tests. Read the local Recon-Ry
`src/stages.sh`, `src/output.sh` and `src/tools.sh` artifact declarations as
producer evidence only; did not modify or run that tool.

Retain the existing `custom/url-output.txt` manifest fixture rather than silently
breaking it. Keep conventional exact `.txt` forms of existing classifier aliases,
plus supported `live-hosts.txt`, `url_seed.txt`, `javascript_urls.txt` and
`all_urls.txt`. Every mapped name was already classified to the same kind by the
old classifier; this repair only restricts admission. JSON input support is not
generalized beyond the established port filenames.

The durable inventory explanation is updated in
`skills/url-ingest/references/url-ingest-reference.md`. No skill main file,
policy, prompt, or scope append interface is changed.

## Verification evidence

Checkout environment provisioned using `./setup.sh --install-python-deps`.
Bounty Core resolved to the manifest's immutable revision
`201a47f7afff1db1b592f5d7126e7717d1feb171` in this checkout's `.venv`.
All test data is temporary and uses reserved example names; HTTP probe tests use
mocks. No live scan command was run.

RED/GREEN receipts:

1. Added `test_discovery_requires_supported_filenames_not_substrings` first.
   `.venv/bin/python -m pytest tests/test_recon_promote_run.py -q` against the
   original classifier: **1 failed, 7 passed** (unexpected artifact admission).
2. Exact mapping implementation: promotion + bus tests **31 passed**.
3. Additional compatibility regression first caught omitted supported aliases:
   **4 failed subtests, 11 passed, 23 subtests passed**. Added those exact aliases.
4. Added status-directory exclusion regression before its fix: **1 failed,
   11 passed, 27 subtests passed**, showing the status exception admitted all
   excluded files. Applied the same narrow exclusion at that exception.
5. Final focused offline command:

   ```sh
   .venv/bin/python -m pytest tests/test_recon_promote_run.py tests/test_recon_bus.py tests/test_recon_mirror.py tests/test_recon_watch_runs.py agents/test_recon_ry.py agents/test_url_ingest.py -q
   ```

   Result: **96 passed, 29 subtests passed**. `git diff --check`: clean.

The baseline is reachable at the base SHA above; new named regressions are
tracked in the feature branch for independent replay against baseline and fix.
Existing bus tests cover explicit wildcard append, rejection when wildcard scope
is not allowed, bare parameter-name rejection, raw/view regeneration, and JSON
port parsing. The new fixtures additionally cover case normalization, exact
suffix matching, every candidate directory/manifest route, preservation of an
existing wildcard store, and non-live hostname preservation.

## Activation, blockers and successor

No functional test blocker remains. Independent release review is deliberately
not claimed: parent must dispatch a fresh reviewer to this worktree, rerun the
focused command, and review the diff/dossier before publication or beta merge.
Fetch beta again at review/integration and reconcile if it moved. No live tests
are needed for this offline repair. No runtime deployment or data repair is
implied by a future merge. On accepted integration retire this branch-local
dossier per the repository lifecycle; the URL Ingest reference remains the
durable explanation.
