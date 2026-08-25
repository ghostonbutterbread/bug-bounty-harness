# Parameterized URL corpus contract — Integration Dossier

- **Task / branch:** `t_ae3bacbd` / `fix/params-url-contract`
- **Base / target:** `601f87b` / `beta`

## Intent

Restore the Recon Bus contract after parameter-mining observations contaminated
SoundCloud's parameterized URL aggregates: `params_raw.txt` holds full HTTP(S)
URLs with query strings and `params.txt` is only its URO-normalized derived URL
queue. Parameter-name observations remain in `recon/parameter_mining` artifacts,
not in either queue.

## Implemented contract

- Reject `recon_bus append --kind param` inputs that are not full parameterized
  HTTP(S) URLs before any aggregate mutation.
- Filter the URO input defensively, so legacy non-URL rows cannot re-enter the
  derived queue.
- Add `recon_bus repair-params <program>` to retain valid existing URL evidence,
  quarantine any legacy non-URL rows outside the queue, regenerate `params.txt`,
  and refresh generated mirrors.

## Evidence

- `uv run --python 3.11 pytest -q tests/test_recon_bus.py tests/test_recon_promote_run.py tests/test_recon_mirror.py` — 34 passed.
- `python3 scripts/recon_bus.py repair-params soundcloud` retained 73,567
  parameterized URLs and regenerated `aggregated/params.txt` with URO. The
  current repair found no remaining non-URL rows to quarantine.
- `python3 scripts/recon_bus.py verify soundcloud` — no mirror drift.

## Activation boundary

The SoundCloud derived views were regenerated through Recon Bus. No live probes,
runtime deployment, or skill synchronization was performed.

## Deferred

Existing parameter-name observations are retained only in their parameter-mining
artifacts; this change does not infer source attribution or create replacement
observations from legacy queue rows.
