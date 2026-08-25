# Parameterized URL corpus repair dossier

- **Status:** implementation complete; awaiting review
- **Owner:** BBH
- **Branch:** `fix/params-url-contract`
- **Base:** `601f87bfad10adf287326095f9ce0ffd1161355d`
- **Target:** `beta`

## Contract

`aggregated/params_raw.txt` and its derived `params.txt` are URL queues. They
accept only full HTTP(S) URLs with a non-empty query string; bare parameter-name
observations belong in source-attributed `parameter_mining` artifacts instead.

Recon Bus now rejects an invalid `--kind param` batch before writing it. Its URO
normalization also filters non-URL values defensively. The new
`recon_bus.py repair-params <program>` command repairs a historical aggregate:
it retains valid parameterized URLs, writes rejected legacy values to the
program's labelled quarantine artifact, regenerates `params.txt`, and refreshes
the derived mirrors.

## Evidence

- Focused Recon Bus/promotion/mirror suite: `python3 -m unittest tests.test_recon_bus tests.test_recon_promote_run tests.test_recon_mirror` — 34 passed.
- Full standalone suite: `.venv/bin/python -m unittest discover -s tests` — 51 passed.
- SoundCloud repair: 73,567 valid parameterized URLs retained from
  `params_raw.txt`; 2,645 bare values quarantined; regenerated `params.txt`
  contains 3,092 valid parameterized URLs and no bare names.

## Activation

Merge into `beta`, then run the repair command for any aggregate known to have
been written by the affected parameter-mining flow. New bare-name attempts fail
closed with an explicit routing message.

## Deferred

Existing parameter-mining run artifacts remain the source-attributed evidence
for the quarantined observations. No bulk migration of every program was run;
repair only programs with confirmed contamination.
