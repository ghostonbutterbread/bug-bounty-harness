# Strict in-scope contract integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `bug-bounty-harness/t_01b3406c-make-pulled-in-scope-scope-files`
- **Base commit:** `951b7426a885bcf17dc2f72218d791d7f0653da3`
- **Intended integration target:** `beta`
- **Latest immutable recovery checkpoint:** none yet

## Intent

Keep `in-scope.txt` executable for Recon-Ry while preserving intended hostname semantics: normalize `label. label` formatting and `host/*` into the exact host, retain real URLs, and omit prose.

## Evidence and review

- `pytest -q agents/test_scope_puller_seed_files.py agents/test_scope_seed_files.py agents/test_scope_validator.py agents/test_recon_ry.py`: 138 passed.
- `compileall` and `git diff --check`: passed.
- Independent review: pending.

## Resume

Commit the implementation, update this checkpoint, review, merge beta, then fast-forward the clean Hoster beta runtime.
