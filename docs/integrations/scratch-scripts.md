# Program scratch scripts

Status: review candidate
Owner: Hermes / BBH
Branch: `feat/scratch-scripts-t66ff4122`
Base: `origin/beta` at `43a81c325750c09ebe1ce51c0f78a086c12de032`
Target: `beta`
Implementation checkpoint: `9cbadd1` on `feat/scratch-scripts-t66ff4122`; reconciled with beta `9f17c67` by merge `cfa2add`.

## Intent and contract

Provide one BBH CLI to create and index small program-specific scratch Python scripts under the selected Shared lane's existing `working/_runs/<run-id>/_scratch/scripts/` path. The lane-level `scripts/SCRATCH.md` is generated from per-script records; `run` writes one per-invocation receipt and shows derived recorded-use counts. `describe` refreshes indexes. `promote --to bbh` prepares a proposal only; `--to program` requires a review reference and verification receipt and indexes a copied script with hash. No target traffic, no automatic BBH repository edit, no bulk migration of prior scratch scripts.

## Evidence and limits

RED: initial 3 tests failed on absent CLI; describe test failed on absent subcommand. Two review rounds reproduced symlink escape, manual index refusal, partial create/promotion, and record-key collision; GREEN: 10 focused scratch tests and 24 adjacent selected policy checks passed (`34 passed, 1 deselected`). Checkout-local launcher `scripts/bbh scripts/scratch_scripts.py --help` resolved. The deselected existing script-policy test fails because `skills/stack-to-program/scripts/README.md` lacks Outputs/Mutates fields; that file is unchanged. `git diff --check` passed. Independent final review pending. Counts include helper-mediated invocations, including nonzero exits, not direct executions. Independent record/event files plus a lane-level process lock protect local concurrent metadata updates; a sync across separate hosts is not a distributed lock, and `list` reconstructs generated Markdown. Promotion review references are operator-supplied, not independently verified by the CLI.

## Activation and next action

Final independent review on reconciled `cfa2add` is pending. If accepted, commit any dossier correction on feature, fetch beta, integrate into a clean current beta checkout, remove this temporary dossier on beta, test, publish, then verify selected Hoster runtime and active skill route separately. Existing agents may retain loaded instructions.
