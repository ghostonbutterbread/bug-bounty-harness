# Program scratch scripts

Status: approved for beta integration after independent review
Owner: Hermes / BBH
Branch: `feat/scratch-scripts-t66ff4122`
Base: `origin/beta` at `43a81c325750c09ebe1ce51c0f78a086c12de032`
Target: `beta`
Implementation checkpoint: `bc982a8` on `feat/scratch-scripts-t66ff4122`; reconciled with beta `02d3bb5` by merge `cfa2add`.

## Intent and contract

Provide one BBH CLI to create and index small program-specific scratch Python scripts under the selected Shared lane's existing `working/_runs/<run-id>/_scratch/scripts/` path. The lane-level `scripts/SCRATCH.md` is generated from per-script records; `run` writes one per-invocation receipt and shows derived recorded-use counts. `describe` refreshes indexes. `promote --to bbh` prepares a proposal only; `--to program` requires a review reference and verification receipt and indexes a copied script with hash. No target traffic, no automatic BBH repository edit, no bulk migration of prior scratch scripts.

## Evidence and limits

RED: initial tests failed on absent CLI; four independent reviews reproduced symlink escape, manual index refusal, partial create/promotion, record-key collision, post-write create/describe/promotion inconsistencies, and placeholder promotion metadata. GREEN: 14 focused scratch tests plus adjacent selected policy checks passed (`38 passed, 1 deselected`) after injected-failure regressions; rerun on `bc982a8` confirms that exact selected count. Checkout-local launcher `scripts/bbh scripts/scratch_scripts.py --help` resolved. The deselected existing script-policy test fails because `skills/stack-to-program/scripts/README.md` lacks Outputs/Mutates fields; that file is unchanged and the fields are absent on `origin/beta`. `git diff --check` passed. Independent final review approved beta integration at `bc982a8` and inspected the create/describe rollback and partial-copy promotion paths. Counts include helper-mediated invocations, including nonzero exits, not direct executions. Independent record/event files plus a lane-level process lock protect local concurrent metadata updates; a sync across separate hosts is not a distributed lock, and `list` reconstructs generated Markdown. Promotion review references and mandatory behavioral metadata are operator-supplied, not independently verified by the CLI.

## Activation and next action

Commit this final dossier correction on feature, fetch beta, integrate into a clean current beta checkout, remove this temporary dossier on beta, test, publish, then verify selected Hoster runtime and active skill route separately. Existing agents may retain loaded instructions.
