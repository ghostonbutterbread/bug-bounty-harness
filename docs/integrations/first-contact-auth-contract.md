# First-contact Auth Contract projection integration dossier

- **Status:** review-ready
- **Owner:** hermes / bugfix
- **Branch:** feat/first-contact-auth-contract
- **Base commit:** 3011f2d55e1e0f8abc953211bd273aa73c23d63d
- **Intended integration target:** beta
- **Last updated:** 2026-10-27
- **Owning feature branch/ref:** feat/first-contact-auth-contract
- **Latest immutable recovery checkpoint:** fbdbb0a7a02973f4e2cc51de868864270b031be3
- **Feature implementation commit(s):** fbdbb0a7a02973f4e2cc51de868864270b031be3
- **Inspiration / canonical references:** companion ai-policies feat/first-contact-auth-contract; Discord thread 1564824966384328835

## Intent

account-management projects existing resolver fields from the one program Auth
Contract. Children inherit. Inventory is not a second narrative.

## Implemented contract

- New `First-contact Auth Contract projection` section in account-management
- Playbook note after auth fields
- account-registry recovery owner split names the Auth Contract
- Focused test: `tests/test_auth_contract_projection.py`

## Evidence and review

- Tests and commands: `python3 -m pytest -q tests/test_auth_contract_projection.py`
- Independent review: pending
- Merge/ancestry evidence: branched from origin/beta `3011f2d`

## Blockers and deferred work

- **Missing test or evidence:** independent reviewer; do not merge to beta until review
- **Command / fixture / environment needed:** reviewer on this worktree
- **Trigger to run it:** after implementation commit
- **Why it blocks integration, activation, or promotion:** experimental policy companion; review first
- **Next completion step / successor reference:** independent review, then merge to beta

## Interruption / resume handoff

- **Owning feature branch/ref:** feat/first-contact-auth-contract
- **Latest immutable recovery checkpoint:** fbdbb0a7a02973f4e2cc51de868864270b031be3
- **Feature implementation commit(s):** fbdbb0a7a02973f4e2cc51de868864270b031be3
- **Exact resume point:** independent review, then merge to beta
- **Working-tree state at handoff:** clean after dossier SHA update

## Decision gates

- **Integration gate:** independent review, then merge to beta
- **Activation / cohort gate:** skill symlink to BBH beta after merge
- **Promotion gate:** main only on explicit direction

## Decision record

- 2026-10-27 — created as BBH projection companion to ai-policies Auth Contract
