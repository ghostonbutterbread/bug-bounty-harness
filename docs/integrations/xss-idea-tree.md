# Advanced-XSS idea-tree integration dossier

- **Status:** review-ready
- **Owner:** Hermes / BBH XSS
- **Branch:** `feat/xss-idea-tree`
- **Base commit:** `fde18b170424d4f0934ab767f9f3bb4758980c3e`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-20 (PDT)
- **Owning feature branch/ref:** `feat/xss-idea-tree`
- **Latest immutable recovery checkpoint:** `a7e55310e7d9b81f7407fc0cef9f8632d3340be1` (implementation; this dossier update is later)
- **Feature implementation commit(s):** `a7e55310e7d9b81f7407fc0cef9f8632d3340be1`
- **Inspiration / canonical references:** Advanced-XSS README at `7d529fe86fe8bdef73b393db9274e427cf637182` (safe-fetched SHA-256 `0bbf3107451b73334bc95d589ab47ed12c1a4b194e155bc92fab77a754a96259`); existing BBH `xss`, `xss-payload-engineering`, `dom-xss`, `xss-lifecycle` and research-card ownership.

## Intent

Turn the pinned upstream's 29 non-basic/non-duplicate technique headings into
an evidence-triggered idea tree: conditionally deepen useful mechanisms, route
already-covered topics, and explicitly quarantine invalid, unrelated or
configuration-dependent claims. Avoid an XSS root payload dump, automatic sweep
or universal bypass claim. Deliver a Markdown tree for Ryu and an independent
agent walk-through on the built tree.

## Implemented contract

- `xss` adds one conditional pointer to `xss-payload-engineering`'s idea tree.
- `references/idea-tree.md` chooses one leaf after a source/consumer signal:
  existing parser/encoding guide, client interpreters, derived consumers, or
  defense edges. Each new leaf has prerequisites, a minimal control, a
  falsifier, evidence owner and source caveat.
- `docs/xss-idea-tree.md` supplies a human-readable tree, concrete walk and
  explicit 29-heading intake audit. No target was probed; only the prior
  composition fixture is a local browser proof, not a universal vector.

## Evidence and review

- Tests and commands: feature focused selection returned **8 passed, 1 opt-in
  browser skip**. Full suite returned **304 passed, 1 skipped, 2 failed**;
  unchanged beta, with the same feature-venv interpreter and working directory,
  returned **300 passed, 1 skipped, the same 2 failed**. Both failures are
  in unchanged `stack-to-program/scripts/README.md` contracts (script index
  fields and direct-Python command lane). No XSS-owned failure.
- Independent review: pending; fresh agent must walk the tree from distinct
  plausible observations, evaluate discoverability/noise, technical correctness
  and dangerous overclaims, then review the exact committed diff.
- Replay/cohort/fixture evidence: no live target tests; source sanitized, primary
  standard references fetched for CSP nonce, Service Worker, import maps, WASM.
- Merge/ancestry evidence: beta `fde18b1` fetched and clean at creation.

## Blockers and deferred work

- **Missing test or evidence:** independent tree-walk verdict; full-suite
  baseline comparison is complete as recorded above.
- **Command / fixture / environment needed:** focused pytest in feature venv;
  fresh read-only reviewer with the committed branch and pinned source audit.
- **Trigger to run it:** after this branch's contents and docs are committed.
- **Why it blocks integration:** correctness of unusual browser/security claims
  and agent navigation cannot be inferred from static link checks alone.
- **Next completion step:** test, commit, independent walk, fix/re-review,
  integrate beta only on acceptance, then verify local skill projection.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/xss-idea-tree`
- **Latest immutable recovery checkpoint:** `a7e55310e7d9b81f7407fc0cef9f8632d3340be1` (implementation; current tip may contain dossier-only update)
- **Feature implementation commit(s):** `a7e55310e7d9b81f7407fc0cef9f8632d3340be1`
- **Exact resume point:** request independent walk of the current clean branch,
  reconcile any review findings, then integrate to beta only after acceptance.
- **Working-tree state at handoff:** clean after this metadata commit.

## Decision gates

- **Integration gate:** no root pollution; all 29 pinned headings accounted;
  each active leaf has evidence/control/falsifier; independent walk accepted;
  tests pass or pre-existing failures reproduced against unchanged beta.
- **Activation / cohort gate:** local beta symlink projection verified after
  merge; Hoster/other remote rollout is a separate action.
- **Promotion gate:** no main promotion in this task.

## Decision record

- 2026-10-20 — created from `fde18b1` after Ryu requested breadth without
  startup pollution and a visible independent agent walkthrough.
- 2026-10-20 — implementation committed at `a7e5531`; focused 8 passed/1
  opt-in skip, full 304 passed/1 skipped/2 unchanged baseline failures; review
  of the complete feature tip is the next gate.
