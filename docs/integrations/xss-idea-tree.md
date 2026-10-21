# Advanced-XSS idea-tree integration dossier

- **Status:** independently reviewed; minor corrections applied, awaiting narrow readback of corrected tip
- **Owner:** Hermes / BBH XSS
- **Branch:** `feat/xss-idea-tree`
- **Base commit:** `fde18b170424d4f0934ab767f9f3bb4758980c3e`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-20 (PDT)
- **Owning feature branch/ref:** `feat/xss-idea-tree`
- **Latest immutable recovery checkpoint:** `b09484a43ca4bac403a83f87a3ed75a28b48bf0b` (corrected implementation; this dossier update is later)
- **Feature implementation commit(s):** `a7e55310e7d9b81f7407fc0cef9f8632d3340be1`, `b09484a43ca4bac403a83f87a3ed75a28b48bf0b`
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
- Corrected feature rerun with checkout-local `PYTHONPATH`: **304 passed, 1
  skipped, 2 failed**, the same two baseline failures noted above. Focused
  rerun: **8 passed, 1 opt-in skipped**. `git diff --check` is clean.
- Independent review of `ab86d03` by two read-only agents: scenario walk
  **MINOR** (on-demand leaves work; one-vs-many wording and Attempts/proof
  ownership ambiguous); separate technical/release review **ACCEPT for beta
  review with three MINOR docs fixes** (introductory mismatched-context
  heading accounting, already-resolved import-map caveat, header-delivered CSP
  condition for nonce attribute hiding). The exact findings and three scenario
  outcomes are captured in `docs/xss-idea-tree.md`. These changes address all
  five minors. No live requests or upstream payload execution were made.
- Replay/cohort/fixture evidence: no live target tests; source sanitized, primary
  standard references fetched for CSP nonce, Service Worker, import maps, WASM.
- Merge/ancestry evidence: beta `fde18b1` fetched and clean at creation.

## Blockers and deferred work

- **Missing test or evidence:** narrow readback of corrected review nits and
  full-suite check on the eventual integrated beta tree; unchanged-beta baseline
  comparison and corrected feature rerun above are complete.
- **Command / fixture / environment needed:** `.venv/bin/python -m pytest -q
  tests`; beta integration worktree plus same interpreter for baseline compare.
- **Trigger to run it:** after minor fixes are committed and again after beta
  merge; read-only narrow re-review confirms all corrected wording and routes.
- **Why it blocks integration:** release claims require exact committed-tree
  evidence; unrelated baseline failures must be enumerated, not waived.
- **Next completion step:** obtain a narrow independent readback of corrected
  commit `b09484a`; integrate beta only on acceptance,
  then verify beta projection. Hoster/other runtime activation is separate.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/xss-idea-tree`
- **Latest immutable recovery checkpoint:** `b09484a43ca4bac403a83f87a3ed75a28b48bf0b` (corrected implementation; current tip may contain dossier/doc-only update)
- **Feature implementation commit(s):** `a7e55310e7d9b81f7407fc0cef9f8632d3340be1`, `b09484a43ca4bac403a83f87a3ed75a28b48bf0b`
- **Exact resume point:** narrow readback of corrected commit;
  integrate beta only after acceptance.
- **Working-tree state at handoff:** clean after this dossier/doc-only commit.

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
- 2026-10-20 — two independent read-only reviews of `ab86d03`: scenario walk
  MINOR and technical review ACCEPT with minor documentation fixes. The tree
  walk identified three concrete edge cases; all actionable minor wording and
  source-boundary corrections are applied. Focused rerun: 8 passed, 1 opt-in
  skip; corrected full rerun 304 passed/1 opt-in skip/2 unchanged baseline
  failures. Corrected commit, narrow readback and beta integration remain
  separate gates.
- 2026-10-20 — corrections committed at `b09484a43ca4bac403a83f87a3ed75a28b48bf0b`;
  the next commit updates checkpoint metadata and its matching assertion only.
  Narrow independent re-review remains before beta merge.
