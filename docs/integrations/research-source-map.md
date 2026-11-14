# Hunt research source map integration dossier

- **Status:** feature, independent review pending
- **Owner:** Hermes; Kanban `t_afa2f5cd`
- **Branch:** `bug-bounty-harness/t_afa2f5cd-map-hunt-research-resources-and-source-i`
- **Base commit:** `695d17be9e5f837a5b4d9b2da620f8aebce0cb14`
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-14
- **Latest immutable recovery checkpoint:** `563fb69c7914249b5a55d44c4945aa9e176302c8`
- **Feature implementation commit(s):** `37b8693ef8f99fbc235ffbd8e099e3af15b12b0e`, `832cd7b6a7f88bcdf89dcfb64301499cf014b7b6`, `804c5aa4047a2f21b50d3f37375d595997299485`, `563fb69c7914249b5a55d44c4945aa9e176302c8`
- **Inspiration / canonical references:** user request in Discord thread `1570852823703355542`; existing research-knowledge-management and source-selection policy.

## Intent and implemented contract

Make question-led source selection and new-source intake discoverable to bounty
agents without adding a second research corpus or silently running tests.
The map distinguishes target knowledge, portable mechanisms, public report
analogues, write-ups, upstream technology and CVEs, and technique references.
The on-demand intake evaluates coverage, a sample question, overlap, provenance,
access, privacy, and uncertainty before recommending adoption. Existing live and
research policies retain their authority. HexBrain's authenticated API and any
actual client are explicitly unverified.

## Evidence and review

- Focused pytest route, registry, methodology, local-shadow, ResearchMap and
  patch-research suites: 31 passed, 10 subtests passed, including map, upstream
  pointer, research gate and intake-return negative checks.
- Independent source inventories complete; incorporated Disclosure Index,
  XSS/WAF references, local template/catalog leads, and Preview's unquarantined
  response limitation. Independent route review found missing routes and an
  absent HexBrain receipt; fixes are in `804c5aa4`. Re-review identified an
  OpenAPI/MCP attribution error and missing research-gate regression checks;
  corrected in `563fb69c`. Independent re-review pending.
- Actual fresh runtime projection: pending after reviewed integration.
- Beta merge/ancestry check and broader focused tests: pending.

## Blockers and deferred work

A real authenticated HexBrain query cannot be verified without an approved key;
no key is requested or provisioned as part of this change. Map labels the
interface accordingly. Fresh-runtime resolution and intended semantic routes
must be checked after an independently reviewed and integrated source change.

## Interruption / resume handoff

- **Owning feature branch/ref:** as above.
- **Latest immutable recovery checkpoint:** `563fb69c7914249b5a55d44c4945aa9e176302c8`; current branch adds a later dossier-only checkpoint.
- **Feature implementation commit(s):** `37b8693ef8f99fbc235ffbd8e099e3af15b12b0e`, `832cd7b6a7f88bcdf89dcfb64301499cf014b7b6`, `804c5aa4047a2f21b50d3f37375d595997299485`, `563fb69c7914249b5a55d44c4945aa9e176302c8`.
- **Exact resume point:** obtain independent
  reviewer findings, resolve them, rerun route tests, commit branch, then review
  beta merge and activation separately.
- **Working-tree state:** dossier-only update pending commit.

## Decision gates

- **Integration:** no open review blockers; current beta and clean target;
  focused source/route tests pass and changed paths are scoped.
- **Activation:** independently verify the selected source checkout and runtime
  projection; do not equate publication with activation.
- **Promotion:** no stable/main promotion implied.
