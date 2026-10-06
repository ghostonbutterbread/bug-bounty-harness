# JavaScript inline inventory integration dossier

- **Status:** feature
- **Owner:** Hermes / t_f05c3e08
- **Branch:** `feat/js-inline-inventory`
- **Base commit:** `b89b944821cc005708af7bd351c64dcf6e141056`
- **Intended integration target:** `origin/beta` / `beta`
- **Last updated:** 2026-10-06
- **Owning feature branch/ref:** `feat/js-inline-inventory`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Jason Haddix, Hackbots DEF CON 34 BBV Masterclass, 13:00–17:20 (tools mind map ~14:20); upstream JSLuice, jxscout, Waymore repositories and Chrome DevTools protocol.

## Intent

Close a deterministic JS acquisition miss: fetched HTML page scripts without a file `src`, and extensionless `script[src]` references, were absent from JS inventory and sink packets. Keep scope restrictions, content-addressed storage, and heuristic non-exhaustiveness. No automated historical crawler, active browser crawler, or outside-target testing in this branch.

## Implemented contract

`inventory --page` parses external script sources, including extensionless URLs, plus executable inline `script` elements. It sends inline bodies through existing content hash, signal, packet, metadata and provenance outputs under synthetic `#inline-script-N` identities. JSON/data script blocks are not treated as executable JS. The parser caps each inline body at 2 MiB of decoded text and inventories at most 100 inline scripts; page context records truncation. These synthetic identities must not be fetched as URLs. The JS skill and playbook prefer bounded CDP/proxy acquisition and optional external AST/archive tooling for other evidence families without claiming those tools are installed or integrated.

## Evidence and review

- Tests and commands: test-first failure for inline page flow and extensionless source; checkout-local `.venv/bin/python -m pytest agents/test_js_analyzer.py -q` -> 177 passed; `git diff --check` clean.
- Independent review: pending.
- Replay/cohort/fixture evidence: local mocked HTML/JS inputs only; no live target.
- Merge/ancestry evidence: branch starts at fetched `origin/beta` `b89b944`.

## Blockers and deferred work

- **Missing test or evidence:** Integrated licensed jxscout, JSLuice, Waymore, and CDP collection are not implemented or benchmarked in this branch.
- **Command / fixture / environment needed:** Separate scoped artifact corpus and tool installation/integration design per acquisition family.
- **Trigger to run it:** Operator chooses next integration after seeing this bounded proof and its review.
- **Why it blocks integration, activation, or promotion:** Does not block this focused inline feature; it blocks claims that all video tooling is implemented.
- **Next completion step / successor reference:** Choose a separately tested local JSLuice enrichment adapter or CDP acquisition path, retaining provenance and limits.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/js-inline-inventory`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** independent review of the four-file diff, then fresh beta reconciliation/integration.
- **Working-tree state at handoff:** intentionally uncommitted pending initial review/checkpoint.

## Decision gates

- **Integration gate:** Independent review, focused tests on current feature and integrated beta, clean integration target.
- **Activation / cohort gate:** Confirm live beta launcher/skill projection separately; no live target needed for local tests.
- **Promotion gate:** Stable/main only with explicit operator direction.

## Decision record

- 2026-10-06 — created at fetched beta with bounded inline/extensionless inventory and non-claims for other tools.
