# JavaScript inline inventory integration dossier

- **Status:** feature
- **Owner:** Hermes / t_f05c3e08
- **Branch:** `feat/js-inline-inventory`
- **Base commit:** `b89b944821cc005708af7bd351c64dcf6e141056`
- **Intended integration target:** `origin/beta` / `beta`
- **Last updated:** 2026-10-06
- **Owning feature branch/ref:** `feat/js-inline-inventory`
- **Latest immutable recovery checkpoint:** `2ec3640` (second-review repair and beta reconciliation)
- **Feature implementation commit(s):** `777109d`, `5f24b14`, `9e032e0`
- **Inspiration / canonical references:** Jason Haddix, Hackbots DEF CON 34 BBV Masterclass, 13:00–17:20 (tools mind map ~14:20); upstream JSLuice, jxscout, Waymore repositories and Chrome DevTools protocol.

## Intent

Close a deterministic JS acquisition miss: fetched HTML page scripts without a file `src`, and extensionless `script[src]` references, were absent from JS inventory and sink packets. Keep scope restrictions, content-addressed storage, and heuristic non-exhaustiveness. No automated historical crawler, active browser crawler, or outside-target testing in this branch.

## Implemented contract

`inventory --page` rejects out-of-scope page URLs before fetching, does not follow HTTP redirects, ignores non-2xx page bodies, then parses external script sources, including extensionless URLs, plus executable inline `script` elements. `--input` accepts extensionless JS candidates while filtering known non-JS suffixes. It sends inline bodies through existing content hash, signal, packet, metadata and provenance outputs under synthetic `#inline-script-N` identities; provenance hints preserve those identities. JSON/data script blocks are not treated as executable JS. The parser caps each inline body at 2 MiB of decoded text and inventories at most 100 inline scripts; page context records truncation. `--limit` bounds the combined external and inline inventory. These synthetic identities must not be fetched as URLs. The JS skill and playbook prefer bounded CDP/proxy acquisition and optional external AST/archive tooling for other evidence families without claiming those tools are installed or integrated.

## Evidence and review

- Tests and commands: test-first failures for inline page flow, extensionless source, three first-review defects, and two second-review defects; checkout-local `.venv/bin/python -m pytest agents/test_js_analyzer.py agents/test_xss_sink_sites.py -q` -> 316 passed after second beta reconciliation; `git diff --check` clean.
- Independent review: first review requested three fixes (out-of-scope page, extensionless `--input`, synthetic provenance); second review verified those and identified redirect-following and limit bypass. Both patched with regressions; final review pending.
- Replay/cohort/fixture evidence: local mocked HTML/JS inputs only; no live target.
- Merge/ancestry evidence: branch starts at fetched `origin/beta` `b89b944`; merged `30482cb` at `97a254d`, then `60845f1` at `2ec3640`. No intervening JS-owner edits in the second merge; focused checks passed.

## Blockers and deferred work

- **Missing test or evidence:** Integrated licensed jxscout, JSLuice, Waymore, and CDP collection are not implemented or benchmarked in this branch.
- **Command / fixture / environment needed:** Separate scoped artifact corpus and tool installation/integration design per acquisition family.
- **Trigger to run it:** Operator chooses next integration after seeing this bounded proof and its review.
- **Why it blocks integration, activation, or promotion:** Does not block this focused inline feature; it blocks claims that all video tooling is implemented.
- **Next completion step / successor reference:** Choose a separately tested local JSLuice enrichment adapter or CDP acquisition path, retaining provenance and limits.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/js-inline-inventory`
- **Latest immutable recovery checkpoint:** `2ec3640` (second-review repair and beta reconciliation)
- **Feature implementation commit(s):** `777109d`, `5f24b14`, `9e032e0`
- **Exact resume point:** final independent re-review of reconciled tip, then beta integration if approved.
- **Working-tree state at handoff:** dossier-only update pending commit; implementation tree clean.

## Decision gates

- **Integration gate:** Independent review, focused tests on current feature and integrated beta, clean integration target.
- **Activation / cohort gate:** Confirm live beta launcher/skill projection separately; no live target needed for local tests.
- **Promotion gate:** Stable/main only with explicit operator direction.

## Decision record

- 2026-10-06 — created at fetched beta with bounded inline/extensionless inventory and non-claims for other tools.
- 2026-10-06 — independent review found scope, explicit input, and provenance-hint defects; repaired with regression tests; beta advanced to `30482cb`.
- 2026-10-06 — committed repair `5f24b14`, merged beta `30482cb` via `97a254d`, and passed 313 focused tests.
- 2026-10-06 — second review found redirect-following scope bypass and `--limit` bypass; repaired with tests (316 passed); beta advanced to `60845f1`.
- 2026-10-06 — committed second repair `9e032e0`, merged beta `60845f1` via `2ec3640`, and passed 316 focused tests.
