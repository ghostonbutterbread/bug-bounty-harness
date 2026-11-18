# Beta five-gate regression repair integration dossier

- **Status:** feature; independent review pending.
- **Owner:** delegated BBH release-gate repair worker; parent owns review and integration.
- **Branch:** `fix/beta-five-gate-regressions`
- **Worktree:** `/home/ryushe/worktrees/bbh-beta-five-gate-regressions`
- **Base commit:** `4a189aa5cd65ad0351092d732f620dada2f5a239` (freshly fetched `origin/beta`).
- **Intended integration target:** `beta` (not stable directly).
- **Last updated:** 2026-11-18.
- **Owning feature branch/ref:** `fix/beta-five-gate-regressions`.
- **Latest immutable recovery checkpoint:** pending implementation commit.
- **Feature implementation commit(s):** pending implementation commit.
- **Inspiration / canonical references:** `SCRIPT_POLICY.md`, `agents/index.md`, `skills/data-store-guidance/SKILL.md`, `skills/xss/SKILL.md`, XSS source-acquisition and shared JS analysis lens. History `b9ddf120`, `2ee868cc`, `0eaf8c07` explains intentional routing.

## Intent and implemented contract

Repair five inherited test-gate failures without restoring obsolete direct routes or reducing safety/behavior coverage. The raw-history script index now states the required fields and retains the original complete invocation, limitations and mutation boundary. Tests follow the actual entry-card → store-map → private hypothesis/bounty-storage ownership, registry → adopted skills, and XSS → JS acquisition/shared analysis paths. XSS defense tests retain same-vector, sanitizer, WAF, proof and inherited stop requirements. Source acquisition retains browser observation, scoped fetching, provenance, named source/sink inventory, stack-specific review, and non-proof boundaries. Thirteen synthetic negative controls mutate disposable copies and prove missing route/behavior fields are rejected. No runtime implementation or live store changed.

## Evidence and review

- **Red:** on unchanged exact base, fenced five node IDs reproduced all five expected failures; `red.log` and `red.xml` under `/home/ryushe/.hermes/cache/scratch/bbh-five-gate-EF9wN3rc/run/`.
- **Selected bounded gate:** adapted `fence.py`, copied prior `selected.txt` as `gate.txt`, with local source checkout first and installed Core pin `9db8b23d7405587bc123338ae0aa44d4d51c95a3`; `gate-final.log` / `.xml`: **168 passed, 108 subtests passed**. Programmatic XML comparison found 168 unique parent IDs identical to prior candidate receipt, zero missing or extra. This is the selected 276 results, not the entire repository suite.
- **Functional:** `fence.py functional`, prior `functional.txt`: **158 passed, 11 subtests passed**; `functional-final.log` / `.xml` records checkout-local agents and installed Core location.
- **Affected files and negative controls:** `fence.py` with six affected test paths: **50 passed**, including 13 negative controls; `affected-final.log` / `.xml`.
- **Fence:** adapted prior harness uses task-owned scratch environment and checkout as read-only source; Landlock ABI 8, seccomp deny networking, child execution, process control, and metadata mutation; no access to real home, store writes, host services or child execution. Each run independently probes these boundaries. Limits apply. The inherited installed Core distribution metadata identifies exact pin; no provider-source overlay. Receipts are scratch and may be pruned; preserve externally if needed.
- **Independent review:** required; delegated to parent, not performed here.
- **Merge/ancestry:** not merged, pushed, promoted, or activated. Fetch target again before integration and retest if changed.

## Blockers and deferred work

Independent review of exact branch diff, test semantics, isolation/receipts and preserved routing is required before integration. This is not a complete unrestricted full-suite result; other tests and live runtime operations were intentionally not executed. If a full gate is required, establish comparable confinement and explicitly classify any test needing process/network access before running it. No authorization to alter stable, runtime or live stores was granted.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/beta-five-gate-regressions`.
- **Latest immutable recovery checkpoint:** pending implementation commit.
- **Feature implementation commit(s):** pending implementation commit.
- **Exact resume point:** independently review committed diff and receipts, then parent decides beta integration. On acceptance remove this branch-local dossier from the integration result.
- **Working-tree state at handoff:** intended clean after commits.

## Decision gates

- **Integration gate:** independent review and actual current-beta compatibility; this record is not acceptance.
- **Activation / cohort gate:** no runtime activation or real data operations.
- **Promotion gate:** separate user-directed beta-to-master workflow; this feature branch does not promote.

## Decision record

- 2026-11-18 — isolated base, reproduced five failures, reconciled intentional route history, verified bounded and negative controls; review pending.
