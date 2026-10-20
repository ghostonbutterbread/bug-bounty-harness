# Stack-to-program generic augmentation integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch / owning ref:** `feat/stack-to-program-generic`
- **Base commit:** `adeec56250962888b42faa79f5a79e7260f14100` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-20
- **Latest immutable recovery checkpoint:** `9385c13e08dd9599b2e15d6bb238f4c3e0b6130c` (reviewed implementation; dossier-only update follows)
- **Feature implementation commits:** `3ac572cd066e5034614ac2653c735110622f431d`, `9385c13e08dd9599b2e15d6bb238f4c3e0b6130c`
- **Inspiration / canonical references:** `skills/stack-to-program/SKILL.md`, `skills/program-finder/SKILL.md`, Discord stack-to-program request

## Intent

Generalize a previously Ghostscript-heavy public-source CVE-to-bounty discovery skill: branch on public observability, reserve conditional dependency/feature tracing for private components, enrich a selected shortlist with public program/product documentation, and keep technology-specific mechanisms in a narrow reference augment. No script change, live candidate request, or automated harvesting.

## Implemented contract

- Core `stack-to-program` owns selection, public-only discovery, evidence labels, exact association, uncertainty, and selected-program scope handoff.
- New `references/visibility-and-bridges.md` supplies the public-versus-private decision model, evidence graph/ladder, alternate consumers, and limitations of existing CLI labels.
- Updated `references/ghostscript.md` adds caller/feature archetypes and a qualified historical Sketchfab/Epic retrospective without asserting the intermediary or current vulnerability.
- `program-finder` already routes stack-led selection to this skill; no competing route introduced.

## Evidence and review

- Tests and commands: `python3 -m unittest discover -s tests -p test_stack_to_program.py -v` (4 passed); `git diff --check`; local markdown-link resolution and YAML frontmatter parsing passed. Repository lacks the `docs/policy-authoring.md` lint guide referenced by shared guidance; manual equivalent run, logged as papercut.
- Independent review: read-only review of `3ac572c` found a moderate overstatement: Sketchfab public texture docs list no EPS/PS; `9385c13` corrected the retrospective to a broad-only lead and explained that the historical EPS path took owned-session observation. Also added safe resolved-Shared relative pointers to D05 report/submission. Narrow independent re-review passed for the corrected distinction, intermediary uncertainty, artifact pointers, and no current-vulnerability claim. Reviewer re-ran 4 tests, checked 12 local links and `git diff --check` on the initial slice.
- Replay/cohort/fixture evidence: core spells public-indexed route without private tracing, optional/private bridge route with feature-only uncertainty, and Sketchfab retrospective as a broad public hypothesis distinct from historical target-side EPS evidence. No automated evidence-harvesting or live-host exercise.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- Public evidence harvesting is still manual; tracked separately by the existing public-composition-intake task. No host enumeration or program detection automation was implemented by this docs change.
- No live candidate app/version validation was performed or is required for this public-only skill change.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/stack-to-program-generic`
- **Latest immutable recovery checkpoint:** `9385c13e08dd9599b2e15d6bb238f4c3e0b6130c` (reviewed implementation; dossier-only update follows)
- **Feature implementation commits:** `3ac572cd066e5034614ac2653c735110622f431d`, `9385c13e08dd9599b2e15d6bb238f4c3e0b6130c`
- **Exact resume point:** integrate reviewed feature into the clean beta integration checkout, remove this temporary dossier from beta, run focused checks, push and read back beta.
- **Working-tree state at handoff:** clean after this dossier-only commit.

## Decision gates

- **Integration gate:** independent review, no contradictory policy route, link/lint and focused CLI checks.
- **Activation / cohort gate:** verify consuming beta skill source; no host/runtime rollout claimed.
- **Promotion gate:** stable only on separate owner instruction.

## Decision record

- 2026-10-20 — feature worktree created from fetched beta; canonical owner confirmed and generic/augment split authored.
- 2026-10-20 — independent review found public Sketchfab format-list overstatement; corrected in `9385c13`; narrow re-review passed. Decision: integrate to beta with temporary dossier retired, no live-target activation or stable promotion.
