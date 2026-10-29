# Android hierarchy output safety integration dossier

- **Status:** independently approved for beta integration; producer defect remains open
- **Owner:** delegated Hermes feature worker; parent owns review and integration
- **Branch:** `feat/android-hierarchy-output-safety`
- **Worktree:** `/home/ryushe/worktrees/bbh-android-hierarchy-output-safety`
- **Base commit:** `52252b96c6d6eb9ebd44f81b9646e6be3ab4214b` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-29
- **Owning feature branch/ref:** `feat/android-hierarchy-output-safety`
- **Latest immutable recovery checkpoint:** `22d0ff5f1ef4e1111bcafed7082bc03718b3d310`
- **Feature implementation commit(s):** `22d0ff5f1ef4e1111bcafed7082bc03718b3d310`
- **Inspiration / canonical references:** PC-20260824-211007; `skills/android-adb/SKILL.md`; `AGENTS.md`; `agents/index.md`

## Intent

Prevent the documented hierarchy-output exposure by explicit safety guidance,
without changing or claiming enforcement. Preserve the authorized emulator
transport and preflight instructions. No device, credential, or target action
is authorized in this task.

## Implemented contract

Before transport examples, the Android skill warns that masked UI text can be
present despite false password metadata. It forbids raw XML and copied values
in outputs or persistence, requires verified pre-output fixed-safe-schema
sanitization and fails closed otherwise. It offers manual on-screen inspection
with a non-sensitive summary, without treating screenshots as safe. It does
not claim an existing sanitizer or producer enforcement.

## Evidence and review

- `python3 -m unittest discover -s tests -p test_android_adb_hierarchy_guidance.py -v`: 3 passed, static only, no device.
- `git diff --check`: passed. A separate read-only Python check compared the
  skill with `git show 52252b96c6d6eb9ebd44f81b9646e6be3ab4214b:skills/android-adb/SKILL.md` after removing the new
  section: all pre-existing content, including transports, was identical; it
  also checked section order, safety phrases, balanced fences, and registry.
- Shared AI Policies `python3 scripts/policy_lint.py`: passed in its own
  repository; this lints shared policy, not the BBH document.
- Reference/alignment audit: BBH `SKILL_REGISTRY.md` is the only other direct
  `android-adb` reference; no hierarchy producer or other hierarchy guidance was
  found by bounded searches for `uiautomator`, `dumpWindowHierarchy`, UI
  hierarchy, and hierarchy XML in BBH and shared AI Policies. `agents/index.md`,
  general/live-testing/resource policy routing, Android preflight and
  verification, shared payment and PoC secret-output rules, and screenshot
  warnings are compatible; the Android hierarchy boundary is deliberately
  stricter for raw hierarchy data. No references were changed. The search is not
  proof that no producer exists outside those repositories.
- Independent review: APPROVE at tip `b10c25b83f27df83968156821353e6453ea0fb42`
  against beta `52252b96c6d6eb9ebd44f81b9646e6be3ab4214b`. All 3 static
  tests passed with feature-source provenance and `git diff --check` passed;
  existing transport/preflight content is intact. No runtime validation.
- Base: fetched `origin/beta` at the stated SHA before branching. Re-fetch and
  reconcile as appropriate before review/integration; do not infer current
  upstream from this historical receipt.

## Blockers and deferred work

- **Missing evidence:** Original producer and a verified output-boundary
  sanitizer are unidentified; static documentation checks cannot establish
  enforcement or close PC-20260824-211007.
- **Environment / fixture:** Once the actual producer is identified, its owner
  must use synthetic non-device hierarchy fixtures including visually masked
  values with false password metadata and failure-path/output-channel checks.
  The exact command is unknown until the producer is located.
- **Trigger:** Authorized follow-up identifies the producer and an appropriate
  implementation/test environment; no live device or credentials are needed
  for the intended synthetic regression.
- **Effect:** The defect remains open; this guidance can be reviewed separately
  but is not proof of a producer fix, deployment, or incident closure.
- **Successor:** parent to locate producer, implement and verify enforcement,
  and own any record decision.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/android-hierarchy-output-safety`
- **Latest immutable recovery checkpoint:** `22d0ff5f1ef4e1111bcafed7082bc03718b3d310`
- **Feature implementation commit(s):** `22d0ff5f1ef4e1111bcafed7082bc03718b3d310`
- **Exact resume point:** parent verifies current beta and clean worktrees, then
  integrates the approved guidance and tests; no closure of the producer issue.
- **Working-tree state at handoff:** clean after the dossier checkpoint commit.

## Decision gates

- **Integration:** independently approved; verify current fetched `origin/beta`
  and run integrated static tests before publication; parent decision only.
- **Activation / cohort:** not authorized or performed; separate runtime review.
- **Promotion:** not authorized; separate stable decision.

## Decision record

- 2026-10-29 — Implemented a guidance-only feature; producer defect remains open.
- 2026-10-29 — Independent reviewer approved `b10c25b`; producer and sanitizer remain unidentified.
