# BaseTeam Architecture Spec (Draft)

## Purpose
This spec defines the next-stage architecture for the bug bounty harness so that `BaseTeam` becomes the central shared module for orchestration, storage, reporting, and review lifecycle behavior.

The design goal is to make concrete teams like `apk_team` and `zero_day_team` as lightweight as possible.

Under this model:
- `BaseTeam` owns the backend work
- concrete teams own modality-specific hunting logic
- storage and reporting behavior stay canonical and shared
- the system becomes easier to extend into future teams without copying large orchestration files

## Core Architectural Direction
The project should move from:
- one large shared implementation file
- plus team files that still duplicate some pathing/report/review logic

toward:
- a `base_team/` package containing small focused modules
- a thin `BaseTeam` facade/class that composes those modules
- thin concrete teams that mostly supply prompts, agent specs, and modality-specific discovery

Short form:
> BaseTeam should be the substrate. Teams should mostly describe what to hunt, not how the infrastructure works.

## Design Goals
1. **Canonical storage behavior**
   - all teams should use the same storage resolver and storage object model
   - no team should invent its own durable path structure
2. **Shared orchestration behavior**
   - agent spawn, logging, trace writing, partial persistence, and review invocation should live in shared infrastructure
3. **Thin team modules**
   - `apk_team`, `zero_day_team`, and future teams should mostly define profiles, prompts, and modality-specific discovery
4. **Low-friction extensibility**
   - adding a new team should not require copying hundreds of lines of orchestration code
5. **Maintainability through decomposition**
   - shared logic should be broken into focused submodules instead of continuously growing one file
6. **Preserve the stronger review doctrine**
   - the richer `zero_day_team` review model should remain the quality target for the shared core

## What BaseTeam Should Own

### 1. Storage lifecycle
BaseTeam should be the owner of canonical storage semantics.

It should resolve and expose:
- `storage`
- `family`
- `lane`
- `team_dir` / canonical lane root
- `reports_root`
- `ledgers_root`
- `working_root`
- `context_root`
- `notes_root`
- `shared_root`
- `recon_root`
- `input_root`

Concrete teams should not manually reconstruct these paths.

### 2. Report lifecycle
BaseTeam should own shared report output behavior, including:
- dated report index path resolution
- confirmed/dormant/novel report writing
- promotion target paths
- report metadata helpers
- later, complete/archive transitions

### 3. Ledger lifecycle
BaseTeam should own ledger orchestration, not canonical ledger persistence mechanics.

BaseTeam should own:
- deciding when candidates are reserved, reviewed, and promoted
- passing normalized finding identity into the universal ledger API
- coordinating deduplication with the canonical ledger contract
- snapshot/version linkage
- partial persistence on interruption
- coverage/support-state merge outside the canonical findings source of truth

The universal ledger implementation should own:
- `ledger.json` read/merge/write behavior
- locking and atomic writes
- durable FID assignment and finding-state persistence

### 4. Review lifecycle
BaseTeam should own the shared review pipeline:
- reviewer prompt assembly hooks
- reviewer invocation
- normalization of reviewer output
- shared tier promotion logic
- PoC validation rules
- intended-behavior / assumption-break doctrine
- routing to confirmed/dormant/novel outputs

### 5. Agent runtime lifecycle
BaseTeam should own:
- agent workspace creation
- agent prompt file creation
- process spawning
- log capture
- log recovery parsing
- timeout handling
- cleanup
- trace emission
- orchestration flow
- signal-aware interruption behavior

### 6. Shared context writing
BaseTeam should own the canonical writeout of context/helper files tied to storage layout.

## What Concrete Teams Should Own
Concrete teams should only own the logic that is truly specific to their modality.

### APK team should own
- exported component / provider / IPC / WebView / intent-centric profiles
- APK-specific prompt doctrine
- APK-specific surface interpretation
- APK-specific dynamic agent generation
- modality-specific attack reasoning

### 0day/web/source team should own
- web/source profile definitions
- web-specific prompt doctrine
- web/source discovery or static-entrypoint reasoning
- dynamic profile generation tied to that modality

### Future teams should own
Examples:
- EXE/macOS-specific profile sets
- binary-specific or parser-specific prompts
- modality-specific preflight logic only when truly necessary

## Teams Should Be Thin
The intended shape of a team module is:
- team identity/config
- static profile definitions
- optional dynamic profile generation
- prompt hooks
- optional modality-specific preflight or normalization hooks

The team module should **not** need to own:
- storage path assembly
- report writing
- ledger mechanics
- review lifecycle
- process lifecycle

## Current Extracted Package Layout
The refactor is now partially implemented, not just proposed.

Current shared package shape:

```text
agents/
├── base_team/
│   ├── __init__.py        # stable package surface + compatibility re-exports
│   ├── storage.py         # storage resolution + canonical path helpers
│   ├── reports.py         # report pathing + dated index writers
│   ├── findings.py        # finding normalization and signatures
│   ├── ledger.py          # ledger loading/merge/dedup/persistence
│   ├── review.py          # reviewer prompts, parsing, normalization, tier logic
│   └── runtime.py         # spawn/wait/log recovery/cleanup/orchestration/tracing
├── base_team_core.py      # active BaseTeam implementation spine during migration
├── apk_team.py
├── zero_day_team.py
└── ...
```

Notes:
- `agents.base_team` is now the stable public import surface.
- `base_team_core.py` is the active implementation spine during migration, not dead or deprecated code.
- the earlier `base_team.py` filename had to be retired because `agents/base_team.py` and `agents/base_team/` collided on the same Python import namespace.

This still does not need to be finished in one big bang. Incremental migration remains the preferred approach.

## BaseTeam Facade Responsibility
The public `BaseTeam` class should remain easy to reason about.

It should act mainly as an orchestrating facade that wires together shared components.

In practice, `BaseTeam` should:
- initialize storage and runtime state
- expose a clean subclass contract
- call into helpers/modules for storage, reports, ledger, runtime, and review
- remain readable enough that a future maintainer can understand the flow quickly

## Minimal Subclass Contract
Concrete teams should implement only the narrowest necessary interface.

Recommended subclass contract:
- `get_static_profiles()`
- `generate_dynamic_from_surfaces(...)`
- optional hook: `build_prompt_context(...)`
- optional hook: `preflight(...)`
- optional hook: `review_context(...)`

Possible future team config fields:
- `team_type`
- `default_family`
- `default_lane`
- `target_modality`
- `supports_dynamic_profiles`

## Storage Rules
The storage resolver remains the source of truth.

Rules:
- do not manually compose canonical durable paths in concrete team files
- derive report outputs from `storage.reports_root`
- derive ledgers from `storage.ledgers_root`
- derive generated artifacts from `storage.working_root`
- derive durable notes from `storage.notes_root`
- keep lane/family selection centralized

If a team needs modality-specific folders, they should be created under canonical shared roots rather than inventing parallel top-level structures.

## Review Rules
The shared review/report model should continue moving toward the stronger `zero_day_team` semantics.

That means the shared core should preserve:
- exploitability-first reasoning
- concrete PoC requirement for `CONFIRMED`
- placeholder rejection
- intended-behavior / broken-assumption analysis

This spec does not replace the existing report-gate spec. It depends on it.

Relationship between specs:
- `report-gate-spec.md` defines the review philosophy and tier semantics
- this spec defines where that shared behavior should live architecturally

## Current Migration Seams
The current codebase already exposes the first real refactor seams, and implementation should follow those seams rather than inventing abstract ones.

### Seam 1: storage/report path duplication still exists across teams
- `zero_day_team.py` now aligns better with canonical storage, but still contains team-local storage helper intent and report writing behavior that should ultimately live in shared BaseTeam modules.
- `apk_team.py` still resolves storage directly, assembles report paths directly, and writes dated report indexes locally.
- `BaseTeam` already exposes storage fields and report roots, which made storage/report extraction the cleanest first migration target.

### Seam 2: APK team still depends on zero-day behavior in some places
- `apk_team.py` has historically routed review/report behavior sideways through `zero_day_team` helpers.
- A central goal of the refactor is to eliminate that sideways dependency and replace it with shared BaseTeam-owned modules.
- Shared BaseTeam review/runtime modules now exist, but cleanup may still be needed at remaining call sites.

### Seam 3: Package extraction should follow behavior clusters already visible in the code
The current files already reveal natural module boundaries:
- storage/report path resolution
- finding normalization + dedup identity
- ledger persistence
- runtime/spawn/log recovery/orchestration
- review prompting + normalization
- trace writing

Those are the real clusters that were extracted first.

## Implementation Readiness Rules
Before each migration step:
- preserve runtime behavior unless the phase explicitly changes semantics
- prefer extraction + call-site replacement over simultaneous redesign
- maintain compatibility shims where useful so teams can migrate incrementally
- validate each step with compile checks and targeted harness smoke checks where feasible

## Migration Status
This refactor has been implemented incrementally.

### Phase 1 - Complete
Shared storage/report helpers have been moved into the BaseTeam package.

Completed scope:
- created the `agents/base_team/` package skeleton
- extracted storage-facing helpers into `storage.py`
- extracted dated report index path resolution and report-writing helpers into `reports.py`
- updated call sites to consume the shared helpers

Delivered outcome:
- canonical storage object is now the standard interface for the refactor path
- report path assembly has started moving out of ad hoc team-local logic

### Phase 2 - Complete
Shared ledger and finding normalization logic have been moved into package modules.

Completed scope:
- extracted finding normalization and signature helpers into `findings.py`
- extracted shared ledger read/merge/write behavior into `ledger.py`
- centralized common dedup identity rules

Delivered outcome:
- one shared path now exists for finding identity, dedup, persistence, and merge behavior

### Phase 3 - Complete
Shared runtime/process lifecycle has been moved into package modules.

Completed scope:
- extracted prompt-file handling, spawn logic, timeout handling, cleanup, signal handling, trace writing, and orchestration flow into `runtime.py`
- kept team-specific prompt content outside the runtime layer

Delivered outcome:
- process/log/recovery/orchestration boilerplate is now shared infrastructure rather than living inline in `BaseTeam`

### Phase 4 - Complete, with one caveat
Shared review behavior has been moved into package modules.

Completed scope:
- extracted shared review prompting, CLI invocation, reviewer output normalization, and tier routing into `review.py`
- promoted the stronger shared assumption-break review doctrine into BaseTeam-owned modules

Delivered outcome:
- BaseTeam now owns a shared review/report gate path
- concrete teams can inherit one common review quality bar through the shared package

Caveat:
- follow-up work may still be needed to fully eliminate any remaining sideways dependencies from `apk_team.py` into `zero_day_team.py` outside the BaseTeam-owned review path

### Phase 5 - In Progress
Slim down concrete teams and reduce the remaining implementation weight in `base_team_core.py`.

Remaining target outcome:
- `apk_team.py` becomes mostly profiles + prompts + APK-specific dynamic generation
- `zero_day_team.py` becomes mostly profiles + prompts + web/source-specific discovery
- `base_team_core.py` becomes primarily class glue, subclass contract, and minimal integration logic rather than a large mixed implementation file

## Non-Goals
This spec does **not** propose:
- rewriting everything at once
- removing modality-specific prompt doctrine
- flattening all differences between teams
- weakening the current 0day review model

## Architectural Principle
A good test for whether code belongs in BaseTeam is:

> If a future EXE team, macOS team, or API team would probably need this too, it belongs in shared infrastructure.

A good test for whether code belongs in a concrete team is:

> If this only makes sense because the target is APK/web/exe/etc, it belongs in the team module.

## Desired End State
The end state should feel like this:
- `BaseTeam` is the stable backend substrate
- storage/report/review/runtime behavior is shared and canonical
- teams are small and easy to understand
- adding a new team mostly means defining profiles and prompts
- the system can expand without reintroducing path drift or orchestration duplication

## Remaining Work To Finish The Spec Direction
The main architectural direction is now implemented. The remaining work is cleanup, slimming, and dependency removal rather than inventing new shared seams.

### Remaining high-value work
1. **Continue slimming `base_team_core.py`**
   - keep extracting only when a real shared cluster remains
   - otherwise let `base_team_core.py` stabilize as the class/facade layer

2. **Remove remaining sideways team dependencies**
   - especially any lingering `apk_team.py` dependence on `zero_day_team.py`
   - teams should depend on shared BaseTeam package modules, not each other

3. **Decide whether the remaining helper clusters deserve dedicated modules**
   - `_select_specs(...)`
   - dynamic agent cache/load/save helpers
   - shared brain loading
   - source excerpt / source resolution helpers
   These may move later, but they are now lower priority than the completed infrastructure lifts.

4. **Make the end-state naming explicit**
   - if and when `base_team_core.py` becomes thin enough, decide whether it should stay as the durable implementation name or become a smaller facade module

## Recommended Immediate Next Step
The next implementation step should be:
1. remove any remaining sideways APK-to-0day coupling
2. slim `base_team_core.py` only where clear shared clusters still exist
3. stop extracting once the remaining code is truly facade-level rather than forcing decomposition for its own sake

That gives the best maintainability outcome with the lowest chance of over-refactoring.
