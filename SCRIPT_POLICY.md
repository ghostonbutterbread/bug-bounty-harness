# BBH Repository-Local Script Policy

Status: active
Owner: BBH maintainers

This is the repository-local script policy discovered through the shared
`script_manager` skill. It owns BBH script placement, indexing, and maintenance
conventions. Shared safety, authorization, scope, and lane rules still apply.

## Discover Before Creating

Start with [`scripts/README.md`](scripts/README.md), then inspect the nearest
skill-owned `scripts/README.md` and established `agents/` modules. Reuse or
extend an indexed script when its responsibility already matches. Do not create
a scratch replacement for maintained behavior.

Multiple cohesive scripts are encouraged when they perform different jobs, have
different interfaces, or need independent tests and lifecycles. Do not force
unrelated behavior into one giant script merely to reuse a filename.

## Placement by Owner

- **BBH-wide command-line helper:** `scripts/`.
- **Vulnerability or capability helper:** `skills/<skill>/scripts/`, such as
  `skills/xss/scripts/`.
- **Program-specific helper whose program has a BBH skill:**
  `skills/<program-skill>/scripts/`.
- **No existing skill owner:** start in `scripts/`. Do not create a new skill or
  category solely to hold one script; split it into a narrower owner later when
  a coherent reusable capability exists.
- **Importable harness runtime implementation:** the responsibility-owned
  package under `agents/`. New argv-oriented standalone helpers use one of the
  script homes above; legacy entrypoints are not moved automatically.

New scripts must follow the selected repository lane and use repository-relative
paths. Do not hardcode a developer checkout, host, username, transient run, or
provider-specific runtime path.

## Index Contract

Every directory that owns executable scripts has a `README.md` containing the
script names, purpose, invocation or inputs, mutation boundary, verification,
and coverage limits when heuristic. The root [`scripts/README.md`](scripts/README.md)
indexes BBH-wide helpers and links every skill-owned script index.

When adding, renaming, moving, or removing a script, update the nearest index in
the same change. An index is discovery metadata, not proof that the script is
exhaustive or correct.

## Scripts-Only Maintenance Boundary

An explicitly authorized script-maintenance agent may change:

- canonical scripts in the homes above;
- directly associated tests and fixtures;
- the nearest script index;
- the branch-local integration dossier.

A scripts-only maintenance agent must not edit `SCRIPT_POLICY.md`, any
`SKILL.md`, `AGENTS.md`, prompts, policy documents, stable/main branches,
repository settings, or unrelated code. If a script change requires one of
those edits, stop and hand off the policy or broader implementation decision to
its owner. Index edits do not grant authority to rewrite this policy.

## Deterministic Authority

Follow the shared `script_manager` bounded-authority contract. Deterministic
mechanics are reusable; hardcoded patterns and heuristic misses remain
non-exhaustive unless a closed input contract proves otherwise. Agents retain
responsibility for semantics, unfamiliar technology, computed behavior, and
unknowns.
