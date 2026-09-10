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

- **BBH infrastructure or cross-skill harness helper:** `scripts/`.
- **Vulnerability-class helper:** `skills/<skill>/scripts/`, such as
  `skills/xss/scripts/`. An existing capability owner such as Recon also keeps
  its focused helper in that skill's `scripts/` directory.
- **Program-specific helper whose program has a BBH skill:**
  `skills/<program-skill>/scripts/`.
- **Abstract reusable bug bounty tool with no existing class, capability, or
  program owner:** `skills/bounty-tools/scripts/<category>/`. Reuse an existing
  responsibility category; if none fits, create one narrow category and index
  rather than using `misc`, `general`, or the top-level Bounty Tools script
  directory.
- **Importable harness runtime implementation:** the responsibility-owned
  package under `agents/`. New argv-oriented standalone helpers use one of the
  script homes above. Legacy entrypoints and existing cross-skill imports from a
  skill script directory are not moved automatically and must not be copied as
  the pattern for new shared modules.

New scripts must follow the selected repository lane and use repository-relative
paths. Do not hardcode a developer checkout, host, username, transient run, or
provider-specific runtime path.

## Index Contract

Every directory that owns executable scripts has a `README.md` containing the
script names, purpose, invocation or inputs, mutation boundary, verification,
owner/scope, last verification date, and coverage limits when heuristic. The
root [`scripts/README.md`](scripts/README.md) indexes BBH-wide helpers and links
every skill-owned script index.

`skills/bounty-tools/scripts/README.md` owns the category catalog for abstract
bug bounty tools. Category directories contain the actual scripts and their
complete local records; executable files do not live directly in the Bounty
Tools script root.

When adding, renaming, moving, or removing a script, update the nearest index in
the same change. An index is discovery metadata, not proof that the script is
exhaustive or correct.

The root catalog link is the scripts-only discovery path. A skill owner may link
its local script index from `SKILL.md`, but creating or maintaining a script does
not grant the scripts-only lane authority to edit that policy file.

## Scripts-Only Maintenance Boundary

An explicitly authorized script-maintenance agent may change:

- canonical scripts in the homes above;
- directly associated tests and fixtures;
- the nearest script index and the root `scripts/README.md` catalog link;
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
