# BBH Repository-Local Script Policy

Status: active
Owner: BBH maintainers

This is the repository-local script policy discovered through the shared
`script-manager` skill when creating or maintaining scripts. It owns BBH script
placement, indexing, and maintenance conventions. Shared safety, authorization,
scope, and lane rules still apply.

## Discover Before Creating

Before a coordinator assigns tooling or a worker creates it, load `script-manager`
and name the job's input, output, program boundary, and whether it is a command
or a component of an existing runner. Start with [`scripts/README.md`](scripts/README.md),
then inspect the nearest skill-owned `scripts/README.md`, established `agents/`
modules, and the resolved program lane's `scripts/README.md` when present.
Select an existing owner before proposing a new path. If an indexed script does
the job, run it with program-specific inputs; do not copy it into the program.
If its responsibility matches but a case fails, extend or repair that owner
with the triggering fixture and false-positive checks. A new module of an
existing runner is often better than a competing command. Do not create a
scratch replacement for maintained behavior.

When a coordinator assigns a **specific script job**, record one short packet
decision: `reuse <owner and index>`, `extend <owner and missing case>`, or
`new <distinct responsibility, home, and gap in existing owners>`. If the job
is exploratory and its inputs or tooling are not known yet, ask the worker to
check the relevant indexes **when scripting becomes useful**, then report its
choice before creating or promoting a helper. The worker may revise a packet
choice on evidence; this is not a ban on exploratory scratch code or a
substitute for runtime judgment. A run-local experiment stays scratch until
promotion is reviewed. Repeated program-only utility belongs in that program's
indexed script home; a generally useful pattern belongs in a BBH owner, not
copied into several programs.

Multiple cohesive scripts are encouraged when they perform different jobs, have
different interfaces, or need independent tests and lifecycles. Do not force
unrelated behavior into one giant script merely to reuse a filename.

## Placement by Owner

- **BBH infrastructure or cross-skill harness helper:** `scripts/`.
- **Vulnerability-class helper:** `skills/<skill>/scripts/`, such as
  `skills/xss/scripts/`. An existing capability owner such as Recon also keeps
  its focused helper in that skill's `scripts/` directory.
- **Program-specific helper whose program has a BBH skill and whose behavior is
  owned by that skill:** `skills/<program-skill>/scripts/`. A local utility that
  is not part of that skill's interface follows the program-only route below.
- **Recurring program-only helper not owned by a BBH program skill:** the resolved
  program family/lane's `scripts/` directory in Shared, with a local
  `scripts/README.md`. Resolve the lane through `bounty-storage`/the storage
  resolver; do not guess a `web` path or use cwd. Keep only small, reviewed,
  non-secret code and index entries there; large dependencies, raw inputs,
  outputs, and credentials belong in their separately governed stores. Run
  these by their resolved path, not through `bbh` (which dispatches only
  repository-owned scripts). Preserve the tested revision/hash and review
  evidence in the index before treating one as maintained. When it becomes
  cross-program, move its implementation to the appropriate BBH owner and
  update/remove the program entry instead of copying divergent versions.

  The selected lane's `context/target_profile.json` contains `canonical_root`
  (the resolved lane root), `program`, `family`, and `lane`; use the already
  selected profile, not a path guessed from cwd. For example, with `PROFILE`
  set to that profile's path, this read-only lookup finds the index:

  ```bash
  script_index="$(python3 -c 'import json,sys; from pathlib import Path; p=json.load(open(sys.argv[1])); print(Path(p["canonical_root"])/"scripts"/"README.md")' "$PROFILE")"
  # Read the selected entry before running its documented command.
  ```

  A documented Python helper in that directory can be invoked as
  `python3 "$(dirname "$script_index")/helper.py" --help` after checking the
  index and the tested revision; do not use the `bbh` repository dispatcher.
- **Abstract reusable bug bounty tool with no existing class, capability, or
  program owner:** `skills/bounty-tools/scripts/<category>/`. Reuse an existing
  responsibility category; if none fits, create one narrow lowercase kebab-case
  category and index rather than using `misc`, `general`, `other`, or the
  top-level Bounty Tools script directory. Executables live directly in the
  category directory, not in nested subdirectories.
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
every skill-owned script index. A program-lane index is local to that program,
not a link in the BBH-wide index. For a maintained Shared program script, also
record a non-secret revision/hash and review pointer so later agents can tell
which code was checked. An unreviewed scratch file is not an indexed tool.

`skills/bounty-tools/scripts/README.md` owns the category catalog for abstract
bug bounty tools. Category directories contain the actual scripts and their
complete local records; executable files do not live directly in the Bounty
Tools script root. Each populated category has exactly one canonical catalog
entry: `- [Category name](category-name/README.md)`. The catalog contains no
alternate, stale, titled, angle-bracket, or non-index category links. When no
categories exist, its Categories section contains exactly
`No categories are currently registered.`

The Bounty Tools catalog is fixed discovery metadata: it contains only its
title, plain-code policy pointer, one `## Categories` section, and either the
empty sentinel or canonical category entries. Extra prose, headings, and links
are prohibited from that file. This intentionally keeps validation independent
of general Markdown parsing.

When adding, renaming, moving, or removing a script, update the nearest index in
the same change. An index is discovery metadata, not proof that the script is
exhaustive or correct.

## Manager and Other-Agent Maintenance Boundary

Hermes is the repository manager and may edit code, skills, and policies within
the authorized task. Existing scope, protected-file approval, review, and
lifecycle requirements still apply; the scripts-only boundary below limits other
agents' maintenance authority, not Hermes's manager role.

Other agents may implement scoped scripts under an explicitly authorized
script-maintenance task. They may change:

- canonical scripts in the homes above;
- directly associated tests and fixtures;
- associated script map/index entries, freely maintained within the existing
  repository `docs/`, `references/`, or skill-local README layout, including
  every required ancestor inventory entry, such as the Bounty Tools category catalog
  and root `scripts/README.md` link;
- add a pointer to the script map at the bottom of the owning skill's main
  `SKILL.md` only; no unrelated body edits are allowed;
- the branch-local integration dossier.

Creating a script MUST update its map in the same change.

Except for that pointer addition, other scripts-only maintenance agents must not edit
`SKILL.md`. They must not edit `SCRIPT_POLICY.md`, `AGENTS.md`, prompts, other
policy documents, stable/main branches, repository settings, or unrelated code.
Route broader code changes as proposals and broader skill or policy changes as
skill seeds to Hermes. Map/index authority covers associated entries, not
unrelated normative prose. Normal branch, test, independent review, and release
guidance still applies.
