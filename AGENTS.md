# Bug Bounty Harness — Agent Instructions

Read [`agents/index.md`](agents/index.md) before ordinary BBH runtime work. It
is the compact entry card: shared AI Policies own live-testing judgment, while
BBH skills own the selected runner, command, packet, and artifact mechanics.

## Recon-Ry ownership boundary

`agents/recon_ry.py`, `skills/recon-ry/`, and `prompts/recon-ry-playbook.md` are
BBH wrappers and integration guidance. They own only:

- saved-scope and exact-origin validation;
- safe auth-seed handoff, rate configuration, remote launch/status, and artifact ingest;
- how BBH agents call the installed Hoster-side Recon-Ry tool.

They do **not** own Recon-Ry profiles, stages, CLI flags, tool behavior, or
output filtering.

Make implementation changes to the actual Recon-Ry tool in the canonical
repository:

```text
~/tools/recon-ry/
remote: ghost-fork (ghostonbutterbread/recon-ry)
```

Examples: adding `recon --exact-urls`, changing profile stage lists, changing
crawler/archive behavior, adding tool integrations, or changing project output
behavior must be implemented and tested in `~/tools/recon-ry/` first. Only then
update the BBH wrapper if its invocation, scope guard, or ingest contract needs
to change.

Before assuming a BBH wrapper flag works, verify the matching Hoster-side
Recon-Ry checkout is updated to the required Recon-Ry main commit.

## Branch and execution workflow

For any source branch, worktree, merge, push, or promotion decision, load the
shared `branch-lifecycle` policy. This repository section applies that policy's
main → beta → feature-worktree topology locally and is a required operational
boundary, not optional documentation.

Use `main` as the reviewed stable lane, `beta` as the sole integration/testing
lane, and a dedicated local worktree plus named `feat/`, `fix/`, or `docs/`
branch for every coherent change. A task agent owns its assigned feature branch
only; it must not fold unrelated work or another project into that branch.

Before branching or merging, fetch `origin/beta`. Merge a reviewed feature into
a clean, current local beta worktree; run its checks; then push beta only from
that beta integration worktree with `git push origin beta`. Feature branches may
push only their own ref for backup/review. Never push `HEAD:beta`, force-push
beta, or merge directly into `main`. A non-fast-forward beta push is a stop and
intentional reconciliation condition, never permission to overwrite history.

Hoster is execution-only: it fetches a reviewed beta commit for an explicit
runtime test but never authors, commits, merges, or pushes harness source.
