# Bug Bounty Harness — Agent Instructions

## Recon-Ry ownership boundary

`agents/recon_ry.py`, `skills/recon-ry/`, and `prompts/recon-ry-playbook.md` are **BBH wrappers and integration guidance**. They own only:

- saved-scope and exact-origin validation;
- safe auth-seed handoff, rate configuration, remote launch/status, and artifact ingest;
- how BBH agents call the installed Hoster-side Recon-Ry tool.

They do **not** own Recon-Ry profiles, stages, CLI flags, tool behavior, or output filtering.

Make implementation changes to the actual Recon-Ry tool in the canonical repository:

```text
~/tools/recon-ry/
remote: ghost-fork (ghostonbutterbread/recon-ry)
```

Examples: adding `recon --exact-urls`, changing profile stage lists, changing crawler/archive behavior, adding tool integrations, or changing project output behavior must be implemented and tested in `~/tools/recon-ry/` first. Only then update the BBH wrapper if its invocation, scope guard, or ingest contract needs to change.

Before assuming a BBH wrapper flag works, verify the matching Hoster-side Recon-Ry checkout is updated to the required Recon-Ry main commit.
