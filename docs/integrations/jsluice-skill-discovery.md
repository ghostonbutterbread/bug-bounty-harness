# JSLuice skill discovery integration dossier

- **Status:** independent review passed; beta integration pending
- **Owner:** Hermes BBH skill task
- **Branch/worktree:** `docs/jsluice-skill-discovery` at `/home/ryushe/projects/bbh-jsluice-skill-discovery`
- **Base / target:** fetched `origin/beta` `35912996eee3b90c865f7897a837b61e22baa85a` → `beta`
- **Implementation commit:** `9ecd4459310abfc8ba4788a344cb41865b2737b4`
- **Date:** 2026-10-06

## Intent and boundary

Ryu narrowed the request to making the upstream BishopFox JSLuice tool discoverable and actionable inside the existing `/js` skill. This replaces the proposed BBH parser wrapper; the old `feat/jsluice-offline-enrichment` branch remains unmerged and must not be integrated. No Recon-Ry change, new script, installation, network access, or runtime activation belongs to this task.

## Contract and evidence

The existing `skills/js/SKILL.md` now points to a direct local-file `jsluice urls` pass, optional `secrets` signals, inventory URL/hash/provenance pairing, bounded selection, and non-exhaustive review limits. The canonical playbook already mentions optional local JSLuice; no duplicate guidance change is required. Direct invocation of the locally built upstream parser against a synthetic local JS fixture returned four URL records including the computed `/api/accounts/EXPR/settings?view=full`; `secrets` completed with no matches. Skill discovery assertions and `git diff --check` pass. Only the skill and this temporary dossier differ from beta.

## Gate and resume point

Independent review must confirm there is no script, Recon-Ry, or stale wrapper dependency. On approval, record the decision here, integrate the skill only into a clean current beta worktree, remove this temporary dossier on the integration target, and verify the resulting beta diff. The unrelated dirty local beta checkout is not safe to use for integration until its owner reconciles it; no merge or push has occurred. Stable promotion and runtime activation are separate owner decisions.

## Review decision

Independent reviewer approved `9ecd4459310abfc8ba4788a344cb41865b2737b4` against freshly fetched `origin/beta` `35912996eee3b90c865f7897a837b61e22baa85a`: only the skill and temporary dossier differ; local upstream parser `urls` returned four records on a synthetic fixture and `secrets` exited 0, with no target traffic; skill assertions and diff check passed. Integrate only the skill; remove this dossier in beta. Do not merge the superseded parser branch.
