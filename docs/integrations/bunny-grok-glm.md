# Bunny Grok + GLM routing integration dossier

- **Status:** feature
- **Owner:** Hermes; Kanban `t_983bf48f`
- **Branch / owning feature ref:** `feat/bunny-grok-glm`
- **Worktree:** `/home/ryushe/worktrees/bbh-bunny-grok-glm`
- **Base commit:** `611ae6bbe11d2ec979bd87c7ce934abceaff6961` (fetched `origin/beta`)
- **Intended integration target:** `beta`; no stable or Hoster rollout
- **Last updated:** 2026-10-22 (local)
- **Latest immutable recovery checkpoint:** `9396a9d` on `feat/bunny-grok-glm`
- **Feature implementation commits:** `9396a9d`
- **Inspiration:** Ryu Discord thread/message `1563028030576926720`; Bunny mode/model owner; installed Hermes CLI help and provider profiles; official Hermes xAI OAuth and delegation documentation retrieved read-only.

## Intent and implemented contract

A thin coordinator preset in the existing Bunny router loads a skill-local
reference. `bunny grok w/ glm` / `with glm` means Grok 4.6 high coordinator and
GLM-5.3-Flash max workers. Ordinary explicit worker aliases, default
collaboration, multi limits, offhand conflict, policies, approvals and evidence
ownership remain unchanged. No parser/launcher, provider mapping registry,
credential migration, global settings, or new security authority is added.

The reference checks real host/profile auth, eligible Hermes xAI/API/OAuth or
Grok CLI transport, coordinator handoff/sole ownership, and independently
verified mixed-provider model/effort workers. Prompt text does not enforce the
model route. Unsupported or unauthenticated selections report blocked instead
of silently substituting models/providers or reducing effort.

## Evidence and review

- Focused stdlib Bunny suite: 12 tests passed; includes ordinary routing and
  new preset contract, mixed transport, missing-link/reference negative tests.
- Installed Hermes chat help confirms invocation-scoped model/provider and
  reasoning flags. Existing ZAI provider maps GLM 5.3 max to native effort.
- Real read-only model smoke: session `20261022_201852_75c225` returned
  `BUNNY_GLM_OK`, zero tools, clean CLI exit; session DB confirms
  `glm-5.3-flash`, billing provider `zai`, reasoning enabled/effort `max`.
- Local `hermes auth status xai` and `xai-oauth`: logged out; no Grok CLI
  executable found in PATH/known local bins and no Grok CLI auth file. One
  bounded Hoster inspection found no Grok executable/auth file; no remote
  source/runtime changes or agent launches performed.
- Independent review: pending; review neighboring `bunny-collaborative`,
  `bunny-multi`, ordinary worker-selection rules and selected provider semantics.
- Full `tests/` after the repository installer provisioned checkout-local
  dependencies: 325 passed, 1 skipped, 196 subtests passed, 3 unrelated failures.
  Those failures (stack-to-program missing index fields, its direct-checkout
  command example, upload-surface old exact wording assertion) also reproduce
  on unchanged base beta `611ae6b`; focused base rerun: 3 failed / 5 passed /
  7 subtests passed. No unrelated fixes included.
- Fresh GLM read-only semantic consumer loaded both candidate files and correctly
  explained coordinator/workers, effort, multi/default collaboration, API auth
  fallback and explicit worker alias. Its long max-reasoning response hit the
  outer terminal timeout before the final scenarios completed; it is a partial
  navigation receipt, not a complete consumer pass. No matching process remained.
  Independent review covers the complete scenario set.
- Focused security-profile sync dry-run: four Bunny destination links already
  resolve to the beta integration checkout, zero planned link/adopt/prune
  changes. No sync apply or unrelated source refresh performed.

## Deferred runtime evidence

- **Missing evidence:** authenticated Grok 4.6 high response; PTY coordinator
  acceptance/status; an actual Grok-coordinated GLM checkpoint/steer/exit.
- **Environment/command:** authenticated Grok CLI with verified session model
  and effort controls, or interactive Hermes xAI command from the reference;
  GLM worker command also from the reference. Use a synthetic offline objective
  first and verify each effective route and approval gate.
- **Trigger:** user provides/activates eligible Grok login/access on the campaign
  host; never solicit secrets in chat or transfer another profile's auth.
- **Boundary:** prevents claiming the end-to-end Grok campaign has run, not
  integration of the conditional skill route; no live target campaign starts
  from this authoring request.
- **Next step:** independent review + final checks; integrate conditional route
  into beta, verify local resolver, report runtime auth limitation explicitly.

## Decision gates and resume

- Integration requires focused/full check reconciliation and independent review.
- Local activation requires reviewed beta source, existing managed projection,
  and fresh actual skill/reference resolver loads. No other-profile changes.
- Stable promotion and Hoster rollout are separate owner decisions.
- Resume at independent review/full check gate on this feature branch; all
  task-owned material is committed with this dossier before handoff.
