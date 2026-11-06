# OMP Bunny worker routing

An OMP `task` child is a native subagent only when the task tool launches it. An interactive terminal or a model name in the packet is not proof of native delegation. Before dispatch, check that OMP advertises the named `bunny-recon`, `bunny-hunter`, `bunny-verifier`, and `bunny-reporter` roles; do not substitute generic `task` for a specialist if it does not have the desired model grant or policy.

## Requested worker model

If no worker model was requested, Bunny selects the parent's active route. OMP can prefer the named agent's frontmatter `model` to the parent's active model, so omission of the per-call model does **not** establish inheritance. Inspect the selected agent and effective route; if necessary, pass the parent's active route explicitly as an authorized per-call selector and verify the child's actual model. If policy or configuration prevents that, report the blocker rather than using the frontmatter model silently.

Resolve an authenticated, available provider-qualified selector exactly. A named role's default `model` is not an authorization grant for a different per-call model. Check `task.perCallModel`, project restrictions and `task.agentModelOverrides`: a named agent override can conflict with a per-call `model`. Do not bypass a denial or silently use another model.

For a new OMP coordinator process, a protected, operator-controlled run-scoped config overlay can grant the exact selector without changing the coordinator's active model. For example, replace the value with the selected available route:

```yaml
modelRoles:
  bunny_worker: zai/glm-5.3
```

Start OMP with `--config /absolute/path/to/bunny-run.yml`, then provide both `agent: bunny-recon` (or the other exact named role) and `model: zai/glm-5.3` in the relevant `task` item. A role grant is not itself a model invocation or evidence of authentication. Keep the overlay protected, present and unchanged through confirmed exit of each child; grants can be rechecked during child requests. The user-specified route, mode and live-activity scope still govern every packet.

An existing process cannot acquire a new CLI `--config` path. If a trusted overlay was already supplied at startup, its operator may update it before dispatch; otherwise request an appropriately launched coordinator or report the blocker. Do not change global configuration or persist `/model` roles for one run. Switching the coordinator's active model or creating a session-local generic agent is not equivalent to applying the requested route to a named specialist without changing the coordinator; do not silently substitute either.

## Verification and safety

Installed OMP native task children run headless with `tools.approvalMode: yolo`; their parent `task` approval is the authorization boundary, subject to explicit tool policies. The parent can itself be configured to auto-approve, including via `yolo`, so its launch settings alone do not prove a gate. Before live dispatch, require a verified, non-bypassed parent task-approval boundary and applicable tool policies for the bounded packet. If that boundary cannot be verified, stop before launching a live worker; do not rely on the headless child's own approval mode or bypass a denial.

Confirm the effective model and provider in each child session's own metadata before live actions, not merely in the parent's intent, config, model catalog or `task` input. Record each child ID and require confirmed exit before releasing its slot or surface lease. If the native route, approval gate or effective model cannot be verified, stop before live work and report the precise blocker.
