# VPN manager inspection routing integration dossier

- **Status:** blocked — provider release and independent review pending
- **Owner:** Hermes, delegated BBH routing worker
- **Branch / owning feature ref:** `feat/vpn-manager-inspect-routing`
- **Worktree:** `/home/ryushe/worktrees/bbh-vpn-manager-inspect-routing`
- **Base commit:** `a2d92142de025966e60def389935334d2470c672` (fetched `origin/beta`, supplied by parent)
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-16
- **Latest immutable recovery checkpoint:** `a2d92142de025966e60def389935334d2470c672` (base; implementation commit pending)
- **Feature implementation commit(s):** pending
- **Canonical references:** BBH `skills/mullvad/SKILL.md`; General Skills `script-manager` skill and its `scripts/README.md` index.

## Intent and implemented contract

Route agents to the General Skills `egress_inspect.py` as an optional read-only IPv4 local snapshot without changing current manager selection, existing commands, fallback, safety gates, or VPN state. The helper is informative, not evidence of public IP, DNS, IPv6, fail-closed behavior, or ISP exposure; absence of the helper means continue existing inspection, not infer a manager is absent. No helper implementation is added to BBH.

## Evidence and review

- Strict RED: `python3 -B -m unittest discover -s tests -p test_mullvad_inspect_routing.py -v` failed because the `script-manager` route was missing.
- GREEN: the same command passed, one test. Both invocations ran as subprocesses with private scratch `HOME`, XDG directories, and `TMPDIR`, under inherited libseccomp network denial; a child socket probe confirmed `EPERM`. No VPN or network state was touched.
- Baseline preservation: a local `git show` comparison after removing the inserted paragraph showed every byte of the original Mullvad skill was unchanged. `git diff --check` passed.
- Full suite was not run; the focused test exercises the documentation routing contract only. Actual helper discovery/execution and active runtime verification remain deferred to the released provider; no live-network test was attempted.
- Independent review: pending. The General Skills helper was not present in the provider checkout at this worker's inspection, so its interface and release cannot yet be verified here.
- Beta ancestry: task branch starts at supplied fetched `origin/beta` base above. No subsequent fetch was performed because this task forbids network operations.

## Blockers and deferred work

1. **Missing evidence:** released General Skills `egress_inspect.py`, its indexed discovery/usage, and representative offline fixture checks of its interface against the routing text. **Environment:** released provider checkout plus private HOME/XDG/TMPDIR and network-denied subprocess; consult the released `script-manager` index for its actual command and fixtures rather than guessing flags. **Trigger:** provider release. **Impact:** blocks beta integration and activation. **Next:** parent verifies the provider release and runs its offline fixture tests and the consumer discovery path.
2. **Missing evidence:** independent review of the complete branch diff and test receipts. **Trigger:** provider release and complete candidate. **Impact:** blocks beta integration. **Next:** parent obtains review and resolves findings.
3. **Missing evidence:** fresh `origin/beta` comparison and post-integration test. **Trigger:** parent has network authorization and the other gates pass. **Impact:** blocks integration, push, and activation. **Next:** parent fetches, reconciles and retests before a separately authorized integration.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/vpn-manager-inspect-routing`
- **Latest immutable recovery checkpoint:** base above; update after implementation commit.
- **Exact resume point:** verify released provider/index, obtain independent review, compare current beta, and rerun focused isolation tests; do not merge, push, or activate before those gates.
- **Working-tree state at handoff:** to be recorded after checkpoint.

## Decision gates

- **Integration:** provider release, consumer/provider evidence, independent review, current beta comparison, and passing checks.
- **Activation:** separately verify the selected runtime loads both released skills; not authorized by this task.
- **Promotion:** stable remains outside this task and requires explicit authorization.

## Decision record

- 2026-11-16 — candidate created; integration blocked on provider release and review.
