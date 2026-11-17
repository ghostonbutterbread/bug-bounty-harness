# VPN manager inspection routing integration dossier

- **Status:** independently reviewed; provider published, beta integration pending
- **Owner:** Hermes, delegated BBH routing worker
- **Branch / owning feature ref:** `feat/vpn-manager-inspect-routing`
- **Worktree:** `/home/ryushe/worktrees/bbh-vpn-manager-inspect-routing`
- **Base commit:** `a2d92142de025966e60def389935334d2470c672` (fetched `origin/beta`, supplied by parent)
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-16
- **Latest immutable recovery checkpoint:** `a53b723d23c7defbd6ba5018781ef57761cb3b0d`
- **Feature implementation commit(s):** `a53b723d23c7defbd6ba5018781ef57761cb3b0d`
- **Canonical references:** BBH `skills/mullvad/SKILL.md`; General Skills `script-manager` skill and its `scripts/README.md` index.

## Intent and implemented contract

Route agents to the General Skills `egress_inspect.py` as an optional read-only IPv4 local snapshot without changing current manager selection, existing commands, fallback, safety gates, or VPN state. The helper is informative, not evidence of public IP, DNS, IPv6, fail-closed behavior, or ISP exposure; absence of the helper means continue existing inspection, not infer a manager is absent. No helper implementation is added to BBH.

## Evidence and review

- Strict RED: `python3 -B -m unittest discover -s tests -p test_mullvad_inspect_routing.py -v` failed because the `script-manager` route was missing.
- GREEN: the same command passed, one test. Both invocations ran as subprocesses with private scratch `HOME`, XDG directories, and `TMPDIR`, under inherited libseccomp network denial; a child socket probe confirmed `EPERM`. No VPN or network state was touched.
- Baseline preservation: a local `git show` comparison after removing the inserted paragraph showed every byte of the original Mullvad skill was unchanged. `git diff --check` passed.
- Full suite was not run; the focused test exercises the documentation routing contract only. Actual helper discovery/execution and active runtime verification remain deferred to the released provider; no live-network test was attempted.
- Independent review accepted the BBH route while finding a cwd-dependent provider usage command. The provider corrected that issue; independent re-review approved it and passed seven provider tests and this routing test under network denial. General Skills beta published `448e02a2efcd8a7f9140a2f9c0b6175eb34ff3db`; parent verified remote readback, seven inspector tests, 11 script-policy tests, and an actual read-only invocation through the Ghost projected helper from the BBH cwd. This is not public egress or rotation evidence.
- Beta ancestry: parent fetched and confirmed the selected BBH beta and remote at `a2d92142de025966e60def389935334d2470c672`; re-fetch immediately before integration.

## Blockers and deferred work

1. **Provider:** General Skills beta `448e02a2efcd8a7f9140a2f9c0b6175eb34ff3db` is published; the projected Ghost helper and the offline cross-cwd contract were verified. Hoster runtime deployment and read-only smoke remain separate.
2. **Review:** complete for the bounded BBH route and provider cwd correction; fresh beta comparison and post-integration verification remain required.
3. **Wider refresh:** public-IP observation and coordinated rotation are not implemented by this slice and must not be represented as active.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/vpn-manager-inspect-routing`
- **Latest immutable recovery checkpoint:** `a53b723d23c7defbd6ba5018781ef57761cb3b0d`; check the current branch tip for this dossier-only handoff update.
- **Exact resume point:** verify released provider/index, obtain independent review, compare current beta, and rerun focused isolation tests; do not merge, push, or activate before those gates.
- **Working-tree state at handoff:** clean after the dossier-only handoff commit; verify with `git status` when resuming.

## Decision gates

- **Integration:** provider release, consumer/provider evidence, independent review, current beta comparison, and passing checks.
- **Activation:** separately verify the selected runtime loads both released skills; not authorized by this task.
- **Promotion:** stable remains outside this task and requires explicit authorization.

## Decision record

- 2026-11-16 — candidate created; integration blocked on provider release and review.
