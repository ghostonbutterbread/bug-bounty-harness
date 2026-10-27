# Browser/proxy orphan lifecycle integration dossier

- **Status:** local parent feature checkpoint; browser stop fence reviewed and merged into the feature, but no `beta` integration, push, runtime activation, or papercut closure.
- **Owner branch/worktree:** `fix/papercut-orphan-lifecycle` in `/home/ryushe/worktrees/bbh-papercut-orphan-lifecycle`.
- **Base / intended integration target:** fetched `origin/beta` at `d5853a9`; target `beta`, not `main`.
- **Inspiration:** PC-20260927-194446-2f4b6822; Discord thread 1564696750067949650.
- **Recovery commits:** parent `3914110` (proxy owner-PID guard); child `81dc490` (stop-fence tip); parent merge `e1b1e60`; beta reconciliation `9bc561f`; fixture/dossier checkpoint `cc35ee5`. This dossier-only correction follows that tested checkpoint.

## Implemented behavior

- Automatic browser retirement checks exact active canonical lease ownership and reports bounded refusal categories; missing task terminality, activity, or verified stop is not replaced with age or absent lane directories.
- Explicit and automatic browser stop/release share a manager/canonical fence across exact ownership, reservation, verified unit/root/CDP termination, and canonical release. Ambiguous systemd status is not stop proof. Direct canonical release refuses all managed leases, including during startup; failed-start cleanup stays under the provisioner's exact-owner/stop-proof gate. Interrupted-stop recovery is tied to the same owner and independent terminal proof.
- A supplied task-proxy owner PID is rechecked before reservation; a vanished or reused PID cannot silently produce an ownerless row. Proxy finishing remains independent of browser release and requires terminal owner and replay quiescence.
- No retroactive task owner was assigned and no legacy Hoster browser or MITM service was stopped.

## Verification and review

- Independent stop-fence review at child `81dc490` found no remaining merge-back blocker and recommended merge into the parent only, not beta activation. The child branch dossier was retired from the parent after merge; its history remains reachable through `e1b1e60`.
- After merging child `81dc490` and reconciling `origin/beta` (`d5853a9`) into the parent, the ten-module focused suite passed **304 tests and 41 subtests**, with two existing real-flow proxy fixture cases excluded.
- The real-flow proxy fixture used positional mitmproxy connection constructors incompatible with the installed version. Changed only that test fixture to keyword-only `Client` and `Server` arguments; both formerly excluded cases passed. The complete ten-module suite then passed **306 tests and 41 subtests**, no deselections, using `--basetemp` under the Hermes scratch root to avoid an AF_UNIX socket-path limit. `git diff --check` passed. No live Hoster calls in these tests.
- **Final decision:** independent reviewer accepted `cc35ee5` as a partial safety patch for beta with no code blocker. The dossier-only `15855f4` corrects checkpoint wording; the clean, current `beta` worktree is `/home/ryushe/worktrees/bbh-beta-integration-offline` at `d5853a9`. Fetch current beta again before integration, merge deliberately, remove this branch-local dossier on beta, and rerun focused tests. No runtime/Hoster activation or papercut closure follows from publication.

## Blocker and exact resume point

Historical Hoster rows have no trustworthy task owner/terminal generation. The task-terminal child `328b8d3` documents that local Kanban completion cannot prove termination of independent Hoster provisioner callers. The missing source is a Hoster launch-supervisor generation and durable terminal event bound to exact browser/proxy leases; until available, old ownerless rows must remain retained for operator/manager-authoritative reconciliation. Do not infer safe cleanup from idle time, dead directories, or quiet traffic. The original papercut remains open and this feature must not be presented as a complete orphan cleanup fix.

Integrate the reviewed partial patch into the clean/current beta worktree, remove this temporary dossier there, and verify on the integrated tree. For ownerless cleanup, obtain exact task-terminal evidence and verify replay clients and unit identity per row before any release. No mass-stop, deployment, or stable promotion is implied by this checkpoint.
