# Browser safe cleanup and resume integration dossier

- **Status:** blocked (automatic stopped-process restore deferred)
- **Owner:** feature worktree agent, parent integration owner t_a6a67529
- **Branch / owning ref:** `feat/browser-safe-resume`
- **Base commit:** `eaa6cca5483e12b79a427bc06cac1629673e3348` (`origin/beta` fetched)
- **Intended integration target:** `beta`
- **Latest immutable recovery checkpoint:** branch commit accompanying this dossier (read branch tip)
- **Feature implementation commit(s):** branch commit accompanying this dossier
- **Inspiration:** capacity incident where four active browser units were stopped by a mismatched suffix; existing request-triggered two-hour CDP idle sweep.

## Intent and implemented contract

Provisioner `cleanup` dry-run reports node admission and per-browser safe refusal reasons. `--apply` admits only canonical manager-owned, exact-invocation healthy units with positively terminal owner, zero attached CDP clients and tracked idle >=7200 seconds; atomic detached-activity freeze, stop verification and canonical release remain required. Active owners are protected also in the existing request-triggered idle sweep. No proxy listener is finished or profile deleted.

`request` no-capacity returns a safe cleanup next step and retains bounded retry behavior and identity. `resume --browser-id --agent-id --run-id` checks exact owner, canonical lease, healthy unit/CDP and proxy/CA; returns the existing ID or a refusal. Verified stopped IDs explicitly return `safe-launch-recipe-unavailable`; task-owned absent profile reports state loss. No automatic restart, auth clone, proxy reroute, display substitution or account change. Fresh ordinary request remains the path with explicitly repeated parameters and new ID, followed by authentication verification.

## Evidence and review

- `python -m pytest agents/test_browser_safe_resume.py agents/test_browser_provisioner.py agents/test_browser_lease_recovery.py -q -k 'not test_task_proxy_completion_indexes_private_default_and_releases'` — 68 passed, 2 deselected (includes attached-client fixture).
- Full same selection without exclusions — 45 passed, 3 failed before fixture correction (one newly added test corrected; two existing real mitmproxy fixtures fail because installed `connection.Client` now requires keyword arguments; no production change for that unrelated dependency drift).
- `.venv/bin/python` absent in this worktree; system Python used for fixtures only, never real browser provisioning.
- Four simulated live owners with 90000 seconds CDP idle and `--apply`: zero stops, four `owner-active-or-unverified` reasons.
- `git diff --check` clean. No Hoster runtime or live browsers touched.
- Independent review: pending parent.

## Blockers and deferred work

- **Missing:** retained, privacy-reviewed launch recipe that binds original exact program/account, automatic/explicit slot selection, proxy ownership/CA, display and graphics mode, profile provenance, origin artifact root and auth state to the stopped browser; safe replay through normal admission and lease without duplicate identity. A launcher command or positional manager row cannot substitute.
- **Trigger:** implement durable recipe on successful start with migration/reconciliation of legacy rows and tests for stopped persistent and missing task-owned profiles, proxy/display conflict, concurrent admission and new-ID linkage. Then run disposable systemd/browser fixture (`BBH_LOCAL_BROWSER_SMOKE=1`) on an isolated browser node. Until then automatic stopped-process restore is blocked, not claimed.
- **Existing test blocker:** run pinned checkout interpreter and compatible mitmproxy version for `agents/test_browser_provisioner.py::test_task_proxy_completion_indexes_private_default_and_releases`, or repair its fixture API on a separate task; current global mitmproxy positional `Client` constructor fails before feature logic.

## Handoff and decision gates

- **Exact resume point:** parent reviews feature diff and receipts, reruns focused fixtures, decides whether safe subset meets acceptance; independently gates beta integration. Do not merge/push or activate this branch from this agent.
- **Working tree at handoff:** clean after checkpoint commit.
- **Integration gate:** independent review of refusal/stop boundaries and portability, plus existing dependency fixture decision.
- **Activation gate:** selected beta runtime install and isolated systemd fixture, not this branch-only test.
- **Promotion gate:** separate owner decision; no stable promotion implied.
- **Decision:** partial safe subset; no automatic restore claim.
