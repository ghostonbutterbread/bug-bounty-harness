# Browser lease recovery — integration dossier

## Ownership and integration boundary

- Task: benign browser resource lifecycle; Kanban `bug-bounty-harness/t_6f1fc293` (parent owns coordination).
- Branch: `feat/browser-lease-recovery`.
- Worktree: `/home/ryushe/projects/bug_bounty_harness/browser-lease-recovery`.
- Fetched base: `69e9a2a01be26ea1e64a0d00fd6cf23a47704e4e` (`origin/beta`).
- Intended target: **beta**, only after fresh independent parent review.
- No push, merge, deployment, Hoster operation, real account session, or live-site browsing authorized by this implementation handoff.
- Checkpoint: pending implementation commit; subsequent dossier-only commit will record its immutable SHA.

## Intent and implemented contract

Separate browser profile lifetime from controller ownership. Do not use memory pressure or idle age as proof that an owner abandoned work. Changes are generic resource management, not vulnerability testing or program authorization.

### Explicit general-purpose task browser

`request --task-owned --agent-id A --run-id R --owner-pid PID --purpose TEXT` omits both program and account. It creates an isolated task namespace keyed by agent/run; conflicting program/account/auth-domain arguments fail. The launcher never reads account inventory, imports seeds, or refreshes authentication in this mode. Multiple normal website authentications can coexist within this profile; this creates **no** combined program authorization scope. Named program/account/auth-domain leasing remains exact and exclusive. Task profiles survive process termination and participate in existing 14-day retention rather than being shared with another task.

### Lifecycle evidence and automatic management

An explicit **task-specific long-lived supervisor PID on the browser node** is captured with `/proc` start ticks, boot ID, and hostname. Do not supply this short-lived request CLI's PID, a remote PID, a generic daemon PID, or infer task completion from a run label. The task-specific process lifetime is the supported task lifecycle integration; inspection found no generic pre-existing authoritative task lifecycle hook in these scripts. Existing invocations without this identity remain accepted but report `owner_state: unknown`; they require explicit release and are not automatically declared abandoned.

A small per-browser user-systemd watcher renews managed leases every five seconds, notices terminal owners within its polling interval, fences their control, permits a 30-second recovery grace only for revocable browser-owned proxy sessions, then stops/verifies the recorded browser unit and releases its lease while retaining profile state. It is not a central queue/broker and does not migrate profiles between nodes. Active identified owners remain protected even past the old TTL and regardless of idle age. `reap-idle` is retained as a compatible command but runs evidence-based reconciliation, never idle eviction.

`touch --work-state awaiting-input --awaiting-seconds N` records an absolute deadline (1–3600 seconds, default 1800); repeated awaiting-input touches cannot extend it. An expired deadline cannot be renewed by a late touch. Explicitly returning to active before the deadline clears the bound. TTL minimum for new requests is 30 seconds. Unknown lifecycle evidence is reported honestly, not guessed terminal.

### Real control fencing and exact live handoff

New provisioned Chromium instances use **remote-debugging-pipe**, with no raw Chromium TCP debugging port. A small per-browser loopback HTTP/WebSocket adapter serves CDP discovery and browser/page sockets behind a random generation path. A private Unix control socket rotates that path, closes old WebSockets, detaches their CDP sessions, and awaits a pipe barrier before acknowledging handoff. Old established sockets and old URLs cease to control the browser; ownership changes are not merely metadata rotation.

A healthy exact program/account/auth-domain browser can survive an abandoned owner's handoff with the same process, tabs, and session state. Both requester and recorded browser must explicitly select `--proxy-ownership browser` with the same explicit fixed `--proxy-server` and certificate mode. This asserts that the route belongs to the browser rather than the old task. **Default task-owned proxy routes are never silently relabelled/transferred:** they force verified stop/restart using the new request's route. KasmVNC/manual display control cannot be revoked through this CDP adapter, so those browsers likewise require restart for cross-owner handoff. Legacy direct-CDP browsers are never promoted to live-transferable by rotating metadata.

The lease rotation is one SQLite transaction. A pending-transfer journal reconciles a crash between the canonical lease transaction and the manager projection before another mutating manager command runs. Old lease renew/release calls are rejected. Node-wide file locking serializes admission, handoff, release, and retention. Root PID identity and user-systemd InvocationID prevent treating PID/unit name reuse as the old resource. A stop is not successful until the unit is inactive, recorded root is gone, and CDP is unreachable. Retention also refuses another active/recent profile record, active profile lease, or an unknown/live Chromium SingletonLock (only an exact recorded dead root with no PID reuse clears a stale lock).

## Compatibility and limits

- Existing named and anonymous profile request, admission, proxy CA, display forwarding, and launcher authorization paths are retained. `--dry-run` remains available; direct real launcher admission bypass is not added.
- CDP consumers must retain the full returned URL **including its generation path**, not reconstruct it from the port. `/json/version`, `/json/list`, browser WebSockets, and page WebSockets are supported. This is not a complete implementation of every Chromium HTTP discovery/debug UI endpoint.
- Operational same-UID isolation, not a hostile same-UID security boundary. A process able to read the owner's files or access the private Unix socket can recover current control; adversarial separation requires separate OS identities. In-flight already-executed browser actions cannot be undone by a handoff; detachment prevents continued control after the fence acknowledgement.
- No account-concurrency relaxation, logout detection, secret extraction, authentication selection expansion, or scope-policy changes.
- A crash before the initial successful launch/owner registration can still leave a managed lease without sufficient runtime evidence. Such an entry stays locked for explicit reconciliation; this implementation does not guess that an unregistered browser is dead. Legacy records without verifiable root/unit identity similarly return `recovery-blocked` rather than killing a process by name. The tested crash journal covers **ownership transfer**, not every initial-provisioning interruption.
- User-systemd and Linux `/proc` are required. Watcher failure/restart and unidentifiable legacy owners remain visible operational concerns; no remote owner identity or cross-node state adoption is supported.
- Browser restart rather than live handoff is intentional when proxy/display/control revocation cannot be proven. It retains disk profile state but cannot promise preservation of unsaved tabs or in-memory state.

## Verification record

- No checkout-local environment existed at first use. Installed through `./setup.sh --install-python-deps`; after adding `aiohttp>=3.12,<4` to the sole root manifest, re-ran that installer. Resolved Bounty Core pin: `7b08495f65a50f733fc18213c38cc3ae8e91bdf5`; module resolved within this worktree's `.venv`.
- Final combined focused suite (including script-index policy and both real browser fixtures): **115 passed in 280.25 seconds**, no skips. Static undefined/unused-name checks and whitespace checks also passed before handoff.
- Real evidence: `docs/integrations/browser-lease-recovery-smoke.json`, written by the successful disposable fixture, not a synthesized result. The systemd fixture uses only temporary state/profiles, `about:blank`, and a loopback synthetic login server. It verifies automatic renewal, active-owner refusal, same-process/tab handoff, stale channel/URL/lease rejection, mandatory restart for a task-proxy handoff, persistent profile retention, task mode, two-host login-cookie continuity, automatic terminal cleanup, and 14-day manifest-only retention in dry-run and confirmed modes. The independent pipe fixture also verifies concurrent CDP responses and real WebSocket/URL revocation.
- Recovery/failure fixtures cover PID reuse, unknown/permission-denied owners, absolute awaiting-input expiry, service InvocationID reuse, unverified-stop refusal, atomic concurrent transfer, interrupted transfer projection recovery, stale lease mutation rejection, and unknown/reused-PID SingletonLock protection. These are temporary test registries; no account sessions were used.
- An early ten-second generic CDP response deadline proved too short for an ordinary local HTTP navigation. A raw-CDP control browser reproduced the local navigation delay; the adapter now allows bounded 60-second command responses. This was not solved by changing authentication, suppressing certificates, or altering site content.

Commands:

```sh
./setup.sh --install-python-deps
.venv/bin/python -m pytest agents/test_browser_lease_recovery.py agents/test_browser_lifecycle.py agents/test_browser_provisioner.py agents/test_browser_profile_lease.py agents/test_chromium_test_launcher.py -q
BBH_LOCAL_BROWSER_SMOKE=1 BBH_BROWSER_SMOKE_RECEIPT=docs/integrations/browser-lease-recovery-smoke.json .venv/bin/python -m pytest agents/test_browser_lease_recovery.py agents/test_browser_lifecycle_systemd.py agents/test_browser_lifecycle.py agents/test_browser_provisioner.py agents/test_browser_profile_lease.py agents/test_chromium_test_launcher.py tests/test_script_policy.py -q
uvx ruff check --select F skills/chromium-test/scripts/browser_provisioner.py skills/chromium-test/scripts/browser_control.py skills/chromium-test/scripts/browser_lifecycle.py agents/test_browser_lease_recovery.py agents/test_browser_lifecycle.py agents/test_browser_lifecycle_systemd.py
git diff --check
```

## Parent-owned documentation corrections (not applied here)

Update `skills/chromium-test/SKILL.md`, the Chromium Test playbook, and shared browser-profile coordination guidance to describe explicit task-owned mode, task-supervisor PID evidence, automatic lifecycle renewal/cleanup, bounded awaiting-input, and exact fenced live reuse. Replace instructions requiring agents to remember periodic touch/release as the sole lifecycle mechanism. Retain explicit terminal release for legacy/unknown owners and manual early completion. Explain browser-owned versus task-owned proxy attribution, conservative KasmVNC/legacy restart fallback, full generation-path CDP URLs, same-UID limitations, and local-only deployment gate. Do not merge task authentication with program authorization or relax profile exclusivity.

## Next gate and activation boundary

Use a generous fixture timeout (at least 600 seconds on loaded hosts); the last local run took 280 seconds, mostly browser startup/navigation. A killed/failed fixture must stop only its recorded task units and verify recorded roots before removing its temporary profile tree.

Fresh independent reviewer must rerun focused suites and the opt-in disposable local fixture from this branch, inspect failure/ownership paths and dossier against the diff, and decide whether additional generic CDP-client compatibility coverage is needed. Parent owns any beta reconciliation/integration. No stable promotion or runtime activation is implied. Remove this transient dossier from the integration lane when the feature is accepted; preserve it in feature history if blocked.
