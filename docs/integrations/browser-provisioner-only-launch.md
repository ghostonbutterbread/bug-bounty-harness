# Browser provisioner-only launch integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `bug-bounty-harness/t_41b055ea-enforce-provisioner-only-browser-launche`
- **Base commit:** `978201a033225570fb974d2b7c51a1fbdea70cbe`
- **Intended integration target:** `beta`
- **Last updated:** 2026-08-27
- **Owning feature branch/ref:** `bug-bounty-harness/t_41b055ea-enforce-provisioner-only-browser-launche`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** SoundCloud Hoster browser-lifecycle diagnosis; Chromium Test skill.

## Intent

Prevent every real Chromium Test launch from creating an unregistered Chromium root that bypasses node admission, ownership records, and terminal cleanup. Hermes ordinary browsing remains separate through its managed browser provider; non-mutating Chromium Test dry-run planning remains available.

## Implemented contract

A real `chromium_test.py` invocation now exits before port/profile/process allocation unless it runs in the provisioner-created `browser-<uuid>.service` cgroup with a matching service-unit environment value. There is no Hermes or other direct-launch exception. Hermes ordinary browsing uses its managed provider; named test-account state, task MITM/provenance, CDP handoff, headed/fingerprint-sensitive runs, and terminal cleanup use the provisioner. The skill, playbook, README, and lease command hint distinguish that policy.

## Evidence and review

- Tests and commands: `env -u HERMES_AGENT -u BROWSER_PROVISIONER_UNIT uv run --project /home/ryushe/projects/bug_bounty_harness/.worktrees/t_41b055ea python -m pytest agents/test_browser_provisioner.py agents/test_chromium_test_launcher.py agents/test_base_team_runtime.py -q` — 50 passed.
- Focused smoke: direct real Chromium Test launches are refused even from a Hermes-marked environment; direct `--dry-run --json` succeeds. Provisioner request forwarding covers task proxy and KasmVNC display parameters.
- Independent review: three reviews found and removed a forgeable CLI marker, inherited Hermes identity bypass, and missing provisioner KasmVNC option forwarding. The remaining same-user systemd-unit forgery is documented as an operational-boundary limitation; explicit user direction accepts it for this rollout.
- Replay/cohort/fixture evidence: local temporary test fixtures only; no live browser or target traffic.
- Merge/ancestry evidence: branch starts from current `beta` commit `978201a033225570fb974d2b7c51a1fbdea70cbe`.

## Blockers and deferred work

- **Missing test or evidence:** Hoster deployment smoke.
- **Command / fixture / environment needed:** review this branch; after beta integration, deploy the reviewed checkout to Hoster and request one disposable browser through the provisioner.
- **Trigger to run it:** accepted beta merge and explicit runtime activation.
- **Why it blocks integration, activation, or promotion:** it does not block local feature review; it blocks claiming the Hoster runtime has adopted the guard.
- **Next completion step / successor reference:** inspect staged diff, obtain re-review, commit, then integrate only through the beta worktree.

## Interruption / resume handoff

- **Owning feature branch/ref:** `bug-bounty-harness/t_41b055ea-enforce-provisioner-only-browser-launche`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** after review/merge, deploy the reviewed beta checkout to Hoster and issue one disposable provisioner request; confirm recorded service ownership, CDP readiness, terminal release, and profile cleanup.
- **Working-tree state at handoff:** ready to commit.

## Decision gates

- **Integration gate:** focused tests pass, independent review finds no unresolved issue, and beta worktree is current/clean.
- **Activation / cohort gate:** Hoster fetches reviewed beta and passes a disposable provisioner-only smoke without modifying active browser runs.
- **Promotion gate:** explicit user direction for later stable promotion.

## Decision record

- 2026-08-27 — created after confirming live SoundCloud Chromium roots could exist outside the provisioner registry; implemented local guard and focused tests.
- 2026-08-27 — review identified a forgeable CLI marker and conflicting direct-launch guidance. Replaced it with Hermes runtime allowlisting plus a provisioner service marker; updated canonical guidance and expanded the focused suite.
- 2026-08-27 — follow-up review found the provisioner environment value forgeable. Bound the provisioner path to its matching user-systemd cgroup and made real-launch tests explicitly opt into the Hermes identity.
- 2026-08-27 — user chose a cleaner separation: removed the Hermes direct Chromium Test exception; Hermes ordinary browsing uses its own managed browser provider.
- 2026-08-27 — added provisioned KasmVNC parameter forwarding after review; all focused tests pass and the feature is ready for review/integration.
