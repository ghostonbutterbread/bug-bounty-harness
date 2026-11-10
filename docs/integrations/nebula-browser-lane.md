# Nebula browser lane integration dossier

- **Status:** feature
- **Owner:** hermes
- **Branch:** feat/nebula-browser-lane
- **Base commit:** a5103e811f9f18eb4aa001a13073a6d47ea108c0
- **Intended integration target:** beta
- **Last updated:** 2026-11-10
- **Owning feature branch/ref:** feat/nebula-browser-lane
- **Latest immutable recovery checkpoint:** 9126c94819a94fa0d63af4e77cc9f8f83f0c8c7f
- **Feature implementation commit(s):** 9126c94819a94fa0d63af4e77cc9f8f83f0c8c7f
- **Inspiration / canonical references:** Hoster seed `~/Shared/skill_seeds/2026-11-10-nebula-browser-lane.md` (newer than the Ghost Shared copy) and the unmanaged Hoster skill `~/.agents/skills/portafort-browser-lane/SKILL.md`. That copy was never in git.

## Intent

PortaFort is gone. Replace the human-at-the-screen browser lane with Nebula
without copying the private key or weakening the owner hard requirements
(Mullvad stays up, Firefox stays untouched, agent files stay under `~/AI/`).

## Implemented contract

- New skill `skills/nebula-browser-lane/SKILL.md`, name `nebula-browser-lane`.
- No PortaFort alias or shim. The old name was not in this repository.
- Connection facts verified by a read-only `ssh nebula` from Hoster on
  2026-11-10: Arch Linux, user `ryushe`, `google-chrome-stable`, Firefox,
  Mullvad, Wayland socket, XWayland `:0`.
- Lane SSH runs on the harness host that has the key (Hoster). Ghost does not.
- Registry row added. No captcha-policy edit: that policy still has no route
  to this lane, matching the seed.

## Evidence and review

- Tests and commands: `/home/ryushe/.local/bin/pytest tests/test_nebula_browser_lane_skill.py tests/test_skill_command_lane_safety.py -q` — 4 passed. `git diff --check` clean.
- Independent review: pending
- Replay/cohort/fixture evidence: not applicable; text contract only
- Merge/ancestry evidence: implementation commit `9126c94819a94fa0d63af4e77cc9f8f83f0c8c7f` is one commit ahead of base `a5103e811f9f18eb4aa001a13073a6d47ea108c0`

## Blockers and deferred work

- **Missing test or evidence:** live headed Chrome launch and in-Chrome Mullvad
  check were not run. This change only publishes the lane instructions.
- **Command / fixture / environment needed:** a real captcha/login segment on
  Nebula, with Ryushe at the screen.
- **Trigger to run it:** the next time `chromium-test` fails a captcha, login,
  or authenticity block.
- **Why it blocks integration, activation, or promotion:** it does not block
  publishing the skill. It blocks claiming the lane has been exercised.
- **Next completion step / successor reference:** first real lane use.

## Interruption / resume handoff

- **Owning feature branch/ref:** feat/nebula-browser-lane
- **Latest immutable recovery checkpoint:** 9126c94819a94fa0d63af4e77cc9f8f83f0c8c7f
- **Feature implementation commit(s):** 9126c94819a94fa0d63af4e77cc9f8f83f0c8c7f
- **Exact resume point:** independent review of `9126c94819a94fa0d63af4e77cc9f8f83f0c8c7f`, then merge to beta. The branch tip after this dossier commit is a handoff-only commit; the implementation commit above is the code checkpoint.
- **Working-tree state at handoff:** clean after the dossier commit.

## Decision gates

- **Integration gate:** focused skill test and command-lane safety test pass,
  independent review accepts the diff, beta worktree is clean and fast-forwarded.
- **Activation / cohort gate:** after beta push, profile sync links
  `nebula-browser-lane` and the unmanaged PortaFort directory is removed only
  after that link exists.
- **Promotion gate:** beta only. Do not merge to stable/main in this task.

## Decision record

- 2026-11-10 — created from the Hoster seed. Hard requirements carried over
  as the seed proposed, with the Chrome binary name updated to
  `google-chrome-stable`.
