# Nebula browser lane integration dossier

- **Status:** review-ready
- **Owner:** hermes
- **Branch:** feat/nebula-browser-lane
- **Base commit:** a5103e811f9f18eb4aa001a13073a6d47ea108c0
- **Intended integration target:** beta
- **Last updated:** 2026-11-10
- **Owning feature branch/ref:** feat/nebula-browser-lane
- **Latest immutable recovery checkpoint:** b9d2d5578274e4491c54ffd89eb28a6af312a241
- **Feature implementation commit(s):** 9126c94819a94fa0d63af4e77cc9f8f83f0c8c7f, 38a16eea901184e88347f4ec94f644c16b0af234, b9d2d5578274e4491c54ffd89eb28a6af312a241
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
- Independent review: accepted 2026-11-10. No blockers. Exclude every dossier commit from beta, including `de1efc5b` and `65d76936`, by removing `docs/integrations/nebula-browser-lane.md` in the merge. Live headed Chrome remains deferred and does not block the text publish.
- Replay/cohort/fixture evidence: not applicable; text contract only
- Merge/ancestry evidence: implementation commit `9126c94819a94fa0d63af4e77cc9f8f83f0c8c7f` plus a later correction commit. Dossier stays off beta.

## Blockers and deferred work

- **Missing test or evidence:** live headed Chrome and in-Chrome Mullvad check were not run.
- **Command / fixture / environment needed:** a real non-CAPTCHA segment on Nebula, with Ryushe at the screen.
- **Trigger to run it:** the next authorized physical-screen use after the policy decision.
- **Why it blocks integration, activation, or promotion:** it does not block the text publish. Ryushe authorized the CAPTCHA exception. Re-review is the remaining merge gate.
- **Next completion step / successor reference:** independent review of both branches, then merge each to its beta without the dossier.

## Interruption / resume handoff

- **Owning feature branch/ref:** feat/nebula-browser-lane
- **Latest immutable recovery checkpoint:** b9d2d5578274e4491c54ffd89eb28a6af312a241
- **Feature implementation commit(s):** 9126c94819a94fa0d63af4e77cc9f8f83f0c8c7f, 38a16eea901184e88347f4ec94f644c16b0af234, b9d2d5578274e4491c54ffd89eb28a6af312a241
- **Exact resume point:** independent review of `b9d2d5578274e4491c54ffd89eb28a6af312a241` with ai-policies `7880e48adbca21382c221023c0a79f87127dcc31`, then merge to beta without this dossier.
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
