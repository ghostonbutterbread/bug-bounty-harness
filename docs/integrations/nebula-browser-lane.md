# Nebula browser lane integration dossier

- **Status:** blocked
- **Owner:** hermes
- **Branch:** feat/nebula-browser-lane
- **Base commit:** a5103e811f9f18eb4aa001a13073a6d47ea108c0
- **Intended integration target:** beta
- **Last updated:** 2026-11-10
- **Owning feature branch/ref:** feat/nebula-browser-lane
- **Latest immutable recovery checkpoint:** 38a16eea901184e88347f4ec94f644c16b0af234
- **Feature implementation commit(s):** 9126c94819a94fa0d63af4e77cc9f8f83f0c8c7f, 38a16eea901184e88347f4ec94f644c16b0af234
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
- Independent review of `9126c94819a94fa0d63af4e77cc9f8f83f0c8c7f` blocked. Reproduced `ssh -f` returning 0 for remote exit 7 on OpenSSH 9.6p1. Lock now waits for a token written only after `flock -n`, and cleanup `pkill`/`rm` run through `ssh nebula`. CAPTCHA override removed so this skill does not contradict `captcha-policy`. Re-review is pending the operator decision below.
- Replay/cohort/fixture evidence: not applicable; text contract only
- Merge/ancestry evidence: implementation commit `9126c94819a94fa0d63af4e77cc9f8f83f0c8c7f` plus a later correction commit. Dossier stays off beta.

## Blockers and deferred work

- **Missing test or evidence:** live headed Chrome and in-Chrome Mullvad check were not run.
- **Command / fixture / environment needed:** a real non-CAPTCHA segment on Nebula, with Ryushe at the screen.
- **Trigger to run it:** the next authorized physical-screen use after the policy decision.
- **Why it blocks integration, activation, or promotion:** the live Chrome check does not block a text publish. The CAPTCHA route does: `captcha-policy` and its regression test forbid switching host or egress and route handoff to `chromium-handoff`. The seed asked for captcha/login on Nebula. That exception is not authorized yet.
- **Next completion step / successor reference:** Ryushe chooses whether captcha-policy stays in force or gets an explicit Nebula exception. Then re-review and merge.

## Interruption / resume handoff

- **Owning feature branch/ref:** feat/nebula-browser-lane
- **Latest immutable recovery checkpoint:** 38a16eea901184e88347f4ec94f644c16b0af234
- **Feature implementation commit(s):** 9126c94819a94fa0d63af4e77cc9f8f83f0c8c7f, 38a16eea901184e88347f4ec94f644c16b0af234
- **Exact resume point:** wait for the CAPTCHA-policy decision, then re-review the correction commit and merge to beta without this dossier.
- **Working-tree state at handoff:** clean after the correction commit.

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
