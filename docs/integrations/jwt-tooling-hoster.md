# JWT tool selection and Hoster rollout

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `docs/jwt-tooling-hoster`
- **Base commit:** `67181af4a6370fa181c8f0a2a905d4590dc731db`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-21
- **Owning feature branch/ref:** `docs/jwt-tooling-hoster`
- **Latest immutable recovery checkpoint:** `9f36ea3534c44501c34c155c7067e08a271aebc4`
- **Feature implementation commit(s):** `9f36ea3534c44501c34c155c7067e08a271aebc4` (initial); correction and dossier update are this branch tip (resolve with `git log -1`).
- **Inspiration / canonical references:** `/jwt-auth`, PyJWT usage documentation, ticarpi/jwt_tool README and CLI help.

## Intent

Make JWT decoding/encoding/signing and focused vulnerability-tool choice/install discoverable to BBH agents; do not alter testing authorization, proof standards, or other classes.

## Implemented contract

`skills/jwt-auth/SKILL.md` routes tooling needs to its owned `references/jwt-tooling.md`. Reference gives isolated PyJWT and revision-pinned jwt_tool setup, synthetic self-test, safe tool selection and live-token/log boundaries. Installation commands are guidance, not an automatic target scan or deployment.

## Evidence and review

- Tests and commands: local isolated venv installed PyJWT 2.15.1 and jwt_tool requirements at upstream `3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b`; PyJWT fixture encode/unverified inspect/verified decode passed; jwt_tool `-h` ran and offline `-X a` emitted four candidates (exit 1); `python3 -m pytest -q tests/test_skill_triage_routes.py` passed (9 tests); frontmatter/local reference check and `git diff --check` passed. Full `pytest -q` collection fails on unrelated root `test_catalog.py` import of missing `bac_checks`; a `pytest -q tests/ agents/` run exceeded the tool's 420-second limit without a result.
- Independent review: initial read-only review blocked broad playbook mode and undisclosed upstream live defaults. Corrections document `-M pb` probe breadth, explicit `-rt`, proxy/redirect/TLS behavior, and offline-first replay. Independent re-review of `6e65021` accepted the prior findings for beta integration; Hoster activation remains unverified.
- Replay/cohort/fixture evidence: synthetic fixture only; no live target traffic.
- Merge/ancestry evidence: base equals fetched origin/beta when branched.

## Blockers and deferred work

- **Missing test or evidence:** Hoster beta checkout, tool installation, active provider skill projection and fresh load/read-back.
- **Command / fixture / environment needed:** bounded Hoster SSH to inspect checkout and user-owned tooling; synthetic fixture smoke and `readlink -f`/content check there.
- **Trigger to run it:** Hoster SSH port 22 becomes reachable; Tailscale peer responds to ping but SSH over LAN and Tailscale IP timed out during this run.
- **Why it blocks integration, activation, or promotion:** blocks Hoster activation and remote tool install verification, not local offline skill review.
- **Next completion step / successor reference:** verify and activate reviewed beta on Hoster; no stable promotion requested.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/jwt-tooling-hoster`
- **Latest immutable recovery checkpoint:** `9f36ea3534c44501c34c155c7067e08a271aebc4`
- **Feature implementation commit(s):** `9f36ea3534c44501c34c155c7067e08a271aebc4` (initial); correction and dossier update are this branch tip (resolve with `git log -1`).
- **Exact resume point:** integrate reviewed feature into `beta`, run focused checks, publish beta, then retry Hoster after SSH recovery.
- **Working-tree state at handoff:** clean after correction commit.

## Decision gates

- **Integration gate:** validated reference and independent review against the diff; beta current.
- **Activation / cohort gate:** Hoster source on selected beta, installed tools smoke-tested, resolved skill content read back.
- **Promotion gate:** no main promotion without explicit instruction.

## Decision record

- 2026-10-21 — created; Hoster SSH unavailable at task start, local tooling smoke performed.
- 2026-10-21 — review blocked overly broad live playbook recommendation and undisclosed upstream defaults; corrected the owned reference, pending re-review.
- 2026-10-21 — re-review accepted correction for beta integration. Hoster installation/projection remains a deferred activation gate, not a beta-completion claim.
