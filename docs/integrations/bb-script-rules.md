# BBH script-rule rename — integration handoff

- Status: review-ready
- Owner: Hermes Agent; branch: `docs/bb-script-rules`
- Base: `8bad30736c553c13791be07588d38afe96eafa3a`; target: `beta`
- Implementation checkpoint: `d93d020b3ad4cd9b0b751ed879dfc4c8e6d562fb`

## Intent

Rename the BBH hunt-script interpretation skill from `/scripts` to `/bb-script-rules`. The BBH entry instructs agents to load it before a hunt script; the skill description supplies the catalog trigger, and JS/XSS route to it. Keep script discovery in specialist skill indexes. Replace the XSS-only example with target technology-stack cases across vulnerability classes. Do not change script implementations or Script Manager's maintenance role. This is an instruction route, not a runtime tool hook.

## Evidence and review

- `pytest -q tests/test_script_policy.py skills/xss/scripts/test_xss_canary_mapper.py`: 40 passed; staged/unstaged diff checks clean.
- `pytest -q tests`: 188 passed, 1 skipped, 2 unrelated pre-existing failures (stale Hoster-authority assertion and command in an older integration dossier); no changed paths involved.
- Independent review: pending. Reconcile fresh beta before integration.

## Handoff and gates

- Branch: `docs/bb-script-rules`; checkpoint `d93d020b3ad4cd9b0b751ed879dfc4c8e6d562fb`; worktree clean after dossier checkpoint.
- Resume: review, merge beta with this dossier retired, publish, update clean Hoster source, then profile-sync new name and inspect safe removal of managed old links. If a full-profile plan includes unrelated changes, do not apply it blindly.
- No main promotion; already-running agents may retain previously loaded instructions.
