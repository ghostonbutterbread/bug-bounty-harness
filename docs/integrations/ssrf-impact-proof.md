# SSRF impact-proof policy

- **Task:** Align SSRF escalation guidance with bounded, rate-limited internal read proof.
- **Branch / worktree:** `docs/ssrf-impact-proof` at `/home/ryushe/worktrees/bbh-ssrf-impact-proof`.
- **Base / target:** `492493a1eec36c727372e8d98532e121e15bb93f` (`beta`) → `beta`.
- **Intent:** A confirmed SSRF may be escalated through minimal read-only internal requests to establish impact; payload volume is governed by scope, observed service cost, rate, and backoff rather than a fixed count.
- **Implemented contract:** `skills/ssrf/SKILL.md` now starts with application-map, UI/API, and JavaScript candidate mining; accepts bounded internal response/status/timing/job-state proof when an outbound callback is unavailable; permits extensive distinct representation coverage after a confirmed fetch boundary; and permits the smallest necessary sensitive response as impact proof while prohibiting persistence, state-changing behavior, use of retrieved credentials/tokens, destructive requests, uncontrolled scans, and unapproved DNS rebinding.
- **Evidence:** `git diff --check` passed; an independent read-only review found no blockers and identified one stop-condition ambiguity, corrected in `e9d9ae7`. Review recommendation: approve after reconciliation with current `beta`.
- **Decision:** Approved for merge into `beta` by Ryushe; remove this temporary integration dossier from `beta` during integration cleanup.
- **Activation boundary:** Canonical skill remains unchanged until this feature branch is reviewed, merged into `beta`, and the external skill projection is synced.
- **Deferred verification:** Fresh Hermes `skill_view('ssrf')` after merge and focused sync; no live SSRF testing is part of this documentation change.
