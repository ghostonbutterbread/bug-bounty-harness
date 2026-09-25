# WAF exploration guidance integration dossier

- **Status:** review-ready
- **Owner:** Hermes; card `t_9f145024`
- **Branch / owning ref:** `docs/waf-exploration-guidance`
- **Base commit:** `2d80b03af499a033a0b9a46c87b7e3a4eb61236c`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-25
- **Latest immutable recovery checkpoint:** none yet; commit this dossier with the skill before handoff
- **Feature implementation commit(s):** none yet
- **Inspiration:** Uncommitted addition in the older root checkout's `skills/waf/SKILL.md`, requested by Ryushe; leave that checkout and its other worktrees untouched.

## Intent and contract

Carry the two source paragraphs into the canonical beta WAF skill. Add a narrow live-policy pointer so the prose cannot override scope or rate controls. This is guidance, not a new authorization or a WAF-bypass result. Do not change implementation, other skills, or the old checkout.

## Evidence and review

- Alignment: `agents/index.md` places AI Policies before BBH mechanics; `waf-live-policy` owns filtering/challenge interpretation and low-rate scoped continuation; `blocker-first-analysis` and `hypothesis-expansion-policy` own the blocker and hypothesis decisions; `bypass` owns general bypass routing. `waf` owns runner/mechanics and a compact pointer to those decisions. No parallel testing rule is intended.
- Tests and commands: pending focused policy/link and diff checks.
- Independent review: pending.
- Merge/ancestry: feature based on fetched `origin/beta` at base above; recheck before integration.

## Blockers and deferred work

No known blocker. Runtime activation is separate from publication: Aiskillsync beta source is the clean integration checkout, while the shared launcher receipt/link was stale before this task. Do not claim fresh consumer activation merely from this merge.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/waf-exploration-guidance`
- **Latest immutable recovery checkpoint:** pending commit
- **Feature implementation commit(s):** pending commit
- **Exact resume point:** run focused checks and independent review, reconcile beta tip, merge/push from the clean beta integration checkout, retire this dossier on target; preserve old dirty source.
- **Working-tree state at handoff:** pending commit.

## Decision gates

- **Integration:** independent review and focused checks; clean feature/integration tree and fetched beta ancestry.
- **Activation:** separately reconcile Aiskillsync and verify runtime skill resolution if requested.
- **Promotion:** no stable promotion requested.

## Decision record

- 2026-09-25 — created from operator-selected WAF guidance; live-policy boundary added for alignment.
