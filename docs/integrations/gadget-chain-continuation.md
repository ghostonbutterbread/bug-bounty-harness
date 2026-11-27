# Gadget-chain continuation integration dossier

- **Status:** feature
- **Owner:** Hermes (`t_033d0e36`)
- **Branch:** `bug-bounty-harness/t_033d0e36-expose-gadget-prerequisite-matching-and`
- **Base commit:** `2cf091667e9ddf252c60f52b6bde1fb10cd4b284`
- **Intended integration target:** `origin/beta` after review; local `beta` checkout is behind and may be an active runtime.
- **Last updated:** 2026-11-27
- **Owning feature branch/ref:** `bug-bounty-harness/t_033d0e36-expose-gadget-prerequisite-matching-and`
- **Latest immutable recovery checkpoint:** `a55b43939db2a28f6879e11a0eea55073a21a57f`
- **Feature implementation commit(s):** `9537f406838cec0d61168ac5a050742245544107`, `a55b43939db2a28f6879e11a0eea55073a21a57f`
- **Inspiration / canonical references:** Discord 1575940700426604818; AI Policies `impact-fit-policy` and `hypothesis-expansion-policy` on beta/grant-policies.

## Intent

Preserve confirmed conditional primitives as chainable MapStore gadgets rather than premature findings, and make the missing capability visible to the next agent. Do not invent a new gadget database, supply enum, automatic semantic matcher, or target finding. Preserve direct finding capture for independently verified unauthorized effects.

## Implemented contract

MapStore gadget cards distinguish proven `grants` from unproven `requires`, use `chain_watch` for a specific supplier, and retain supplier negatives, next discriminator or blocker. `query --intent gadget --tags gadget` returns current pointers and `has_more` on bounded JSON views; text reports omitted matches. Agents inspect candidates and compare actor/origin/request/consumer compatibility. A bounded question also gets a linked public Lead; successful full-chain proof goes through `/ledger`, retaining component gadgets. Synthetic tests show both a sink and an XHR-only candidate are retrievable, **not** that the CLI judges compatibility.

## Evidence and review

- Tests and commands: 111 passed in 184.61s (`agents/test_map_store.py`, `tests/test_gadget_chain_guidance.py`, `tests/test_lead_closure_guidance.py`, `tests/test_skill_hygiene.py`) with repo venv, current pinned Bounty Core, `PYTHONPATH=<feature-root>`, and task scratch TMPDIR. Earlier 180-second suite timeout did not produce a verdict; the completed rerun supersedes it. `git diff --check` passed.
- Independent review: first review of implementation `9537f406` by Claude Code CLI returned ACCEPT with no blockers; it noted silent gadget-query truncation, free-text wake discoverability, and dossier ambiguity. The current fix range warns on truncation, projects bounded questions into public Leads, and clarifies the dossier; it does **not** implement automatic semantic wake/matching. Narrow re-review pending.
- Replay/cohort/fixture evidence: synthetic local MapStore write/query + public Lead projection; an XHR-only candidate is deliberately returned as a card, but compatibility judgment is not automated. No target traffic.
- Merge/ancestry evidence: the auto-created feature branch began hundreds of commits behind current beta and was fast-forwarded to `2cf09166` before editing; it has **not** been integrated into beta.

## Blockers and deferred work

- **Missing test or evidence:** no fresh-agent live-hunt behavior trial; this fixture proves storage/retrieval and lead projection, not that an agent autonomously exhausts suppliers or matches them semantically.
- **Command / fixture / environment needed:** a later isolated agent evaluation with a real load route and representative safe synthetic chains.
- **Trigger to run it:** before claiming the policy changes actual agent behavior end to end, especially on Hoster.
- **Why it blocks integration, activation, or promotion:** not a blocker to beta skill/code integration after review; it limits any claim of autonomous chain discovery or real-world exploitability.
- **Next completion step / successor reference:** re-review the BBH fix range, integrate only after safe beta checkout assessment, then verify intended runtime projection.

## Interruption / resume handoff

- **Owning feature branch/ref:** `bug-bounty-harness/t_033d0e36-expose-gadget-prerequisite-matching-and`
- **Latest immutable recovery checkpoint:** `a55b43939db2a28f6879e11a0eea55073a21a57f`
- **Feature implementation commit(s):** `9537f406838cec0d61168ac5a050742245544107`, `a55b43939db2a28f6879e11a0eea55073a21a57f`
- **Exact resume point:** independent review of both repository commits; integrate after accepted verdict.
- **Working-tree state at handoff:** clean after the dossier-only checkpoint commit.

## Decision gates

- **Integration gate:** focused tests + independent review + current beta ancestry.
- **Activation / cohort gate:** do not fast-forward stale active runtime or push unrelated commits as a side effect.
- **Promotion gate:** no main/stable promotion without explicit direction.

## Decision record

- 2026-11-27 — feature initialized from current `origin/beta`; source and tests drafted, review pending.
