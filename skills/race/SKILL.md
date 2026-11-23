---
name: race
description: Use when testing race conditions, concurrent workflow flaws, double-submit bugs, parallel requests, locking issues, time-of-check/time-of-use behavior, or state consistency under load.
---
# Race Condition Testing

Test for race conditions, state desynchronization, and concurrent workflow flaws.

## Required Preflight

Read the relevant notes for the concrete surface when they exist:

1. `notes/summary.md`
2. `notes/observations.md`
3. `checklist.md` (race items only)
4. `todo.md` (race items only)

## Primary Harness

Use `agents/bypass_harness.py` in `--type race` mode for first-pass concurrent replay. Set `--concurrency` above the module burst size so the harness does not artificially serialize the race.

```bash
bbh agents/bypass_harness.py --target https://target.com/api/redeem \
  --type race --program target --concurrency 20 --rps 20
```

## Mechanism

A race exists when a check and the commit that depends on it are not atomic:

```text
request A:  read ---- check ---- write
request B:       read ---- check ---- write
                 ^^^^^^^^^^^^^^ both saw pre-write state
```

The **window** is the gap between the read/check and the write. Winning a race
means delivering requests so they land inside that window. So the first
question is never which payload, it is **how wide the window is** and **what
delivery is tight enough to fit it**.

## Why each technique works

| Technique | The obstacle it removes |
|---|---|
| plain parallel requests | nothing; sufficient when the window is wide (an async worker, a queue, a second endpoint) |
| HTTP/2 multiplexing | requests serializing behind each other on one connection |
| **single-packet attack** (HTTP/2) | network jitter entirely: many requests in one TCP packet arrive with no relative delay |
| **last-byte synchronization** (HTTP/1.1) | most jitter without HTTP/2: send every body but its final byte, then release the final bytes together |
| connection warming | first-request skew from TLS handshake and TCP slow-start; send a throwaway request first |
| same state via two endpoints | a per-handler lock that does not cover the shared object |
| multi-step workflow interleave | nothing needs tightening: the check and the commit are in *different requests*, so the window is large by construction |

## Locating the window

1. **Baseline.** One request. Record the authoritative state change and timing.
2. **Are check and write in the same request?** Then the window is
   sub-millisecond and needs single-packet or last-byte delivery.
3. **Is the state settled by an async worker, queue, or second endpoint?** Then
   the window is wide and plain parallelism is enough.
4. **Escalate delivery only as needed:** two parallel requests, then a burst,
   then multiplexed, then single-packet or last-byte.
5. **Prove state, not responses.** Read back the authoritative resource. Two
   `200`s with one increment is not a race.

Note on the harness: `--rps` rate-limits outbound requests, which *defeats* a
narrow race by spacing the burst. The harness is a first pass for wide windows.
A sub-millisecond window needs synchronized delivery it does not implement; say
so rather than concluding the race does not exist.

## Mode Matrix

| Mode | Use When | What It Tests |
|------|----------|---------------|
| `single-use` | Token, coupon, or invite should be consumed once | Duplicate acceptance before invalidation |
| `limit` | Quotas or redemption limits should gate actions | Pre-check bypass under concurrency |
| `toctou` | Read-then-write checks gate value changes | Stale authorization, balance, or inventory windows |
| `workflow` | Multiple endpoints change the same object state | Conflicting transitions and ordering bugs |

**Depth.** Once any probe produces signal on an owned surface, load
`hypothesis-live-testing` and stay in its mutate-compare-continue loop while
responses still teach. State why each variation should behave differently
before sending it (`race-live-policy`). The surface is gated once, not per
burst; do not leave a warm vector to record a blocker.

## CLI Notes

`agents/bypass_harness.py` shares its options across types; only two change a
race result. Keep `--concurrency` above the burst size so the harness does not
serialize it, and treat `--rps` as a rate limit that widens the gaps between
requests. Everything else is transport and output plumbing.

## Stop Conditions

- Stop if behavior risks irreversible financial impact or harms real user data.
- Stop if the only effect is duplicate responses with no duplicated state change.
- Stop if the target becomes unstable.

## Files

- **Playbook:** `prompts/race-playbook.md`
- **Shared Root:** `$HARNESS_SHARED_BASE/{program}/agent_shared/`
- **Race Findings:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/race/findings.md`
- **Bypass Artifacts:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/bypass/`

## Workflow

1. Complete the required preflight reads in shared state order.
2. Read `prompts/race-playbook.md`.
3. Measure the window, then pick delivery from it. Use
   `agents/bypass_harness.py` in `--type race` mode for a wide window; for a
   sub-millisecond window use synchronized delivery and record that the
   harness cannot produce it.
4. Confirm any promising result by proving duplicated or inconsistent state, not just varied responses.
5. Write findings to `agent_shared/findings/race/findings.md`.
6. Update race entries in `checklist.md`, `todo.md`, and relevant notes.
