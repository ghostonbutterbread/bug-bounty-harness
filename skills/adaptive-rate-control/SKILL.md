---
name: adaptive-rate-control
description: Use when implementing adaptive per-target scanner rate control.
---

# Adaptive Rate Control

Use for a scheduler, crawler, or scanner implementation that **changes its future request allocation** from observed target signals. This is a controller-design aid, not a claim that BBH's current `tool-run` has adaptive scheduling. For an actual live run, `/bounty-tools`, published program rules, and the live-testing policies own ceilings, admission, and stop decisions. A controller must not override them or switch host, proxy, identity, or machine to bypass a block.

## Controller boundary

- Key state by program and target bucket (host or an evidenced shared backend/rate bucket). Independent buckets may proceed only under their respective policy and aggregate program budget. Preserve configured policy cap separately from effective allocation; a recovery ramp never exceeds the cap.
- Persist observations and transitions with reason, evidence pointer, timestamp, effective allocation, and cooldown deadline where applicable. Raw run artifacts remain with the owning runner; a summary is not a substitute.
- Apply persisted state **before** planning/rendering the next job. Block a bucket in cooldown or operator review; do not render a nominal configured rate while the effective allocation is zero.
- Parse valid `Retry-After` delta seconds and HTTP dates against an injected clock. Reject malformed, expired, nonpositive, or unreasonable values and use a documented conservative fallback rather than an unbounded wait or immediate retry. Soft blocks may reduce the bucket's next rate; CAPTCHA, IP bans, and comparable hard blocks require operator review, not automatic recovery or alternate egress.

## Ordering and recovery

In-flight healthy work can finish after a newer cooldown. Never clear or shorten an active deadline because an older completion arrived. A fresh stronger rate signal may extend, but not shorten, it; operator review remains terminal until an explicit authorized reset. After expiry, schedule an explicitly marked low-rate stability probe. Only its healthy completion may enter ramp state: persist the probe's effective rate before counting later healthy observations toward bounded gradual increases. A new soft/hard signal resets progress. A completed job alone is not proof that it was the recovery probe.

## Focused verification when implementing

Test the controller and the planner together, not just response parsing: two bucket isolation; delta and HTTP-date retry boundaries with an injected clock; soft reduction; hard-block monotonicity; rendered command rate; no cross-backend fallback; expiry and marked probe; and gradual ramp capped by configured policy. Include an ordering fixture: persist a cooldown, finish an older healthy job, assert the deadline and blocked next plan survive, then pass a marked post-expiry probe and assert the next allocation starts at its low rate. Keep tests offline and deterministic. Do not claim these behaviors are implemented until the owning scheduler and its fixtures prove them.

## Related skills

- If operating an external scanner rather than changing its controller, load `bounty-tools`.
- If an observed block needs live interpretation, load the applicable WAF/status policy before resuming.
