---
name: bunny-multi
description: Use when collaborative Bunny spans multiple programs.
version: 0.1.0
author: Ryushe, Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [bug-bounty, orchestration, multi-program]
---

# Bunny — Multi-Program Collaborative Overlay

Load this **only in the coordinator** when `bunny-collaborative` receives an explicit `multi` parameter. This is not a new Bunny mode, a `/goal` requirement, or a worker skill. Workers still load `bunny-collaborative` and receive one program-scoped packet; do not pass them the portfolio queue.

The coordinator owns one objective across named, distinct bounty programs. Confirm each program against its published scope and rules before assigning work. If program names are missing, obtain them before live work. Several domains within one program are still one program; a worker may investigate those domains but may not cross into another program.

Keep a small **run-local coordinator key** in the existing campaign record, not in any program's Shared data: program identifier, queued/active/paused/closed state, **all active worker/run IDs** for that program, next decision, and pointer to that program's evidence. A queue is memory of eligible future work, **not** a timer, deadline, or reason to move on from a deep current chain. Admit another program when a slot is actually available and the coordinator judges it useful. A quiet or blocked worker does not automatically free a slot. A paused program retains its next discriminator and can resume; close a program only on evidence-backed grounds, never to make room.

At most **three active subagents total** across all programs; hunters, recon, verifiers, and reporters all count, but the coordinator does not. Count every active run ID globally, including multiple workers in one program, and free a slot only after confirming that worker has stopped. If independent verification needs a fresh worker while all slots are occupied, release or pause an existing worker at a checkpoint and confirm its stop first. Keep each live packet, account/browser/proxy lease, rate budget, and evidence destination bound to exactly one program. Share only sanitized, portable hypotheses across programs—never credentials, session state, raw captures, or proof. Verify each candidate independently in its own program. Apply `bunny-collaborative`'s depth and negative-result challenge within each program.

When the invocation also uses `/goal`, its existing `goal_router.py` accepts one program per call: produce a plan for each named program before that program's first target action, using the same objective. Do not pass a comma-separated program list as one program. Treat any Hunter Loop or `hunt-orchestration-policy` plan fields as per-program routing hints; Bunny remains the sole coordinator and its collaborative checkpoints govern dispatch. For a Bunny invocation without `/goal`, this goal helper is not a prerequisite.
