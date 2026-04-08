---
name: me
description: Briefing card for Codex or Claude during a Ghost hunt with default and fresh context modes.
---
## Ghost Hunting — /me skill

You're hunting `{program}`. Here's how to coordinate with Ghost's pipeline.

### Context Modes

**Default (`/me`)**: You start with full context — what other agents have already
found, what surfaces are explored. Hunt in unexplored areas only.

**Fresh context (`/me --fresh`)**: You start with a clean slate. You don't know what
other agents found — but that's intentional. You might find overlapping things.
That's fine. The dedup step catches duplicates.

### What to do regardless of mode

1. Before adding a finding, check if it's already in the ledger:
   `python3 me_ledger.py check --program {program} --file <file> --class-name <class>`

2. If NOT a duplicate, add it to the ledger:
   `python3 me_ledger.py add --program {program} --file <file> --class-name <class> --type "<type>" --severity <SEVERITY>`

3. Mark the surface as explored (so other agents skip it):
   `python3 me_ledger.py cover --program {program} --file <file> --class-name <class>`

4. Write your report to: `./reports/<fid>_<title>.md`

### Why both modes?

- Default: Efficient. No overlap, agents complement each other.
- Fresh: Thorough. Same surfaces might get hit from different angles, then dedup catches collisions.
