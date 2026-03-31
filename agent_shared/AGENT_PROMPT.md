# Agent Prompt — Bug Bounty Hunting

When hunting on a bug bounty program, use this prompt to bootstrap yourself:

---

## COPY BELOW THIS LINE

```
You are hunting bugs on the {program} bug bounty program.

## Knowledge Base Location
~/Shared/bounty/{program}/agent_shared/

## Before Starting
1. Read {program}/agent_shared/README.md
2. Read {program}/agent_shared/notes/summary.md
3. Read {program}/agent_shared/notes/observations.md
4. Read {program}/agent_shared/checklist.md
5. Read {program}/agent_shared/todo.md

## After Testing
1. Update {program}/agent_shared/checklist.md (mark tested items)
2. Add findings to {program}/agent_shared/findings/{vuln-type}/
3. Update {program}/agent_shared/todo.md
4. Update {program}/agent_shared/notes/summary.md

## Directory Structure
{program}/
├── agent_shared/
│   ├── README.md              # Start here
│   ├── checklist.md            # Mark tested items
│   ├── todo.md               # Update priorities
│   ├── notes/
│   │   ├── summary.md        # Quick overview
│   │   └── observations.md   # WAF, auth notes
│   └── findings/
│       ├── xss/findings.md   # XSS findings
│       ├── idor/findings.md  # IDOR findings
│       └── ...               # Add new folders as needed!

## IMPORTANT: Creating New Finding Folders
If you test a vulnerability type that has NO folder under findings/:
1. CREATE the folder: findings/{vuln-type}/
2. Copy findings template from: agent_shared/templates/findings/findings.md
3. Add your finding to the new folder

Example: Testing for XXE but no findings/xxe/ folder exists:
  mkdir -p ~/Shared/bounty/{program}/agent_shared/findings/xxe
  # Copy findings.md template
  # Add your XXE finding

## Checklist Update Format
When marking items tested:
- [x] XSS — Tested /search endpoint, found reflected XSS — @yourname
- [x] IDOR — No IDOR found, /profile/{id} properly validates — @yourname

## Todo Update Format
When updating todo:
[new] XSS — /api/search — Reflected XSS in "q" param — @yourname

## Finding Format
Each finding should include:
- Severity, Status, Target URL, Description
- Step-by-step PoC
- Impact, Remediation, References

## Status Codes
[x] = Tested (found or cleared)
[ ] = Not tested
[P] = In progress

---
Happy hunting! Remember: read before testing, update after.
```

## COPY ABOVE THIS LINE

---

## Using This Prompt

**When spawning Claude Code:**
```bash
claude
# Paste the prompt above, replacing {program} with actual program name
```

**When spawning Codex:**
```bash
codex
# Paste the prompt above
```

**When using Ghost:**
Just tell me the program name and I'll read the knowledge base.

---

## Setup.sh --prompt Usage

Run `./setup.sh --prompt` to display this prompt.

Add `--program {name}` to customize for a specific program:
```bash
./setup.sh --prompt --program superdrug
```
