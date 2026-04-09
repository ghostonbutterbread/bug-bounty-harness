# Retard Collaboration — Creative Multi-Agent Brainstorming

## What It Does
A 3-agent creative brainstorming harness that builds on zero_day_team findings to generate novel attack chains using deliberate creative chaos.

**Agents:**
1. **Creative Chaos Agent** — model=gpt-4.1 (weaker, weirder, more creative). Reads zero_day findings, generates 10+ wild lateral ideas
2. **Analyst Agent** — model=gpt-5.4. Filters creative output to 2-3 genuine diamonds
3. **Synthesizer Agent** — model=gpt-5.4. Combines filtered ideas with zero_day findings into novel attack chains

## Invocation
```
/retard_collaboration <program> [--source <path>]
```

Examples:
```
/retard_collaboration evernote
/retard_collaboration evernote --source ~/Shared/bounty_recon/evernote/0day_team/
```

## Harness Location
`~/projects/bug_bounty_harness/agents/retard_collaboration.py`

## Workflow Position
```
zero_day_team → retard_collaboration → chainer
```

Run zero_day_team first to get findings, then feed the findings to retard_collaboration to generate creative chains.

## How It Works

**File-based 3-stage pipeline:**

```
/tmp/collab_{program}_{date}/
  creative/findings.txt       ← wild ideas (gpt-4.1)
  analyst/filtered.txt        ← diamonds only (gpt-5.4)
  synthesizer/chains.md       ← novel chains (gpt-5.4)
  shared_context/
    zero_day_findings.txt     ← from zero_day_team
    app_map.txt               ← optional app map
    task.txt
```

**Stage 1 — Creative Chaos (gpt-4.1):**
- System prompt: "You are the Creative Chaos Agent. Your sole job is to be CREATIVE. There are NO bad ideas."
- Reads zero_day findings + app map
- Outputs 10+ wild, lateral, unconventional attack ideas

**Stage 2 — Analyst (gpt-5.4):**
- System prompt: "You are the Senior Security Researcher — the gatekeeper. Be brutal in filtering."
- Reads creative output
- Filters to 2-3 ideas with actual security potential

**Stage 3 — Synthesizer (gpt-5.4):**
- System prompt: "You are the Synthesis Expert — the builder. Think in chains."
- Reads filtered ideas + zero_day findings
- Outputs 3-5 novel attack chains that neither team produced alone

## Output Location
```
~/Shared/bounty_recon/{program}/ghost/collaboration/{date}/
├── collaborative_chains.md    ← main output (chains)
├── creative/findings.txt      ← raw creative output
├── analyst/filtered.txt       ← filtered ideas
└── synthesizer/chains.md     ← synthesizer output
```

## Usage Pattern

```bash
# 1. Run zero_day_team first
python3 agents/zero_day_team.py evernote ~/source/

# 2. Run retard_collaboration on the findings
python3 agents/retard_collaboration.py evernote --source ~/Shared/bounty_recon/evernote/0day_team/

# 3. Run chainer on the collaborative output (optional)
python3 agents/chainer.py evernote --source ~/Shared/bounty_recon/evernote/ghost/collaboration/
```

## Why "Retard"?

The name reflects a real technique: deliberately impaired or unconventional reasoning
generates more diverse ideas than pure optimization. A slightly "dumb" agent
breaks out of local minima that a fully capable agent never leaves.

The creative chaos agent uses:
- A weaker model (gpt-4.1) that defaults to less obvious paths
- A prompt that explicitly tells it to break conventions
- No penalty for wild ideas — only reward for quantity

## Options
- `--skip-creative` — Skip creative stage (if output already exists)
- `--skip-analyst` — Skip analyst stage
- `--verbose` — Print raw agent output

## Credits
Concept inspired by research on impaired agents and creative diversity in LLM ensembles.
