# BBH ResearchMap Pattern

## Ownership split

- **Authored corpus:** ResearchMap's `$HOME/notes/appsec/research` default or explicit `--root`
- **Project-local CLI and tests:** `scripts/research_map.py` and `tests/test_research_map.py`
- **Target facts:** BBH MapStore
- **External discovery:** Preview/write-up source, only after local research is insufficient

Markdown cards are synced and human-readable. SQLite FTS is a local generated index and must be rebuildable from Markdown.

## Agent policy wording

> Start with target-specific reasoning and current-run observations. Use MapStore for concrete target facts, dedupe, and coverage. If a plausible surface has no next discriminating hypothesis, query ResearchMap before declaring it exhausted. If ResearchMap is thin or does not resolve the block, query the external source for source-backed idea generation. Research results are hypotheses, not target facts.

## CLI contract

```bash
bbh scripts/research_map.py init
bbh scripts/research_map.py validate
bbh scripts/research_map.py index
bbh scripts/research_map.py query --terms "sanitizer svg" --class xss --tag url-parsing
```

The query response should be bounded and include card ID, title, class, status, confidence, relevant code signals, a concise mechanism/test direction, and source citations.

## Card boundaries

A portable card describes a reusable mechanism such as a strict-string comparison bypass or parser discrepancy. It must not claim a mechanism works on a target. Target-specific observations, exact test history, and next steps belong in MapStore and hunt notes.