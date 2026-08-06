# ResearchMap

ResearchMap is BBH's local CLI for portable AppSec research. It keeps authored
knowledge as synced Markdown under `~/notes/appsec/research/` and uses a
rebuildable local SQLite FTS index only for fast retrieval.

It is **not** MapStore: MapStore records target-specific observations and tested
state. ResearchMap records portable, source-cited mechanisms, code signals, and
testing directions that can generate hypotheses when an agent is blocked.

## Commands

Run from the BBH repository:

```bash
python3 scripts/research_map.py init
python3 scripts/research_map.py validate
python3 scripts/research_map.py index
python3 scripts/research_map.py query --terms "custom protocol parser" --class xss
python3 scripts/research_map.py query --terms "sanitizer svg" --tag url-parsing --limit 5
```

Use `--root /path/to/research` **before** the command to work with another
corpus—for example, an isolated test corpus:

```bash
python3 scripts/research_map.py --root /tmp/research init
```

`query` automatically builds the index if it is missing. Run `index` after card
edits or sync updates so SQLite reflects the Markdown source of truth.

## Layout

```text
~/notes/appsec/research/
├── README.md
├── cards/                    # canonical portable research cards
│   └── xss/
├── sources/                  # raw captures / write-up summaries
├── templates/research-card.md
└── indexes/research.sqlite   # generated local search state
```

Sync the Markdown files and template. Do not rely on `indexes/research.sqlite`
as durable knowledge; it is generated from cards and may be excluded from sync.

## Card metadata

Every `cards/**/*.md` file must have YAML frontmatter with:

```yaml
---
id: xss.parser-differential.invalid-javascript-url
title: Invalid JavaScript URL accepted by partial protocol parser
class: xss
tags:
  - dom-xss
  - url-parsing
  - parser-differential
status: credible-source-reported
confidence: medium
sources:
  - https://source.example/writeup
code_signals:
  - custom protocol parser
  - parse failure maps to safe
technologies:
  - sanitizer-api
---
```

Supported statuses:

- `draft`
- `source-reported`
- `credible-source-reported`
- `validated`
- `reproduced`
- `stale`
- `superseded`

`source-reported`, `credible-source-reported`, `validated`, and `reproduced`
require at least one citation in `sources`. A card is a portable hypothesis aid,
not proof that a current target is affected.

## Agent use

Start from target-specific reasoning and current observations. Query MapStore for
concrete app facts, dedupe, or coverage. When a plausible surface has no next
discriminating hypothesis, query ResearchMap. If local cards remain thin, query
the external Preview source for source-backed idea generation. Record target
facts back to MapStore; add reusable ResearchMap material only with a status and
citation.

For XSS, the active `/xss` and `/dom-xss` skills apply this at a specific
boundary: first map a concrete framework/renderer/source/sink/sanitizer clue;
then query matching cards only when that evidence does not yield a next
context-matched check. The XSS integration policy is
`skills/xss/references/research-card-integration.md`. ResearchMap results remain
bounded hypothesis input and never replace source-to-sink or browser proof.
