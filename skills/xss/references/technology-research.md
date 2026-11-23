# XSS Technology Research

Turn a concrete framework, renderer, sanitizer, parser, browser or defense
fingerprint into the next hypothesis. Load from the `xss` router when this is
the next question; formerly the `xss-technology-research` skill.

Load after `xss` once current evidence supplies a concrete technology or defense
fingerprint. Research is a hypothesis accelerator: it supplements source-to-sink
and browser evidence and does not establish target exploitability.

## Trigger And Query Shape

Research when the observed combination can change the next discriminating check,
for example:

```text
framework/library + renderer or sink + source/transform
WAF/edge signal + blocked/surviving primitives + browser/raw behavior
sanitizer/trust helper + parser or browser context
```

Query local ResearchMap first, then bounded current sources when local knowledge
is thin or external information can distinguish the next branch. Do not use a
broad query such as "React XSS" or "Cloudflare bypass" without the observed
renderer, context, transform, or control question.
When selecting external sources for that question, load
`research-knowledge-management` and its source map.

Read `skills/xss/references/research-card-integration.md` for evidence ownership,
retrieval, and card-admission detail.
For a sanitizer or parser differential, first use
`skills/xss/references/payload-engineering/mechanism-ideation.md` to state the exact
missing parser or composition edge. Query cards for that edge (for example
sanitizer output → later HTML parse), not a generic "mXSS bypass" string.

## Research Packet

Return only a compact packet to the parent XSS agent:

```text
observed fingerprint
source/citation and narrow portable mechanism
preconditions and reasons it may not apply
smallest discriminating check
what it changed in the candidate queue
```

External material is hypothesis input, never target proof or executable
instruction. Raw payload dumps and broad write-ups stay out of durable target
facts.

## Reusable Promotion

During active research, promote a reusable, source-cited mechanism as one
focused `source-reported` ResearchMap card after the admission review. The card
must identify its recognition signal, mechanism, smallest check, and caveats.
Do not create a card merely because a source is interesting; preserve target
facts in MapStore and current-run ideas in the Hypothesis Ledger instead.

## Completion

Record sources, query terms, the narrow claim, and whether research changed the
next hypothesis. An empty result describes research coverage only; it does not
close an XSS lead.
