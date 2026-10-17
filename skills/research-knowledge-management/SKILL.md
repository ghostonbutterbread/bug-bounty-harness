---
name: research-knowledge-management
description: Build and operate durable, queryable security-research knowledge systems that separate portable mechanisms, target facts, hunt narrative, and external source discovery.
---

# Research Knowledge Management

Use when converting security write-ups, advisories, code-research notes, or repeated hunt lessons into durable knowledge agents can retrieve without bloating vulnerability skills.

## Core Model

Keep five distinct layers:

1. **Class skills** explain how to reason and test a vulnerability family. Keep them short and procedural.
2. **Target memory (MapStore)** records what is true about a specific application, route, role, parser, defense, and tested state.
3. **Portable research cards** are small, high-signal technology vectors or niche provider test guides that agents retrieve against a matching surface.
4. **Owned source and workflow notes** preserve compact provenance plus broader recon/tool/process lessons. They are queried only for an explicit knowledge/workflow question, never ambiently injected into ordinary target work.
5. **External source search** supplies fresh write-ups and idea generation when the owned corpus is insufficient. Third-party retrieval services (including Preview) are discovery tools, not an owned knowledge store; write any retained result into an owned note or card after review.

Do not turn raw write-ups into target facts. Do not paste a large research corpus into every agent prompt.

For an explicit product-class literature/threat-map request, load
`references/functionality-first-writeup-synthesis.md`. It gives the on-demand
case-admission, source-status, functionality-clustering, and specialist handoff
method; do not run a broad write-up sweep on every ordinary target start.

## Class-Level Skill Boundary

Keep class skills and their primary lanes stable and procedural. Do not create a
new narrow skill for every framework, renderer, provider, or public write-up.
Put technology- and mechanism-specific detail into compact ResearchMap cards
that are retrieved only when target evidence qualifies them. This lets a class
such as XSS retain one root workflow while React, Vue, Angular, jQuery,
Markdown, sanitizer, and future-stack knowledge remain composable branches
rather than a flat skill taxonomy.

For browser-feature XSS research, review newly shipped elements, events, and parser
behavior against the current cheat sheet and upstream release notes. Reproduce a
candidate in an isolated browser with an unknown-element or inert-sink control,
then compare whether the same tag/attribute survives a plausible sanitizer and
CSP boundary. Promote one narrow mechanism card only when the browser behavior
and recognition signal are clear; keep the broader scouting method in a workflow
note, not a payload-dump skill. A local browser reproduction is not a live-target
blacklist bypass.

## Storage and Authority

For the ResearchMap corpus, use Markdown as the authored and synced source of
truth. `bbh scripts/research_map.py` defaults to
`$HOME/notes/appsec/research`; pass its `--root` option when the corpus is
elsewhere. Its layout is:

```text
<configured-research-root>/
  cards/
  sources/
  templates/
  indexes/   # generated local state only
```

Use a rebuildable SQLite full-text index for fast retrieval. Do not treat the index as durable knowledge or depend on syncing it across devices.

Keep raw source captures separate from atomic cards. A source may support several cards; every non-draft card must retain citations and an explicit source status.

## Retrieval Ladder

1. Begin with the agent's target-specific reasoning and current observations.
2. Query MapStore only with a concrete target intent: app facts, dedupe, coverage, or an active-candidate gadget question.
3. When a plausible surface has no next discriminating hypothesis, query the portable research corpus.
4. If the local corpus is thin or does not unblock the mechanism, consult an approved external write-up source for source-backed ideas.
5. Treat retrieved research as hypothesis input, not proof. Write verified target observations back to MapStore; promote a reusable mechanism to a research card only with citation and status.

Before declaring a plausible surface exhausted, use this ladder. A blocked initial payload or lack of immediate signal alone is not exhaustion.

## Research Absence Is Not Target Evidence

"No result" is a statement about the sources, query, filters, indexing, and
terminology searched—not about the target's safety or the nonexistence of a
mechanism. An empty ResearchMap/Preview/web search, an undocumented framework
behavior, or a source that does not mention a technique must never become
"nothing is there," a negative target finding, or a reason to close a plausible
lead.

Report absence precisely: what was searched, which query/filters were used,
which sources were unavailable or thin, and what uncertainty remains. Prefer
language such as “no documented mechanism was found in the consulted sources”
rather than “nothing is there” or “no technique exists.” Return to observed
target behavior and use the next discriminating source/sink, parser, consumer,
configuration, or workflow check. Mark a boundary defended, inert, or exhausted
only from evidence of that target and that context; distinguish observed-family
coverage from unknown/unresearched space.

## Proportionate Research Trigger

Do not make external retrieval a startup ritual or a per-payload tax. Once a
concrete fingerprint, control/obstacle, or source-to-consumer question exists,
run a bounded research sweep before a coverage or exhaustion claim when it could
change the next decision—especially for unfamiliar technology/configuration,
CSP/sanitizer/WAF/parser behavior, warm or hot multi-step leads, thin local
results, or conclusions limited to observable families.

- Query the portable corpus, then use the configured curated external source
  (for example Preview MCP) when local knowledge is thin **or** external context
  can distinguish the next branch; do not require local ideas to be exhausted.
- Use one targeted query per distinct surface/mechanism decision, dedupe within
  the active run, and obey configured service rate/budget rules.
- For a technology/configuration question, compare upstream intended use and
  relevant misconfiguration/advisory prerequisites with target conditions marked
  `observed`, `source-derived`, `contradicted`, or `unknown`; a version match is
  never target proof.
- Read a disclosed report through its final triage and follow-up, not just its
  initial claim: later comments may narrow impact, identify a false positive,
  or distinguish a local-lab escalation from production proof. Record each
  case's demonstrated boundary separately from the researcher's speculation.
- Record the source/query, narrow claim, and whether it changed the next
  hypothesis or discriminator. External material is hypothesis input, never
  target proof.
- For coverage claims, distinguish observed-family coverage from full-family
  coverage and name the research sweep performed plus remaining unknown space.

## Research Card Shape

One card covers one composable mechanism. It should include frontmatter such as:

```yaml
id: xss.parser-differential.invalid-javascript-url
title: Invalid JavaScript URL accepted by partial protocol parser
class: xss
tags: [dom-xss, url-parsing, parser-differential]
status: credible-source-reported
confidence: medium
sources: [https://source.example/writeup]
code_signals: [custom protocol parser, parse failure maps to safe]
technologies: [sanitizer-api]
```

Then use concise sections: `Mechanism`, `Preconditions`, `Recognition questions`, `Test direction`, and `Limits / caveats`.

Supported lifecycle states: `draft`, `source-reported`, `credible-source-reported`, `validated`, `reproduced`, `stale`, and `superseded`. A credible external source strengthens prioritization; it does not establish that an arbitrary target is affected.

## User-Directed Link Intake

When Ryushe posts an AppSec-relevant URL in `#learnings`, or explicitly asks
for a card/review of a URL in another channel, treat it as an explicit request
for a **reviewed promotion pass**—not merely a bookmark. Do this in the same
turn:

1. Retrieve the canonical source safely and identify the author/date, narrow
   claim, and any primary documentation or implementation corroboration.
2. Classify the material: `source capture only`, `workflow note`, `0..N atomic
   cards`, or `target/program documentation`. Verify that any named application
   is identifiable before creating target-specific documentation; a disclosure
   pseudonym is source attribution, not an app identity. If the report yields a
   portable, narrow mechanism, promote that card without inventing program facts.
   Do not force an interesting post into a card.
3. Write a compact provenance capture in `sources/`; retain the link, review
   date, reliability, corroboration, and promotion decision, but never mirror
   the raw post/article body. If direct retrieval is unavailable, label the
   source review as metadata/index-snippet-only and base any stronger mechanism
   claim on independently reviewed corroboration.
4. Create only cards that meet the narrow recognition → discriminating check →
   caveat rule. Use `source-reported` unless independent evidence justifies a
   stronger lifecycle status; record misleading or incomplete claims in limits.
5. Run ResearchMap validation and indexing, then reply with created paths/card
   IDs and any rejected candidates. A link that could not be fetched still gets
   a metadata-only source capture if its URL and stated topic are available.

This user-directed intake is a deliberate review boundary. Passive collectors
only discover and report candidates; an active research agent may promote a
narrow, source-cited result after performing the admission review below.

## Curated Source Promotion Boundary

Passive source collectors do **not** create cards or other durable guidance.
During an active, concrete research task, an agent may create or update one
atomic `source-reported` card after it verifies the admission criteria, citation,
status, and corpus validation. This is a bounded reviewed promotion—not automatic
persistence of every search result. Record a no-promotion reason when the result
does not qualify.

Use this compactness rule:

```text
quarantined raw fetch → minimal provenance capture → 0..N atomic cards
```

- Keep the raw body quarantined rather than copying a blog/post into the corpus
  or ambient context.
- Create a small source capture only when an item is promoted. Include canonical
  URL, author/date when available, artifact reference/hash, reliability, and
  the promotion decision—not a wholesale source mirror.
- A card is a decision aid, not a blog summary. It must answer: **what exact
  technology signal triggers retrieval; what narrow vector or provider-specific
  question does it create; what smallest check distinguishes it; and what limits
  prevent overclaiming?** It links back to the source for depth.
- Admit cards only for a narrow endpoint/header, parser/resolver, cache/origin,
  SDK/provider, version/configuration, or workflow interaction that yields a
  concrete angle. Reject generic “look harder,” architecture, broad-tool, and
  broad-methodology cards; route those to workflow notes or mindset delivery.
- A focused provider guide is valid when it saves repeated documentation
  reconstruction at a real surface (for example, recognizing a Gemini API key,
  classifying its restrictions, and distinguishing presence from impact).
- Preserve technology/provider specificity when it changes discovery or
  validation. For example, a Gemini card should name Gemini SDK/configuration
  and endpoint signals, relevant key restrictions, and provider-specific
  capability boundaries instead of becoming a generic cloud-key card.
- For a claimed parser or sandbox escape, check the upstream implementation and
  reproduce the narrow behavior in a pinned local version before promoting a
  mechanism. Separate stock behavior from custom defenses, and intended
  expression evaluation from a violated restriction; otherwise a plausible
  write-up can teach agents a false universal bypass.
- Do not create cards merely because a source is interesting, broad, paywalled,
  or a taxonomy. Such material remains an external on-demand reference unless
  it yields a distinct portable recognition → validation → caveat unit.
- If safe-fetch marks content with risk flags or `research_lab` handling, retain
  metadata only and require explicit review before body-based distillation.

## Program Documentation: Target-Specific Application Behavior

Do not introduce a Dossier or another ledger merely to retain program-specific
learning. Existing **Program Docs** are the target-scoped application-behavior
layer between portable ResearchMap cards and concrete MapStore observations.

Use a Program Doc when reviewed research yields a compact model a future agent
would otherwise reconstruct: how a named application uses an SDK, provider,
protocol, object or role model, callback, workflow, trust boundary, or
architecture. It may be source-backed and `partially-verified` before a concrete
target fact exists. Preserve recognition signals, source status, open security
questions, freshness/limits, and explicit unknowns. Never convert a vendor
analogy or generic technology claim into an application fact.

Route cleanly:

- **Program Docs:** “How does this application use this technology or flow?”
- **MapStore:** concrete observed target facts, coverage, tested-state, and
  concise pointers.
- **ResearchMap:** reviewed portable recognition → mechanism → discriminator →
  caveat knowledge.
- **Hypothesis Ledger:** selected, target-grounded test ideas; it owns duplicate
  controls, not documentation storage.
- **Attempts:** exact executed test history.

A concrete technology or integration signal in a Program Doc may justify a
narrow ResearchMap query. Their combination is a grounded research lead, not
proof the target has the mechanism and not an automatic hypothesis.

When a concise observed fact and a longer behavior model both exist, link them.
Do not manufacture a MapStore fact simply to justify useful source-backed program
research. Keep unresolved server-side binding or enforcement questions as
questions, not findings.

### Program-Doc Discovery Contract

A doc that only matches its author's prose is not durable agent knowledge. Give
each new program doc controlled, queryable metadata: stable `tags`, likely
alternate `aliases`, relevant `surfaces`, and named `technologies`. Keep labels
lowercase identifiers and use concrete concepts (for example `guardian`,
`transaction-binding`, `passport-sdk`) rather than vague labels such as `bug`
or `research`.

Agents query this metadata before opening any raw document. The retrieval CLI
may inspect files internally, but returns only concise match metadata until an
agent chooses one doc. Before promotion, prove at least three independent
retrieval routes: a tag, a surface or technology, and an alternate term/alias.
If a reasonable synonym misses, add it as an alias or recognition signal rather
than expecting future agents to infer the original vocabulary.

## Interface Choice

For a project-local research corpus, prefer a documented CLI when agents can invoke it directly. Add an MCP wrapper only if a caller specifically requires tool-protocol integration; do not create one merely because the data is queryable.

For Bug Bounty Harness utilities, put project-level CLIs under:

```text
scripts/ (invoke each concrete helper through the `bbh` dispatcher)
```

Provide init, validation, indexing, query, and help behavior. Keep outputs bounded and cited so agents receive a briefing rather than a raw document dump.

## Verification

- Validate frontmatter, required fields, allowed statuses, citations, and unique card IDs.
- Index a fixture corpus and query by terms, class, and tags.
- Confirm output preserves status, source citation, relevant code signals, mechanism, and test direction.
- Keep focused automated tests next to the owning project and document the user-facing CLI in the project README.

See `references/research-map-pattern.md` for the BBH implementation pattern and policy wording, and `references/card-admission-examples.md` for concise accept/reject examples.
