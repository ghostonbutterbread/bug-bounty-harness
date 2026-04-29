# Shared Review Gate Spec (0day-Team Canonical Model)

## Purpose
BaseTeam exists to provide the shared baseline for all hunting teams. The goal is that new teams inherit the same core orchestration, review semantics, and reporting behavior that already work well in `zero_day_team`.

Under this model:
- teams should mainly differ in the agents they spawn, the target-specific prompts they use, and the target surfaces they inspect
- the shared review/report gate should follow the `zero_day_team` model as closely as possible
- future teams should inherit the same quality bar for confirmed, dormant, and speculative findings

This means the canonical design target for BaseTeam is not the current lightweight shared review. It is the richer `zero_day_team` review model.

## Canonical Source of Truth
The canonical model for review/report behavior is the `zero_day_team` implementation.

The parts of `zero_day_team` that should become shared baseline behavior are:
- strict structured review output
- `CONFIRMED`, `DORMANT_ACTIVE`, `DORMANT_HYPOTHETICAL` semantics
- real PoC requirement for `CONFIRMED`
- placeholder PoC rejection
- exploitability-first reasoning
- differentiation between concrete blockers and speculative blockers
- conservative downgrade behavior when evidence is incomplete

## Design Goal for BaseTeam
BaseTeam should contain the shared core of:
- agent lifecycle / spawning
- logging and trace writing
- findings collection
- deduplication
- shared review gate
- promotion into report states / ledger

Teams should primarily customize:
- which static agents exist
- which dynamic agents get generated
- how prompts are targeted to a target family (web, apk, exe, etc.)
- any target-family-specific preflight context

In other words:
> The teams should differ mainly in what they hunt, not in how the shared review/report core thinks.

## Core Doctrine
For every finding, the shared reviewer should answer:
1. What safety assumption makes this implementation appear safe?
2. Can an attacker realistically break that assumption?
3. Is the resulting behavior actually an unintended and security-relevant boundary break, or merely intended feature behavior?
4. What is the practical exploit path?
5. If the exploit path is incomplete, is the blocker concrete/actionable or still hypothetical/speculative?

Short form:
> What assumption makes this safe, can an attacker break that assumption, and does that create a practical exploit path?

This doctrine is additive to the existing `zero_day_team` exploitability model, not a replacement for it.

## Shared Tier Model
The shared tier model should follow `zero_day_team`.

### CONFIRMED
A finding is `CONFIRMED` only when all of the following are true:
- the code path is real
- the reviewer can identify the safety assumption
- the reviewer can explain how attacker input breaks that assumption
- the resulting behavior is not merely intended feature behavior
- the exploit path is concrete
- the reviewer can support a real standalone PoC

### DORMANT_ACTIVE
A finding is `DORMANT_ACTIVE` when:
- the vulnerability appears real
- the broken assumption / boundary break is meaningful
- the exploit path is not fully complete yet
- but the blocker is concrete and actionable

Examples:
- needs prior XSS
- requires authenticated access
- requires a separate file-write primitive
- depends on a specific prerequisite interaction or foothold

### DORMANT_HYPOTHETICAL
A finding is `DORMANT_HYPOTHETICAL` when:
- the pattern is interesting and plausibly security-relevant
- but the exploit path is still incomplete or speculative
- or the blocker is vague/inconclusive
- or the assumption break is not fully proven yet

Examples:
- maybe reachable
- unclear whether attacker controls the final sink
- more research needed
- possible boundary break but not yet validated

## Novel Findings
"Novel" is a content classification, not a replacement for exploitability review.

A finding may still be marked novel, but its exploitability tier should follow the same reasoning discipline:
- if concrete and PoC-backed, it can still be strong
- if incomplete, it should still land in `DORMANT_ACTIVE` or `DORMANT_HYPOTHETICAL`

## Intended Behavior Gate
A dangerous capability is not automatically a vulnerability.

Examples of capabilities that are not inherently bugs:
- downloading a file
- opening a document
- rendering remote content
- exposing a parser
- providing an IPC route
- accepting a callback
- exposing a WebView bridge to trusted content

The question is not just:
- is this dangerous?

The question is:
- what assumption makes this safe?
- can attacker-controlled input violate that assumption?
- if yes, does that produce unintended security impact?

This intended-behavior analysis should be part of the shared reviewer’s reasoning for all teams.

## PoC Rule (Shared)
The `zero_day_team` PoC rule should become the shared default:
- `CONFIRMED` requires a real standalone PoC
- placeholder, generic, or hand-wavy PoCs do not qualify
- if PoC is missing, the finding should not be promoted to `CONFIRMED`
- if the issue looks real but the PoC is not yet available, it belongs in dormant, not confirmed

## Shared Review Output Contract
The shared reviewer should return a structured JSON object with these fields:
- `tier`
- `poc`
- `impact`
- `cvss_vector`
- `cvss_score`
- `severity_label`
- `vulnerability_name`
- `blocked_reason`
- `chain_requirements`
- `remediation`
- `review_notes`
- `safety_assumption`
- `assumption_break`
- `intended_behavior_analysis`
- `exploit_path`

The first group comes from the current `zero_day_team` model.
The second group adds the new shared doctrine.

## Shared Review Rules
The shared reviewer should follow these rules:
- Use `CONFIRMED` only when there is a concrete exploit path and a real PoC.
- Use `DORMANT_ACTIVE` when the issue appears real but a specific prerequisite still blocks exploitation.
- Use `DORMANT_HYPOTHETICAL` when the issue is incomplete, inconclusive, or still speculative.
- Always identify the safety assumption.
- Always explain whether attacker input can break that assumption.
- Always judge whether the observed behavior appears intended or unintended.
- Prefer dormancy or inconclusive handling over overstating a capability as a vulnerability.

## Shared Promotion Logic
The shared normalization/promotion logic should enforce:
1. Missing or placeholder PoC blocks `CONFIRMED`
2. Missing safety assumption weakens confidence and should block promotion
3. A supposedly confirmed finding must include:
   - a broken assumption
   - a practical exploit path
   - a real PoC
4. Findings with concrete blockers become `DORMANT_ACTIVE`
5. Findings with vague blockers become `DORMANT_HYPOTHETICAL`
6. Intended feature behavior without a real boundary break should not be promoted as a vulnerability

## Architecture Direction
The long-term architecture should be:
- `BaseTeam` owns the shared review/report core
- `zero_day_team` is no longer special because of different review philosophy; it is special only because of the agents and prompts it uses
- `apk_team`, `exe_team`, and future teams inherit the same review semantics
- target families differ mainly in their hunting surfaces, not in the shared core logic

## Current Gap
Today, BaseTeam still uses a lighter review model than `zero_day_team`.
That means the architecture has not yet reached the intended design.

The desired end state is:
- BaseTeam review logic is upgraded to match `zero_day_team`
- the assumption-break doctrine is layered into that richer shared model
- teams inherit the same review/report behavior by default

## Implementation Guidance
When implementing this spec:
- do not simplify `zero_day_team` down to the lightweight BaseTeam model
- instead, lift `zero_day_team` concepts upward into BaseTeam
- preserve the dormant-active vs dormant-hypothetical split
- preserve the PoC requirement for confirmed
- integrate the assumption-break and intended-behavior doctrine into the richer shared review contract

## Recommended Next Step
The next implementation phase should be:
1. treat `zero_day_team` review semantics as canonical
2. refactor BaseTeam review/promotion logic to mirror those semantics
3. integrate the new assumption-break / intended-behavior fields into that shared review model
4. update teams to inherit the shared BaseTeam logic rather than maintaining different review philosophies
