# Research Card Admission Examples

Use these as classification examples, not target claims.

## Accept: Next.js client build manifest route candidates

**Trigger:** an authorized browser context for a Next.js application exposes
`__BUILD_MANIFEST.sortedPages` or loads a client build-manifest asset.

**Angle:** compiled client page-route candidates may be read without wordlist
guessing.

**Small check:** inspect the already-loaded manifest; treat each value as a
recon lead only. Dynamic instances, API/server-only handlers, protected routes,
and some routing/deployment modes may be absent.

**Why it qualifies:** a product-specific client artifact creates a narrow,
repeatable reconnaissance angle with a clear pivot condition.

## Accept: Gemini API-key restriction/impact guide

**Trigger:** an authorized artifact contains a Google API-key-shaped value near
Gemini SDK/configuration or `generativelanguage.googleapis.com`.

**Angle:** classify whether it is a Gemini-context key, what consumer/service
restrictions apply, and whether an unintended consumer can make the smallest
permitted request.

**Why it qualifies:** provider-specific recognition and validation boundaries
avoid re-deriving documentation at each actual Gemini surface.

## Reject to workflow notes: “IIS recon and fuzzing”

A broad article about recon/fuzzing is useful process knowledge, but has no
single implementation interaction, trigger, or discriminating check. Preserve a
cited workflow note and retrieve it only when someone asks about IIS or recon
workflow.

## Reject to mindset delivery: “AI changes bug-bounty economics”

Strategic framing can influence lane selection, but it does not tell an agent
what concrete signal to recognize or validate. Send a compact insight to the
user rather than creating an ambient tactical artifact.

## Promotion evidence

A social post or newsletter is a candidate source, not fact by itself. Capture
provenance, inspect primary material, corroborate behavior/version claims with
vendor docs/source/patches or independent quality evidence, and use an owned
fixture where feasible. Label the resulting card according to the actual
strength of evidence.