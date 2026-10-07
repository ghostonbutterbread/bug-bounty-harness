# XSS Source Acquisition and Sink-Census Decisions

Load this reference from the XSS router when a confirmed sink has no currently
reachable controlled source, a sink census needs coverage or prioritization,
or a sanitizer or impact clue could change that ranking. The router owns the
missing-fixture / server-constrained / no-source decision; do not reclassify a
missing fixture as an exhausted or false-positive lane here.

## Prioritize a path, not a sink count

1. **Source reachability:** identify an attacker-writable field, parameter,
   header, stored object, or later consumer that could feed the observed sink.
   If it requires a normal owned artifact or account, name and create that
   fixture under `account-testing-policy` and inherited safety gates.
2. **Consumer and defense posture:** compare the actual renderer and CSP;
   `unsafe-inline` or absent CSP may change viability, while a nonce-based
   policy can constrain an otherwise promising path. Look for email, export,
   metadata, share, or other consumers that might render the same stored value
   differently.
3. **Sink count:** use only as a tiebreaker among paths with comparable source
   reachability and consumer behavior.

A static inventory discovers candidates but does not prove that a user-controlled
source reaches them. Preserve the specific source-to-sink question and a
reopening condition instead of repeating a larger census.

## Reconcile sink groups without collapsing input paths

Group repeated sites when they share a downstream consumer or rendering helper;
this saves repeated analysis of that piece, not testing of every route into it.
Keep each distinct input/entry route as a separate path through its request
filter, validation, encoding, storage and decode stages. Two writers of the same
backend field may have different transforms or WAF treatment; the same value in
a page and an email may have different renderers or CSP. A group-level negative
does not close an untested ingress or consumer.

For a distinct path, retain the input route and control, meaningful transforms,
consumer/render context, evidence, and disposition: connected, constrained or
fixed, not live in the tested context, missing a source/prerequisite, or
unexamined. Scope each negative to the route, source, and consumer tested.
At a meaningful handoff, distinguish raw inventory hits from reviewed
consumer groups and ingress paths, and name unexamined paths and inventory
limits (including capped or missing assets). This is coverage accounting, not
a fixed percentage, new Attempt shape, or demand to payload-test every hit.

## Sanitizer evidence

Do not infer the absence of sanitization from a bundle name search: server-side
sanitization is invisible in the client bundle, and minified client libraries
may not retain recognizable names. If sanitizer behavior is observed, examine
its configuration and actual output—allowed tags/attributes/schemes,
namespace handling, trust wrappers, decode and reparse stages—rather than
ranking solely by whether a library name appears. Route a concrete fingerprint
to `xss-technology-research`; route context-matched mutation to
`xss-payload-engineering`. Neither a sanitizer hit nor one rejected payload
closes a plausible source-to-consumer path.

## Impact amplifiers

Before deprioritizing an otherwise reachable path on a low-tier host, check
whether a **confirmed** same-origin-family primitive changes its impact. For
example, a proven cross-origin credentialed read might amplify a browser
execution path. Use a bounded ledger query for the concrete origin family;
route severity judgment to `impact-fit-policy`. Do not assume an amplifier
merely from a report title or use it to expand scope.

## When to rerun a census

A sink census is a ranking instrument, not proof of coverage. Re-run when the
corpus or application changes materially (new hosts, bundles, deployments, or
consumers), or when a concrete observed source could change the ranking. Do not
rerun an unchanged corpus merely for a fresher list. Continue to inspect
stack-specific render paths and track unexamined source-to-sink questions.
