# RCE Validation Ladder

Use the lowest rung that proves the current question. Follow the live-testing
and attempt-recording policies for every target interaction.

1. **Baseline:** capture ordinary behavior and all relevant request/response,
   async-job, callback, and rendering context.
2. **Inert differential:** use a harmless marker or structurally equivalent
   value to test encoding, normalization, parsing, storage, and retrieval.
3. **Pre-sink precursor versus interpreter differential:** a narrowly scoped,
   non-enumerating process-context precursor may test a *plausible* execution
   boundary before the sink is evidenced, under the owned-state, baseline,
   comparison, rate, and live-policy gates in `precursor-ladder.md`. A
   class-appropriate interpreter expression is a different rung: use it only
   once the candidate sink is evidenced, and compare with an inert sibling.
4. **Controlled execution signal:** after informative precursor evidence, or a
   recorded blind/asynchronous observation gap, first explain why an available
   lower-impact measurement is insufficient and select one permitted,
   correlated deterministic confirmation. A visible synchronous branch may use
   a response difference; a blind branch may need a bounded delay or an owned,
   authorized task-scoped callback. A callback is not mandatory for a visible
   branch, and no-signal on one channel is not closure of another.
5. **Safe owned-impact proof:** only when the program permits it and lower
   signals are insufficient; keep it non-persistent, non-enumerating, and
   confined to a disposable/owned resource.

## False-positive controls

A positive requires a baseline plus a negative control and an explanation for
why the signal is attributable to the alleged executor rather than caching,
retry, proxy behavior, a generic error handler, client rendering, WAF response,
or unrelated background work. Re-run only when it is safe, necessary, and
rate-compliant; do not create noisy confirmation loops.

## Stop boundaries

Stop and request approval before filesystem enumeration, secret or token access,
interactive shells, reverse connections not explicitly allowed, persistence,
privilege changes, internal network access, broad worker triggering, or any
operation that may affect non-owned resources.
