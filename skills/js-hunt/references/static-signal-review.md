# Static signal inventory: application-site review

**Status:** canonical BBH review guidance. **Owner:** `/js-hunt`. This is an
on-demand lens for interpreting an existing JS inventory, not a new scanner,
signature specification, or live-testing permission. It incorporates the
application-site review contract from a profile-local static-signal sketch;
scanner development remains with the analyzer owner and the normal repository
workflow.

Start with the actual scoped corpus and its page/flow provenance: external
scripts, executable inline scripts, runtime-loaded chunks, historical assets,
and source-map modules are distinct acquisition paths. Check the inventory's
skipped inputs, hit caps, truncated packets, and source-map availability.
Neither a zero-hit category nor a downloaded but unscanned module proves the
application lacks a consumer. Never fetch a named target merely to fill an
offline inventory gap without the live policy/scope gate.

Read **individual call sites**, nearby code and the operation's conditions,
not just a category total or the number of named signatures. In parallel,
research APIs of the *observed* framework, renderer, template engine, and
sanitizer for plausible consumers absent from the generic signature catalog;
search the scoped application corpus for their actual use. A documented API is
only a search direction, not evidence that this application calls it. Preserve
bundle/source-map/response location, page or route loading the code, receiver,
argument, guards, and source candidates when deduplicating equivalent sites.

Treat a signature as a tiered lead: recognizable operation, context-dependent
candidate, or non-sink clue. In particular, distinguish a getter from a setter,
fixed from dynamic input, an HTML attribute from a DOM property, text writes
from HTML parsing, script text-node writes from insertion into an executable
element, and URL navigation from script-loading URLs. Template output depends
on escaping and the later consumer; a lexical match alone does not establish
execution or XSS. If a path is warm or hot, trace it now rather than waiting for
a complete sink census.

At handoff, separate the **corpus examined**, **sites observed**, **paths
investigated**, **still-unexamined sites**, and **unknown runtime/server
surfaces**. Keep unexamined-site status and evidence pointers in run notes and
the relevant Coverage question, not in an Attempt or a MapStore status queue.
Record an Attempt only for a deliberate target test, and put supported target
facts in MapStore under its normal contract. Do not create a parallel durable
queue. Trace a candidate through source → transformations → consumer and hand
live validation to its class owner under the normal policies. A site count is
not a review-depth measure or an exploit count.
