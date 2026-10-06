# Freshness and historical memory in a new-finding hunt

**Owner:** Hunter Loop. Load only when historical leads are starting to select
new targets in place of current-app observation. Cold-start scope and live-action
boundaries remain with `general-security-testing-policy`; this reference does
not grant testing authority.

Before choosing another new-finding target, pause historical target selection
and look at the current app/session again. Observe a route, consumer, response
difference, role or object boundary, parser/render behavior, or another behavior that
could change the next decision. State what that evidence changes, then choose
an in-scope action or follow-up. One decisive observation can suffice; neither
elapsed time nor a fixed count establishes freshness on its own.

Historical notes remain useful for a **targeted** `app-facts`, `dedupe`, or
`coverage` question about the selected surface. Do not block those queries or
force an unrelated surface change. Avoid `old-leads`, past findings, and broad
MapStore reads as a new-finding target generator; explicit retest, repass,
cleanup, duplicate triage, evidence capture, and status review follow their
own task goals. When a fresh observation yields a specialist card or a
meaningful lead, attach it to the handoff rather than substituting an old
finding for current evidence.
