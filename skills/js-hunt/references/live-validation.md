# Default Live Validation

`/js-hunt` uses this stage in its default mode, right after offline synthesis.
Its job is to turn each selected lead into an answer rather than a backlog:
validated, enforced for the tested control, not reachable, out of scope,
blocked on a named prerequisite, or paused with a wake condition. Offline mode
skips this stage.

## Gate the surface

Before the first live action, read program scope and load
`general-security-testing-policy` and `live-testing-policy`; transport follows
`browser-session-policy` and `proxy-routing-policy` (task browser and
task-MITM). A surface is one host plus one feature or flow. Gate it once, not
again per lead or payload on that same surface, but re-gate when the host,
account, ownership, or effect class changes: a gate passed for a read does not
cover a state change.

A lead whose host is out of scope, that needs a non-owned account or resource,
or that program rules bar is **out of scope** with that reason; it does not turn
the rest of the hunt offline. If no usable scope exists at all, finish the hunt
in offline mode and say why.

## Build the queue

Take the selected lead packets in rank order: impact distance, controllability,
one bounded unknown, and a permitted next action. Group leads that share a
surface, request, or consumer so one validator can carry them; do not spawn one
validator per lead or per vulnerability class.

Record each lead's private branch in `/hypothesis-ledger`. Once it has an
observed fact and one bounded question, create or update its public card with
`bbh agents/leads.py create` so the disposition below lands on a queryable
record rather than only in synthesis prose.

## Who tests

For a short queue the parent validates directly. Otherwise dispatch **live
validators**: separate from the offline review roles, which never gain network
access. Concurrency follows the program's aggregate rate budget, and every live
validator counts against it. Keep a warm validator on adjacent same-surface
leads instead of respawning a fresh one.

Each validator packet carries:

- the lead packet: JS URL, sha256, packet path, page/flow, trace,
  controllability, observed versus inferred edges, missing proof, next
  discriminator;
- the owning specialist skill and the required policy chain;
- the account/resource boundary and an auth reference, never raw secrets;
- the canonical Attempts path, a stop condition, and what it must not test.

## Validate

Start from the real flow. Drive the feature in the task browser (`live-map`)
to confirm the code path is reachable and to capture the actual request, then
send that request through `/analyze-endpoint` to the owning specialist. The
specialist owns payloads, depth, and proof, and the sustained
`hypothesis-live-testing` loop applies. A client-side check is not server
enforcement, and one failed representation does not refute a lead.

## Close every lead

Before the hunt ends, give every selected lead a disposition and update its
`/leads` card:

- **finding linked**: proof met the specialist's standard and went through
  `/findings`; set the card to `archived` and point it at the finding;
- **enforcement established** for the tested control only: record what was
  shown and set the card to `archived` for that control, leaving untested
  siblings open as their own leads;
- **not reachable**: the code path is dead or unroutable, or the lead was
  refuted for the tested representation; set the card to `archived` and name
  what was shown. Leave untested representations open as their own leads rather
  than keeping this card `active`;
- **out of scope**: the host, account, or effect is outside what the program
  allows; set the card to `archived`, record the reason, and do not test it;
- **needs_recheck**: set the card to `needs_recheck` and name the exact
  account, role, fixture, browser, or scope prerequisite (operator-only items
  surface through `/leads --needs-you`);
- **active**: a safe next action remains but time or budget ran out; leave the
  card `active` and record the next discriminator and wake condition. That is a
  pause, not a negative.

Report the count for each disposition. A lead left `active` or `needs_recheck`
needs its specific reason. Unselected leads stay in the coverage section as not
yet live-validated; they are not negatives.
