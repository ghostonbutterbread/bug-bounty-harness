# Desync, Deferred, and Cross-Surface Access Control

Use after a normal owned-account object comparison is blocked or inconclusive,
or when the observed request has more than one plausible authority input. This
is a **candidate generator**; load `mutations/idor.md` for the concrete object
mutation list.

## Core Question

An authorization failure can arise when the validator and object resolver use
different values, locations, representations, timings, principals, or surfaces.
Against a known-good baseline, vary **one** observed authority axis at a time.

## Candidate Lanes

- **Location / representation:** the same observed object or owner reference in
  path, query, body, nested input, header, or cookie; number/string, scalar/list,
  duplicate key order, composite/opaque representation.
- **Principal:** observed `accountId`, `userId`, `act_as`, `on_behalf_of`,
  `impersonate`, or equivalent client actor hint. The question is whether the
  server derives the actor from the session or trusts the client field.
- **Method / consumer:** read, update, delete, export, download, finalize, or
  another normal endpoint for the same owned object; indirect fields such as
  `embed`, `expand`, or nested resolvers.
- **Deferred consumer:** an owned reference planted in an invite, assignment,
  transfer, share, export, notification, callback, or async job and consumed
  later under a different authority.
- **Surface:** the same path/query through an in-scope sibling API, client,
  representation, or legacy route. Capture a clean baseline for every surface
  before comparing replay results.

## 403 Pivot

A concrete eligible 403 is neither a conclusion nor a finding. Preserve the
owned-boundary baseline, then load `/403` for the applicable path, header,
auth-state, or route behavior. Continue object-boundary proof through `/idor`.

## Script and Agent Roles

The agent selects the owned accounts/resources, the observed authority axis, and
the interpretation of a result. A script may generate an approved variant matrix
and enforce scope/rate controls; it never infers ownership, impact, or finding
status.

## Proof and Stop

A result must show unauthorized read, list, export, write, delete, transition,
or cross-tenant/cross-principal behavior. Do not promote response-size changes
or status-only deltas. Stop on non-owned private data. For state-changing owned
requests, load `../idor-postconditions.md`.
