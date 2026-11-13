# Fetcher-family stewardship

Owner: `bunny-collaborative`. Complements investigator continuity, compaction
rotation, the negative-result challenge, and recon catalog-as-queue. It does not
replace them. This is an **explicit admission/ownership contract**, not a testing-importance gate and not a reason to skip an in-scope discriminator.

## Family versus lens

A **fetcher family** is one server-side fetch *implementation*. Same family
when **all** of these match:

- same executing service / route-kind (asset ingest, chat index, RSS parser,
  headless crawler)
- same egress class (VPC/cloud vs third-party proxy vs browser)
- same response channel (stored object, parsed feed fields, documents body,
  numeric-only, classify-only)

A **lens** is a remaining discriminator on that family: loopback vs metadata vs
hostname vs redirect-follow vs extra field vs content-type. Lenses are not new families.

A **new family** needs a different service, different egress class, **or** a
different body channel. If family identity is unclear, keep the current steward
and ask one characterizing question (service name, UA, egress IP/ASN, body
channel). Do not spawn a hunter to resolve the label.

## Coordinator rule

The campaign record names **at most one steward** per open fetcher family:
worker id, Attempt stream, leased family, remaining discriminator, wake/blocker.
The family stays **open** until evidence-closed. **Live** means that steward is
still interactable. An ended process does not clear the family or authorize a
greenfield hunter.

**Steer, don't respawn.** While that family is open:

- If the steward is live, send the next lens on the native steer channel. Compaction rotation does not spawn while the steward is live.
- If the prior process ended, spawn a **successive bounded segment**:
  same role, same family, predecessor stream cited, **new** Attempt stream only
  because the prior process ended. The packet is “continue this family at discriminator D”, not a greenfield lease. Dispatch must allow this continuation spawn.
- If rotating for compaction after confirmed exit, spawn a **compaction successor** that inherits the family lease. That hunter is not greenfield.
- Do **not** invent a new hunter nickname and greenfield packet because the
  last checkpoint was residual-closed on one lens.
- A steward that is not interactable and has no confirmed exit is not process-ended; inspect status and steer.

**Spawn a greenfield hunter** only when:

- the family is evidence-closed (tested chain link + remaining discriminator
  named as wake, or direct disproof), **and** the next work is a different
  family; or
- independent verification of a candidate.

**Do not spawn** because the steward is still loading skills, writing Attempts,
or sitting in the negative-result challenge. Inspect status and steer. A quiet terminal is not a new family.

A worker that discovers a fetch on a family that already has a steward
checkpoints `need_surface` with pointers; it does **not** self-admit, spray
internals, or ask to be re-leased onto that family. Bunny either steers the
steward or records a wake.

Assign unused fetchers from a recon catalog by unused **family** (or the
existing steward if it is the same family). Do not mint one hunter per catalog
row. Catalog-as-queue remains in `bunny-collaborative`.

Optional campaign-record / hunter-packet field: `fetcher_family:` service +
egress + body channel, one line.

## Worker guidance

You own nearby mechanism-distinct lenses on your leased family while it is
warm. A coordinator steer that names loopback / metadata / hostname / redirect
on the same fetcher is in-scope unless it changes account, rate, or location
(then re-admission). Do not treat “packet said one URL” as a reason to refuse
the next lens on the same implementation. If you cannot continue, checkpoint
with the family identity, last Attempt, and next discriminator — do not spawn
peers.
