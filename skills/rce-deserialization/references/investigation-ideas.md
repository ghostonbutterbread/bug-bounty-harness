# Deserialization Investigation Ideas

Use the branch matching the observed path, then follow evidence beyond this
list. These ideas are **not a ceiling**, a required sweep, or a payload ladder.
They apply the representation/control/reconstruction/trigger lens in the entry;
runtime semantics and primary sources are in
[technology mechanisms](technology-mechanisms.md). A discriminator below is a
question to resolve with existing code, normal runtime observations, or a scoped
probe through `rce-validation`—not independent authorization for live mutation.
Retain the baseline, inert comparison, strongest benign explanation, and the
precise edge measured. Do not infer execution from a parser error or acceptance.

## A data-only wrapper contains a second format

**Signal / question:** JSON, signed state, an XML element, or a typed bytes field
contains another blob. Does the later consumer merely store it, or decode and
reconstruct objects from it?

**Discriminator and control:** trace the inner field from the normal request to
the actual loader and trigger; compare with an ordinary data-only sibling using
the same outer path. Inspect each transform without invoking the loader locally.
The [session case](session-object-case.md) illustrates this mechanism without
making the outer framework itself unsafe.

**What would falsify it:** the selected inner value is only treated as data and
never reaches object reconstruction on the examined path. Successful base64
decoding or an object-looking prefix proves neither loading nor accepted control.

## Readable state is mistaken for writable state

**Signal / question:** a round-tripped object is readable, or comes from a store
assumed to be internal. Can this actor author bytes the loader actually accepts?

**Discriminator and control:** locate authentication/encryption and integrity
verification order, producer authorization, and fields covered by the check.
Compare the normal state with an inert owned-field change where live policy
permits it; identify whether rejection occurs before reconstruction. Exposed or
reused signing material is a distinct, evidence-backed precondition—not a reason
to guess keys. An opaque ID requires an authorized writer to its backing store.

**What would falsify it:** verified integrity rejects this actor's changed
representation before any behavior-capable load and no controlled writer reaches
that object. Readability, ability to edit a request, or possession of one valid
signed sample does not demonstrate a signing capability.

## A format field selects a class rather than a schema

**Signal / question:** type discriminators, class/assembly names, object tags,
or custom converters appear. Do they select fixed application data types or
open-ended runtime types?

**Discriminator and control:** inspect the reader, allowed subtypes, filter or
binder, and available classes. Compare the expected benign type with a harmless
schema/type discrepancy appropriate to that loader; distinguish validation error
from resolved type. Ask which reachable hook or later operation would matter.

**What would falsify it:** the selected path enforces a closed harmless mapping
before risky reconstruction, or the supplied metadata remains ordinary data.
An arbitrary-looking class name in a response is not instantiation proof, and
one missing gadget does not prove every permitted type harmless.

## The first request is not the consuming request

**Signal / question:** upload, import, saved workflow, callback state, cache
entry, or queued job is accepted but appears inert. Is the dangerous reader a
preview, resume, retry, callback, or worker with a different configuration?

**Discriminator and control:** use `rce-lifecycle` to track one owned artifact
through the legitimate producer and specific later consumer. Compare a normal
fixture and inert sibling at that trigger, preserving correlation across jobs
and retries. Distinguish validation before enqueueing from reconstruction later.

**What would falsify it:** evidence shows this selected consumer never loads
the controlled representation, or a verified defense prevents that edge.
An empty immediate response or a missing observation channel is not that
negative. Record the missing consumer/observer and reopening condition rather
than declaring the whole feature exhausted.

## A post-load error hides an earlier effect

**Signal / question:** the handler rejects the reconstructed value or reports a
type error. Did that happen before loading, during a hook, or after an earlier
behavior? Some runtimes can act before the final value is usable.

**Discriminator and control:** establish ordering from source, available traces,
or a deterministic permitted observation chosen with `rce-validation`. Compare
with an inert sibling that fails at the same later validation boundary. Separate
parser, reconstruction, application validation, and subsequent use.

**What would falsify it:** the evidenced rejection precedes the behavior-capable
operation for this representation. A 500 response alone supports neither
execution nor safety; do not deploy delays, callbacks, or destructive effects
merely to locate the stage.

## Alternate representations reach a different policy

**Signal / question:** an observed feature has different import formats, reader
versions, content-type handlers, compatibility paths, or error/fallback loaders.
Do they share the same integrity and type restrictions?

**Discriminator and control:** compare legitimate representations of the same
owned data and trace parser selection, decoded bytes, verification coverage,
and loader configuration. A concrete discrepancy supplies the next branch;
`injection-testing-policy` owns parser-boundary testing, with `waf-live-policy`
only when filtering is the observed blocker.

**What would falsify it:** the compared handlers enforce the same effective
pre-load boundary on this input. Do not assume fallback acceptance or a bypass
from different status codes; a rejected format says nothing about an unexamined
supported format. Avoid format spraying without a reader-selection hypothesis.

## No attacker-controlled producer has been found

**Signal / question:** source reveals a risky loader but the visible UI only
supplies a server-issued ID. Is there a legitimate import, low-privilege writer,
shared cache producer, or integration that can feed the same object?

**Discriminator and control:** work backward from the reader and forward from
mapped producers, comparing their actual namespaces, keys, object identities,
accepted types, and ownership. Use normal owned fixtures to establish the edge;
separate access-control or state-tampering impact from deserialization RCE.

**What would falsify it:** the examined loader is fed only by an integrity- and
authorization-protected producer outside this actor's control. A sink without a
source remains a chain lead until that boundary is established; do not guess
cache keys, target other users' objects, or treat an internal label as proof
that no writer can exist.

## A visible technology signature tempts a ready-made chain

**Signal / question:** a bundle, error, manifest, report, or advisory names a
serializer or gadget library. Are its relevant version, options, dependencies,
reader, and trigger actually present on this deployment?

**Discriminator and control:** use `rce-technology-research` and the matching
technology card to turn the mechanism into a target-specific precondition
question. Look for an exact call/configuration or observed reader behavior;
contrast with dead code, a browser-only dependency, fixed data types, or an
unreachable worker. Preserve version uncertainty instead of filling it in.

**What would falsify it:** the required behavior is disabled, unavailable in
that runtime, or cannot consume the controlled value on the examined path.
A package version or a public exploit is exposure context, not target proof;
a negative for one known chain is not a universal safety verdict.
