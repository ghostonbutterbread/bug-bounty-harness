# RCE Precursor Ladder

Use this resource when the primitive is plausible but not yet evidenced. It
allows agents to create signal rather than wait for passive proof, while keeping
one test tied to one named uncertainty.

## Rule

A precursor is allowed when it is scoped, rate-compliant, uses owned/approved
state, has a baseline and comparison, and avoids execution-environment
persistence, sensitive reads, broad worker activity, or non-owned effect. A
normal application-state write on a verified owned/disposable fixture remains
eligible when it is needed to exercise the named primitive. Record it as an
Attempt. `live-testing-policy` still controls any approval boundary.

## Progression

1. **Normal behavior:** exercise the ordinary feature to establish request shape,
   validation, trigger, and asynchronous behavior.
2. **Representation precursor:** vary one safe structural dimension—format,
   encoding, content type, filename/content relationship, delimiter/quoting,
   template-looking data, object shape, or parser feature—only to learn what
   consumer/transform is involved.
3. **Process-context precursor:** where program rules and live policy permit,
   use a narrowly bounded identity or current-working-directory-style
   discriminator to establish whether a process execution primitive exists.
   Do not expand it into host/file enumeration; redact output and compare it to
   an inert sibling.
4. **Controlled confirmation:** after informative signal, or after the active
   hypothesis records a blind/asynchronous observation gap, explain why an
   available lower-impact measurement is insufficient. Choose one permitted,
   correlated deterministic proof appropriate to the branch; use an authorized
   task-scoped observer only when that branch requires it. Stop at sufficient
   evidence. See `validation-ladder.md` and `rce-validation` for attribution,
   observation-channel, and closure checks.

## Bad precursors

Do not use persistence, interactive shells, reverse connections, secret/token
access, arbitrary file reads, recursive environment discovery, network probing,
privilege changes, or high-volume job triggers as “just precursors.” If a next
step needs one of these, ask under the live policy.

## Result packet

```text
primitive question
baseline and variable changed
expected discriminator
observed result and negative control
transform/consumer inference
next question or closure reason
```
