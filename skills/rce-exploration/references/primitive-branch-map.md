# RCE Primitive Branch Map

Use after an RCE lead is plausible and before repeating a mutation family. This
is a reasoning map, not a payload list. Keep each branch as a private hypothesis
with its observed basis, predicted signal, and next safe discriminator.

## Branch dimensions

```text
producer: field, file part, header, object property, stored value, or job input
representation: quoting, delimiter, encoding, declared/detected type, or parser form
transform: validation, normalization, serialization, storage, queueing, or reparse
consumer: process API, evaluator, template, deserializer, converter, loader, or worker
trigger: synchronous request, preview, retrieval, scheduled job, import, or later action
context: runtime, feature flag, role, sandbox, privilege, deployment, or reachability
observation: response, error, timing, owned output, stored render, task-owned observer, or trace
```

A source-to-execution explanation is a branch through these dimensions. Unknown
links stay explicit; do not replace them with a generic RCE label.

## Process / command branch questions

For a suspected process helper, distinguish whether the controlled value is:

- an argument to a direct process API or part of a shell-parsed string;
- quoted, concatenated, normalized, or rejected before the consumer;
- consumed immediately, by validation/delivery/diagnostics, or by a deferred
  worker; and
- observable through synchronous behavior, delayed owned output, or an
  authorized task-owned observer.

A no-signal result for one representation and observation model does not decide
another source, consumer, trigger, or execution API model.

## Other primitive families

- **Templates/evaluation:** source versus data, renderer/parser mode, escape
  layer, feature state, and output/side-effect channel.
- **Deserialization/parser/converter:** selected format/type, declared versus
  detected type, parser fallback, nested representation, later processor, and
  error/output channel.
- **Uploads/processors:** file metadata versus body, selection/routing, preview
  or worker trigger, converter identity, and owned result channel.
- **Configuration/loaders/jobs:** controlling setting or artifact, selection
  boundary, actor/worker context, delayed trigger, and bounded observation.

## RCE handoff fields

For an RCE branch, include the active primitive's source/field,
representation/transform, consumer/API, trigger/timing, execution context, and
observation channel in the hypothesis record. Use
`hypothesis-expansion-policy` for candidate status, materially-distinctness,
repeated non-distinguishing tests, deferral, and exhaustion decisions.
