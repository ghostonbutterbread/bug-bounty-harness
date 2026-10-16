# Blocker-first examples

Use these as compact status shapes. Replace the factual values with the actual
evidence; do not claim closure from the template.

## Access/state gate

```text
BLOCKER — access/state: the tested route needs an owned account that can create content; only unauthenticated reads were available.
WHY — This leaves the create → store → render path untested; it does not show that stored content is safely handled.
NEXT — Create the smallest program-permitted throwaway account and exercise the normal content-creation flow.
```

A missing fixture is a testing precondition, not evidence of a product defense.

## Output encoding on one route

```text
BLOCKER — normalization/encoding: the controlled value reached the tested HTML attribute but was escaped for that attribute context.
WHY — This rules out the tested breakout on this response, not other render contexts or consumers.
NEXT — Compare only evidenced alternate consumers or contexts before deciding whether the route is closed.
```

## Scope/policy gate

```text
BLOCKER — scope/policy: the next reproducing action would require a non-owned resource.
WHY — The observed difference is insufficient to establish impact within the authorized boundary.
NEXT — Use an owned equivalent or obtain explicit program authorization.
```

## When `closed` is justified

Use `closed` only after the mechanism and meaningful reachable variants for the
claimed route have been evidenced. Otherwise report `not demonstrated under
<conditions>` and name the condition.
