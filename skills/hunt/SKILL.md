---
name: hunt
description: Use for the `/hunt` slash entry on a program: explore a current surface through normal browser and task-proxy behavior. Goal-driven runs load `bug-goals`; solo hunting cadence loads `hunter-loop`; multi-agent campaigns load `bunny`.
---
# Hunt — Start a Bug Bounty Hunt

For a live application behavior question, explore the relevant feature using
its normal browser behavior and task-proxy requests; use `live-map` for
class-neutral runtime understanding and complementary source/technology lenses.
`browser-session-policy` also permits direct HTTP for small, known-shape
questions. Start from the current surface or a strong lead and connect
observations as you go; a complete map, code inventory, or research sweep is not
a prerequisite. Explicitly offline or collection-only work stays in scope.
When an actual research question needs outside ideas or technical context, load
`research-knowledge-management` and its source map to select useful sources;
existing policy still owns research and conclusion gates.

## Invocation
```
/hunt <program> [tasks]
/hunt superdrug xss,sqli
/hunt superdrug fuzz --parallel
```

## Examples
```
/hunt superdrug xss
/hunt superdrug xss,sqli,ssrf --parallel
/hunt superdrug fuzz
```
