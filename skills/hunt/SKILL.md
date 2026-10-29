---
name: hunt
description: Use when starting or orchestrating a bug bounty hunt, running /hunt for a program, selecting testing tasks, or coordinating parallel security research work.
---
# Hunt — Start a Bug Bounty Hunt

For a live application behavior question, explore the relevant feature using
its normal browser behavior and task-proxy requests; use `live-map` for
class-neutral runtime understanding and complementary source/technology lenses.
`browser-session-policy` also permits direct HTTP for small, known-shape
questions. Start from the current surface or a strong lead and connect
observations as you go; a complete map, code inventory, or research sweep is not
a prerequisite. Explicitly offline or collection-only work stays in scope.

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
