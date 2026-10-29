---
name: hunt
description: Use when starting or orchestrating a bug bounty hunt, running /hunt for a program, selecting testing tasks, or coordinating parallel security research work.
---
# Hunt — Start a Bug Bounty Hunt

For a live application hunt, understand the relevant feature through its normal
browser behavior and task-proxy requests; use `live-map` for class-neutral
runtime understanding and the complementary source/technology lenses. Start
from the current surface or a strong lead and connect observations as you go;
a complete map, code inventory, or research sweep is not a prerequisite. For
browser behavior, `browser-session-policy` owns the transport and its limits.
Explicitly offline or collection-only work remains within the requested scope.

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
