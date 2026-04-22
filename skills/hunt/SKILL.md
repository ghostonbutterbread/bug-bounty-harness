---
name: hunt
description: Use when starting or orchestrating a bug bounty hunt, running /hunt for a program, selecting testing tasks, or coordinating parallel security research work.
---
# Hunt — Start a Bug Bounty Hunt

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
