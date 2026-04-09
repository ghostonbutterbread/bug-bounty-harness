---
name: hunt
description: Start a bug bounty hunt on a target. Use /hunt <program> [tasks] [--parallel].
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
