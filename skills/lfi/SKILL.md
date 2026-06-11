---
name: lfi
description: "Use when testing Local File Inclusion, file path traversal, file read sinks, path normalization bypasses, wrappers, null bytes, log poisoning, or proc/environment disclosure."
---

# LFI — Local File Inclusion Bypass

## What It Does
Tests LFI bypass techniques: path traversal, null bytes, wrappers, log poisoning.

Load `general-security-testing-policy`, `live-testing-policy`, and
`injection-testing-policy` before live testing. For file/path sinks, absence of
an immediate file read or response delta is not a stop reason by itself; use
the policy to reason about path normalization, extension allowlists, wrappers,
encoding, parser differences, and stack-specific proof ladders.

## Invocation
```
/lfi <target> [--param <param_name>] [--program <program>]
```

## Harness Location
Uses `/bypass` harness: `~/projects/bug_bounty_harness/agents/bypass_harness.py`

## Example
```
/lfi https://target.com/download?file=test.pdf
/lfi https://target.com/view?path=/etc/passwd --param path
```

## Techniques
- Path traversal: `../../etc/passwd`, `%2e%2e%2f`
- Null bytes: `%00`, `%2500`
- Wrappers: `php://filter/`, `data://`, `expect://`
- Log files: `/var/log/apache2/access.log`
- Proc: `/proc/self/environ`, `/proc/[pid]/fd/*`
