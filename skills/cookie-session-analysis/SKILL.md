---
name: cookie-session-analysis
description: "Use when inspecting authorized stateless session cookies."
version: 0.1.0
author: Ryushe, Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [cookies, sessions, jwt, django, flask, laravel, express, rack]
    related_skills: [general-security-testing-policy, browser-session-policy]
---

# Cookie Session Analysis

Use CookieMonster for offline inspection of **non-authentic synthetic** stateless-cookie fixtures. It supports JWT (HS256/384/512), Django, Flask/itsdangerous, Rack, Express cookie-session, and AES-CBC Laravel formats. The present runnable workflow does not accept live bearer cookies: the CLI takes `-cookie` in process arguments, and no approved isolated secret-handling adapter is packaged. A weak signing key is a lead, not proof of account impact; this skill does not assess arbitrary cookies or replace authorization/scope checks.

## When to Use

- An owned, synthetic non-authentic cookie fixture may be a signed stateless session; a live target cookie is a deferred candidate, not input to this runnable workflow.
- You need to identify a supported format, decode it, or test it against a controlled/base64-encoded signing-key wordlist.
- Do not use for opaque server-side session IDs, unclear ownership, or unsanctioned live URL fetching.

## Prerequisites

- CLI: resolve `cookiemonster` from `PATH` or the host's user-local `~/.local/bin/cookiemonster`; verify its `--help` locally before use. Ghost and Hoster have been observed with v1.5.0, but do not assume every agent host does.
- For live target interaction, first load `general-security-testing-policy` and `live-testing-policy`; use only approved scope, rate, and owned session context.
- Never place raw cookies, recovered keys, or secret wordlists in shared artifacts, Kanban, tool-call text, logs, or chat. `-cookie` passes its value in process arguments, which may be visible to other processes: use only non-sensitive synthetic, non-authentic fixtures in ordinary agent commands. For a live bearer cookie, stop and request a separately reviewed isolated secret-handling adapter; do not paste it into a shell command or pretend the present workflow can analyze it.

## Procedure

1. Confirm the cookie is a stateless-session candidate and its source is authorized. Completion: supported framework/JWT hypothesis and ownership are recorded without sensitive values.
2. Perform an offline decode/unsign attempt using the verified CLI and a **synthetic, non-authentic** cookie fixture only; do not put live bearer material in a `terminal` command. Completion: output identifies support/decoding or a negative result for that fixture, not the target's cookie.
3. If a custom wordlist is justified, ensure every line is base64-encoded and keep the file private; use `-concurrency 1` against that same offline fixture. Completion: record only a sanitized lead or negative evidence, not the raw key.
4. Treat a recovered signing key as a lead, not a finding. Validate impact only in an owned/approved fixture and follow the applicable technique, attempt-recording, and live-testing policies before any resigning or target-facing request.

## Quick Reference

```text
# Resolve the CLI in the host runtime (user-local is a supported fallback).
COOKIE_MONSTER="$(command -v cookiemonster || printf '%s' "$HOME/.local/bin/cookiemonster")"
test -x "$COOKIE_MONSTER" || exit 1

# Offline inspection
"$COOKIE_MONSTER" -cookie '<synthetic-non-authentic-cookie>' -verbose

# Controlled custom wordlist; contents must be base64 lines
"$COOKIE_MONSTER" -cookie '<synthetic-non-authentic-cookie>' -wordlist '<private-base64-wordlist>' -concurrency 1

# Django resigning only after approved owned-fixture validation
"$COOKIE_MONSTER" -cookie '<synthetic-non-authentic-cookie>' -resign '<controlled-body>'
```

## Pitfalls

- `-url` issues a live HTTP request; it is not an offline inspection mode and is not a substitute for the live-testing policy chain.
- A secret-bearing `-cookie` argument may be exposed in process listings; hiding shell history alone does not make it safe.
- Express `cookie-session` needs the named content and signature cookies joined as documented upstream with `^`.
- Laravel GCM and server-side/opaque sessions are unsupported.
- A key match alone is insufficient evidence of privilege or account impact.

## Verification

Resolve the CLI as above, then run `terminal(command="\"$COOKIE_MONSTER\" --help", timeout=30)` and confirm cookie, URL, and wordlist options. If absent, stop with a host-install prerequisite; do not silently switch to a different cookie tool.
