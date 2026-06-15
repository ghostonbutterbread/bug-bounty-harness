---
name: use-wordlists
description: Use when composing local wordlists and generated packs, running rate-limited fuzz campaigns, posting fuzzing updates, and recording fuzz history.
---

# Use Wordlists

Compose and use wordlists for fuzzing. This skill owns temporary wordlist
composition, fuzz campaign manifests, progress updates, and fuzz history logs.

## Workflow

1. Read `prompts/use-wordlists-playbook.md`.
2. Prefer local wordlists under `/usr/share/wordlists`; use generated Ghost
   packs and other configured wordlist roots when relevant.
3. Compose selected files into a temporary run wordlist instead of duplicating
   large lists permanently.
4. Before fuzzing, check the program fuzz history log for the same URL pattern
   and wordlist set.
5. Run the selected fuzz harness with explicit scope, rate, filters, and output.
6. Post active campaign updates to the Telegram fuzzing topic every 2 hours.
7. Record the run in fuzz history with date, URL pattern, wordlists, output path,
   and outcome.
8. Ingest discovered URL-like output through `/url-ingest`.

Use `/fuzz` for the underlying fuzzing method and safety rules.
