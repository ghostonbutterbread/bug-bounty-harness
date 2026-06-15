---
name: create-wordlists
description: Use when building bug bounty wordlist packs from JavaScript, URL params, proxy traffic, recon artifacts, technology fingerprints, documentation, or subdomain patterns.
---

# Create Wordlists

Build target-aware wordlist packs from evidence. This skill creates candidate
lists; it does not run fuzzing campaigns.

## Workflow

1. Read `prompts/create-wordlists-playbook.md`.
2. Resolve the program recon root and existing aggregate files.
3. Try Ryushe proxy as a best-effort source. If unavailable, report that and
   continue with recon, local proxy, agent proxy, JS, docs, and technology
   fingerprint sources.
4. Build separate packs by source and purpose instead of one opaque list.
5. Write generated target packs under the program recon/wordlist area with
   source metadata and date.
6. Hand execution to `/use-wordlists` or `/fuzz`.

Do not store raw cookies, bearer tokens, credentials, or unsanitized proxy
request dumps in generated wordlists or notes.
