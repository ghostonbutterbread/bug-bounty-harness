# Use Wordlists Playbook

## Purpose

Compose local/public wordlists with Ghost-generated packs, run bounded fuzzing,
post progress updates, and record what was tested.

## Wordlist Roots

Prefer local wordlists here:

```text
/usr/share/wordlists
```

Other useful roots:

```text
~/wordlists
~/projects/ghost-wordlists/wordlists
~/Shared/web_bounty/<program>/web/recon/wordlists/generated
```

Do not assume SecLists is the only public source. SecLists is one strong source
inside the broader `/usr/share/wordlists` tree.

## Temporary Composition

When multiple lists are needed, compose them into a temporary run file rather
than committing or preserving a giant duplicate list.

Example shape:

```bash
tmp_wordlist="$(mktemp -t ghost-wordlist.XXXXXX)"
trap 'rm -f "$tmp_wordlist"' EXIT

python3 ~/projects/ghost-wordlists/scripts/compose_wordlist.py \
  --wordlist /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  --wordlist ~/Shared/web_bounty/<program>/web/recon/wordlists/generated/<run-id>/packs/javascript-routes.txt \
  --output "$tmp_wordlist"
```

Preserve the manifest and source list paths. Do not preserve the temporary
combined list unless Ryushe explicitly asks for it or the campaign needs a
resume artifact.

## Fuzz History

Before fuzzing, check the program fuzz history log for the same URL pattern and
wordlist set.

Suggested path:

```text
~/Shared/web_bounty/<program>/web/recon/fuzz_history/fuzz_runs.jsonl
```

Each record should include:

```json
{
  "timestamp": "2026-06-15T12:00:00-07:00",
  "program": "example",
  "run_id": "fuzz-example-20260615T120000",
  "url_pattern": "https://www.example.com/FUZZ",
  "wordlists": ["/usr/share/wordlists/...", "generated/.../javascript-routes.txt"],
  "wordlist_fingerprint": "sha256:<sources-or-temp-file-hash>",
  "rate": 5,
  "filters": {"match_codes": "200,204,301,302,307,401,403,405", "filter_codes": "404"},
  "output": "~/Shared/web_bounty/example/web/recon/fuzz/runs/<run-id>/raw/ffuf.json",
  "status": "running|completed|stopped|failed",
  "summary": {"tested": 1000, "hits": 12, "interesting": 3}
}
```

This log is not a replacement for `/url-ingest`. It answers "what fuzzing did
we run, when, against what URL pattern, with which lists, and where are the
outputs?"

## Telegram Updates

Post active campaign updates every 2 hours to the fuzzing Telegram topic:

```text
https://t.me/c/3763915138/15974
```

Update fields:

- percent complete
- ETA or remaining candidate count
- new hits since last update
- key URLs/routes found
- status: running, stalled, completed, needs review

## Ingest

After each checkpoint or completion, ingest URL-like results:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
python3 agents/url_ingest.py aggregate <program> \
  --input ~/Shared/web_bounty/<program>/web/recon/fuzz/runs/<run-id>/normalized \
  --run-id <run-id> \
  --scope-filter auto
```

## Exit Checklist

- Fuzz history record exists.
- Raw output path is recorded.
- Interesting hits are summarized.
- URL-like output is ingested.
- Telegram update posted if the campaign is active or completed.
