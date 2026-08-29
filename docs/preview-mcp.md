# Preview research search

Preview is an authenticated external retrieval source for curated security
write-ups. Use it for cited analogue mechanisms, implementation context, and
emerging knowledge—not as proof of a target condition.

## Credential storage

The API key is **not** stored in this repository, BBH run artifacts, prompts,
logs, or shell history. The default key location is a user-only file outside the
repository:

```text
~/.config/bug-bounty-harness/preview.env  (mode 0600)
```

Its only required entry is:

```text
PREVIEW_API_KEY=rk_...
```

`PREVIEW_API_KEY` in the process environment takes precedence. The client parses
the file as key/value data; it does not source or execute it. The client refuses
a key file readable by group or others.

## Search

```bash
bbh scripts/preview_mcp.py search \
  --query "WAF bypass for reflected XSS behind Cloudflare" \
  --k 5 --min-score 0.1
```

Optional flags:

- `--candidates 80` controls the pre-rerank candidate pool (1–300).
- `--full-content` requests available whole articles.
- `--key-file /secure/path/preview.env` selects another 0600 key file.
- `--endpoint URL` supports a compatible endpoint for testing.

The standard account API caps `k` at 5 and has a 4-request-per-minute burst
limit. Keep queries targeted and preserve only the cited, relevant result
material. Do not write raw API keys into task packets, artifacts, commits,
reports, or chat.

## Verification

```bash
uv run --with pytest python -m pytest tests/test_preview_mcp.py -q
bbh scripts/preview_mcp.py search --query "DOM clobbering" --k 1
```
