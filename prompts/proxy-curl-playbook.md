# Proxy Curl Playbook

Use this when a saved proxy request must become a working direct `curl` replay.

## Core Rule

Start from the raw request. Do not rebuild it from memory.

For auth-sensitive apps, the important pieces are often not just cookies. Preserve product context headers, workspace/account headers, CSRF/challenge headers, `Origin`, `Referer`, `Content-Type`, and the body exactly before attempting mutations.

## Conversion Checklist

1. Parse the request line:
   - method: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, etc.
   - target: absolute URL or origin-form path
   - protocol version: usually not needed in `curl`
2. Build the URL:
   - absolute target stays as-is
   - origin-form path uses `Host`
   - default scheme is `https://`
   - use `http://` only when the capture or proxy metadata proves it
3. Preserve headers in raw order:
   - keep `User-Agent`, `Accept`, `Accept-Language`, `Referer`, `Origin`, `Content-Type`
   - keep `Cookie` as one header exactly as captured
   - keep `Authorization`, CSRF headers, and product-specific `X-*` auth/context headers
   - keep duplicate headers if the server behavior may depend on them
4. Preserve the proxy request's header list by default:
   - keep `Host`
   - keep `Content-Length` and `Connection` unless there is a specific replay/framing reason to drop them
   - keep browser fetch metadata such as `Sec-Fetch-*`
   - keep priority/client hints such as `Priority`
   - drop the `HTTP/1.1` request-line protocol marker because `curl` expresses protocol through flags, not the URL line
5. Preserve the body:
   - use `--data-binary @body.file` when possible
   - do not reformat JSON before the baseline replay works
   - do not convert multipart boundaries manually unless replaying the exact captured body
6. Add replay controls:
   - `--compressed` when the request advertises compressed response support
   - `--path-as-is` for path normalization, traversal, or encoded path tests
   - `--max-time` for bounded probes
   - `--include` or `--dump-header` for evidence

## Helper

```bash
python3 "$HARNESS_ROOT/skills/proxy-curl/scripts/raw_to_curl.py" request.raw
python3 "$HARNESS_ROOT/skills/proxy-curl/scripts/raw_to_curl.py" --body-file /tmp/replay-body.json request.raw
python3 "$HARNESS_ROOT/skills/proxy-curl/scripts/raw_to_curl.py" --scheme http request.raw
python3 "$HARNESS_ROOT/skills/proxy-curl/scripts/raw_to_curl.py" --drop-framing-headers request.raw
```

The helper emits a command that preserves method, URL, raw header order, and the captured body. It keeps `Content-Length` and `Connection` by default because the saved proxy request is the source of truth. Use `--drop-framing-headers` only when deliberately letting `curl` recompute transport framing.

The helper keeps the raw `Host` header by default and does not force `--http1.1`. Add `--http1.1` only when the server or proxy behavior depends on HTTP/1.1 instead of curl's negotiated default.

## Sensitive Material Handling

Generated commands may contain cookies, bearer tokens, CSRF tokens, or app-specific auth headers. Execute them locally, then clear shell history or use a temp script if needed. Do not paste them into Telegram, findings, long-term notes, or child-agent prompts.

When writing evidence, use this format:

```text
proxy-curl:
- method:
- full URL:
- preserved header names:
- body shape:
- mutation:
- result:
- raw request artifact: local path only, access controlled
```

## Baseline Before Mutation

Always run one baseline replay before changing a security-relevant field. If the baseline fails, fix request shape first:

- stale cookies/token: capture a fresh request with `/single-request-grabber`
- missing browser/client fingerprint: retry through the agent proxy or browser lane
- 400/415: compare `Content-Type`, body bytes, and multipart boundary
- 401/403: compare auth headers, cookie freshness, account/workspace headers, `Origin`, and `Referer`
- route mismatch: compare full URL, scheme, host, path encoding, query order, and `--path-as-is`

Only mutate after the baseline behaves like the browser/proxy request.
