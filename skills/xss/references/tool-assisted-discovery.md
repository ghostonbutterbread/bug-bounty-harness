# Tool-Assisted XSS Discovery

Canonical sources:

- Dalfox: `https://github.com/hahwul/dalfox`
- Dursgo: `https://github.com/roomkangali/dursgo`

Use Dalfox and Dursgo to expand the application map before deep XSS work. Tool
output is triage evidence, not confirmation. Every lead still needs source,
sink/context, and browser verification through the normal reflected, stored, or
DOM XSS lane.

Before running either tool, load `/bounty-tools` for the shared output directory,
manifest, raw/parsed/normalized artifact, rate-limit, stop-condition, and ingest
contract.

## Install Check

Check whether the tools are available before using them:

```bash
command -v dalfox || echo "dalfox missing"
command -v dursgo || echo "dursgo missing"
go version
chromium --version 2>/dev/null || google-chrome --version 2>/dev/null || true
```

If a tool is missing and the user asked for tool-assisted XSS discovery, install
or build it before the run. Do not let install work consume the hunt; record the
tool version, install method, and any blocker in the lane notes.

## Dalfox Install

Dalfox v3 is Rust-based. Upstream-supported install paths include:

```bash
# Homebrew on Linux/macOS
brew install dalfox

# Ubuntu Snap
sudo snap install dalfox

# Arch AUR
yay -S dalfox
# or
paru -S dalfox

# Nix
nix-shell -p dalfox
nix profile install github:hahwul/dalfox
```

If package installs are unavailable, use the latest prebuilt binary from:

```text
https://github.com/hahwul/dalfox/releases
```

Verify:

```bash
dalfox --version
dalfox --help
```

## Dursgo Install

Dursgo requires Go 1.23 or newer. Build from source:

```bash
git clone https://github.com/roomkangali/dursgo.git
cd dursgo
go build -o dursgo ./cmd/dursgo
```

Optional PATH install:

```bash
sudo cp dursgo /usr/local/bin/
```

JavaScript rendering and DOM XSS mode require Chrome or Chromium:

```bash
# Debian/Ubuntu
sudo apt-get update && sudo apt-get install -y chromium-browser

# RHEL/CentOS
sudo yum install -y chromium

# macOS
brew install --cask google-chrome
```

Verify:

```bash
dursgo -h
dursgo -u http://example.com -s none -c 2 -d 1 -output-json /tmp/dursgo-map.json
```

## When To Use Dalfox

Use Dalfox for parameter-centered discovery:

- Large URL lists from recon, archives, crawlers, or proxy history.
- Hidden parameter mining against routes that have few or no visible params.
- Reflection screening before expensive browser or deep payload work.
- Injectable character, filter, and WAF clue collection.
- Structured JSONL/JSON/TOML/Markdown/SARIF output for later lane handoff.

Typical command shapes:

```bash
# URL list reflection and parameter mining pass
dalfox scan urls.txt --format jsonl --output dalfox.jsonl

# Pipeline mode with auth or proxy headers
cat urls.txt | dalfox scan --headers "Cookie: session=REDACTED" --format jsonl --output dalfox.jsonl

# Custom payload corpus for a focused route family
dalfox scan urls.txt --custom-payload /home/ryushe/Shared/word_lists/xss/payloads.txt --format jsonl --output dalfox.jsonl
```

Store output using the `/bounty-tools` run contract:

```text
~/Shared/web_bounty/<program>/web/recon/tools/dalfox/runs/YYYY-MM-DD/<run-id>/
```

## When To Use Dursgo

Use Dursgo for application-centered mapping:

- Route clusters where forms, links, and endpoints need crawling first.
- SPAs and DOM-heavy surfaces where browser-rendered routes matter.
- Authenticated app areas where cookies, bearer tokens, or custom headers are in
  scope.
- Broad XSS lead discovery with `xss`, `xss-reflected`, `xss-stored`, or
  `domxss`.
- Crawling-only maps with `-s none` to collect endpoints before assigning
  specialist agents.

Typical command shapes:

```bash
# Crawl-only application map
dursgo -u https://target.example -s none -c 5 -d 2 -output-json dursgo-map.json

# Reflected/stored XSS discovery
dursgo -u https://target.example -s xss -c 5 -d 2 -output-json dursgo-xss.json

# DOM-heavy SPA discovery
dursgo -u https://spa.target.example -s domxss -render-js -c 3 -d 2 -output-json dursgo-domxss.json
```

For authenticated runs, use a target-local `config.yaml` with sanitized notes.
Never write real credentials or long-lived tokens into shared docs. Save only
artifact paths and credential references.

Store output using the `/bounty-tools` run contract:

```text
~/Shared/web_bounty/<program>/web/recon/tools/dursgo/runs/YYYY-MM-DD/<run-id>/
```

## Hybrid Agent Workflow

The hybrid approach is: tools map broadly, agents reason deeply.

1. Start from existing recon, URL ingest, proxy history, or live-map artifacts.
2. Use Dalfox when the unknown is "which params reflect or accept dangerous
   characters?"
3. Use Dursgo when the unknown is "what routes, forms, browser-rendered pages,
   or authenticated surfaces exist?"
4. Preserve the raw run, write `manifest.json`, and normalize URL-like output
   according to `/bounty-tools`.
5. Normalize tool output into route packets: full URL, method if known, params,
   source clue, sink/context clue, auth state, WAF/filter clue, tool output path.
6. Hand packets to `reflected-xss`, `stored-xss`, or `dom-xss` agents.
7. Agents dynamically map from each lead instead of trusting the tool finding:
   resend inert markers, classify source/sink, inspect browser-rendered DOM
   where needed, choose payload families, and stop when the boundary is clear.
8. Mark tool-only results as `Potential`; mark `Confirmed` only after browser or
   equivalent execution proof.

Good packet shape:

```json
{
  "tool": "dalfox",
  "program": "target",
  "url": "https://target.example/search?q=test",
  "method": "GET",
  "params": ["q"],
  "source_clue": "query param reflected",
  "sink_clue": "HTML attribute candidate",
  "auth_state": "anonymous",
  "filter_clue": "quotes encoded, angle brackets reflected",
  "output_path": "raw/dalfox.jsonl",
  "next_lane": "reflected-xss",
  "status": "Potential"
}
```

## Agent Rules

- Do not treat Dalfox or Dursgo findings as final reports by themselves.
- Do not run broad `-s all` Dursgo scans on large live targets by default; scope
  by route cluster and scanner.
- Keep concurrency and depth conservative unless Ryushe explicitly asks for a
  broad run.
- Use full URLs in notes and reports.
- Preserve auth-state separation: anonymous, owned user A, owned user B, admin,
  or unknown.
- Record install/version, command/config, output file, rate/depth/concurrency,
  and stop reason in `attempts.jsonl` or `summary.md`.
