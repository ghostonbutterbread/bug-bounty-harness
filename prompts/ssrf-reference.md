# SSRF Reference

Use this after `prompts/ssrf-playbook.md` tells you which lane applies.

## Destination Classes

| Class | Examples | Notes |
|-------|----------|-------|
| Loopback | `127.0.0.1`, `localhost`, `::1` | Good first proof for internal reach |
| RFC1918 | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | Useful when loopback is blocked but internal ranges are not |
| Cloud metadata | AWS, GCP, Azure, ECS metadata endpoints | Stop after proving access; do not harvest secrets |
| Internal services | Redis, Elasticsearch, Docker, Kubernetes, admin consoles | Use banner-only proofs when possible |
| Local files | `file:///etc/passwd` and platform-specific equivalents | Only if the fetcher supports file access and the impact is safe to demonstrate |

## Parser-Confusion Families

- Userinfo confusion
- Decimal, octal, hex, or shortened IP representations
- Encoded dots or mixed separators
- DNS rebinding helpers
- Allowlisted host followed by redirect to internal target

## Metadata Notes

| Platform | Common Root | Extra Requirement |
|----------|-------------|-------------------|
| AWS | `http://169.254.169.254/latest/meta-data/` | Usually none |
| ECS | `http://169.254.170.2/v2/credentials/` | Usually none |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | Often requires `Metadata-Flavor: Google` |
| Azure | `http://169.254.169.254/metadata/instance` | Often requires `Metadata: true` |

## Confirmation Indicators

- Metadata banners or platform-specific keys
- Internal service banners such as Redis, Docker, Elasticsearch, or Kubernetes
- Server-side redirect traces or reflected internal status
- Blind fetch callbacks or timing changes tied to a specific destination

## Safety Rules

- Prefer banners, roots, or status-only confirmation over secret retrieval.
- Do not pivot deeper into internal networks once reachability is proven.
- Record the boundary reached and stop there.
