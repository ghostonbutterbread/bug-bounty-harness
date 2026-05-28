# Metadata And Scheme

Use when cloud/container metadata or non-HTTP schemes may be reachable through a server-side fetcher.

## Checks

- Start with low-risk metadata roots or banners.
- Add required metadata headers only when the platform requires them and `/headers` confirms the header behavior is relevant.
- Check alternate schemes only when the feature accepts or partially parses them.
- Prefer banner/status proof over secret retrieval.

## Destination Classes

- AWS metadata root
- GCP metadata root
- Azure metadata instance root
- ECS credentials root
- loopback service banner
- RFC1918 internal service banner
- non-HTTP scheme acceptance marker

## Evidence Required

- Destination class reached.
- Minimal payload.
- Response/callback/banner proof.
- Statement that no secrets were harvested.

## Stop

Stop after proving metadata/internal reachability. Do not enumerate deeper, collect tokens, or interact with destructive internal protocols.
