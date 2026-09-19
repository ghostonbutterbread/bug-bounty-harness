# DNS Rebinding

Use when a fetcher's hostname validation and connection appear to resolve
independently, or when an approved test calls for racing validation-time against
connection-time DNS. Rebinding requires explicit approval; without it, use this
pack only to observe the validation/connection resolution differential, never to
complete an internal connection.

## Mechanism

DNS rebinding exploits TOCTOU between two resolutions of the same hostname:
a validator resolves address A (public, allowed) and approves the URL; the
fetcher's later resolution returns address B (internal) and connects there.
It succeeds when resolution is repeated — not cached or pinned between check
and connect — and no post-resolution address re-check exists.

## rbndr.us test hostnames

Tavis Ormandy's public rebinding service generates a hostname that alternates
randomly between two IPv4 addresses with a very low TTL. Format: the two
addresses as concatenated hex quads, first address first:

- `127.0.0.1` + `192.168.0.1` → `7f000001.c0a80001.rbndr.us`
- `127.0.0.1` + `169.254.169.254` → `7f000001.a9fea9fe.rbndr.us`
- generator UI: https://lock.cmpxchg8b.com/rebinder.html ; source:
  https://github.com/taviso/rbndr

Each hex quad is the four octets as two-digit hex, in order
(`10.0.0.1` → `0a000001`). Swap the two quads to flip which address is "first".
Common pairs: loopback + private target, loopback + cloud metadata
(see `metadata-scheme.md`).

## Listener-side address (A or B)

Resolution itself never touches your listener: the rbndr.us nameservers answer
every query, so DNS lookups of the rebind hostname produce no callback. On the
target side you see only which address the fetcher connected to — evidence is
the connection plus whatever response delta it produces. Attribution therefore
depends entirely on the address you choose:

- **Owned IP** (preferred for attributed proof): point an interactsh-client
  (or equivalent OOB listener) at your own server and use that IP as A or B.
  Any connection is attributable to your run, including raw-socket or
  non-HTTP callbacks that never send an interactsh-style Host header.
- **Public OAST cluster IP** (boundary proof only): the interactsh default
  clusters resolve to e.g. `oast.pro` 178.128.212.209, `oast.live`
  178.128.210.172, `oast.site` 178.128.16.97, `oast.online` 178.128.87.9,
  `oast.me` 178.128.209.14, `oast.fun` 206.189.156.69. Your DNS query returns
  this IP, but you receive no interaction from it — these IPs only prove
  "something connected out" plus a response delta; connections are not
  attributable to you and the target receives the cluster's default response,
  not a payload you control.

Typical approved test flow:

1. Repeatedly resolve the rbndr hostname to confirm both addresses appear.
2. Submit `http://<rebind-host>/` to the fetch surface; observe whether the
   validator saw the public address while the fetch connected internally
   (status delta, timing, callback, or error shape).
3. If resolution is cached/pinned or a re-check exists, the family is dead;
   record it and stop.

Note: resolution is random per query, so a single attempt proves little —
compare repeated submissions against a non-rebinding baseline hostname.

## Differential observation without approval

Without approval, gather only resolution-behavior evidence: DNS lookup timing
and answer stability across validation and fetch, whether the fetcher re-resolves
after a redirect, IPv4-only validation with an AAAA connection, and whether a
hostname allowlist checks addresses post-resolution. These map the
validation/connection boundary without deliberately completing an internal
connection.

## Evidence and stop rule

Record both resolved addresses, TTL behavior, which resolution the validator
used, which the fetcher used, and the resulting response delta. A rebinding
claim needs resolution traces on both sides plus a server-side response
difference — client-side navigation or speculation is not evidence. Stop when
the boundary is understood or the impact proof is reached; do not scan
internally through a rebinding hostname.

## Sources

- Tavis Ormandy, [rbndr](https://github.com/taviso/rbndr) and
  [rebinder UI](https://lock.cmpxchg8b.com/rebinder.html)
- Wikipedia, [DNS rebinding](https://en.wikipedia.org/wiki/DNS_rebinding)
