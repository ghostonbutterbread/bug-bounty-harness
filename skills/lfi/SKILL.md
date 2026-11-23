---
name: lfi
description: "Use when testing Local File Inclusion, file path traversal, file read sinks, path normalization bypasses, wrappers, null bytes, log poisoning, or proc/environment disclosure."
---

# LFI — Local File Inclusion Bypass

## What It Does
Tests LFI bypass techniques: path traversal, null bytes, wrappers, log poisoning.

Load `general-security-testing-policy`, `live-testing-policy`, and
`injection-testing-policy` before live testing. For file/path sinks, absence of
an immediate file read or response delta is not a stop reason by itself; use
the policy to reason about path normalization, extension allowlists, wrappers,
encoding, parser differences, and stack-specific proof ladders.

**Depth.** Once any probe produces signal on an owned surface, load
`hypothesis-live-testing` and stay in its mutate-compare-continue loop while
responses still teach. Build each family from a defense thesis and a class
thesis (`injection-testing-policy`). The surface is gated once, not per
payload; do not leave a warm vector to record a blocker.

## Invocation
```
/lfi <target> [--param <param_name>] [--program <program>]
```

## Harness Location
Uses `/bypass` harness: `agents/bypass_harness.py`

## Example
```
/lfi https://target.com/download?file=test.pdf
/lfi https://target.com/view?path=/etc/passwd --param path
```

## Mechanism

The app builds a filesystem path from input and hands it to an opener:

```text
input -> decode(s) -> filter / normalize -> join -> open() | include()
```

A bug exists when the filter and the opener disagree about what the string
means. Every family below is a hypothesis about **where the filter sits** in
that pipeline. Locate the filter first; the payload follows from its position.

## Why each family works

| Payload | The disagreement it bets on |
|---|---|
| `/etc/passwd` | the path is concatenated, not safely joined, so no traversal is needed |
| `../../etc/passwd` | nothing normalizes between input and the opener |
| `%2e%2e%2f` | the filter runs **before** URL-decoding, so it never sees `../` |
| `%252e%252e%252f` | **two** decode passes, with the filter between them |
| `....//` | the filter strips `../` **once, non-recursively**; the remainder re-forms it |
| `..%c0%af`, overlong UTF-8 | the decoder accepts a non-canonical form the filter does not recognize |
| `/.&./` | some component **collapses unknown dot-segments**; which one is the open question |
| `/etc/passwd%00.pdf`, `%2500` | the opener terminates on NUL **before** the extension the filter validated |
| long path plus valid suffix | the opener truncates **after** the filter validated the suffix |
| `php://filter/convert.base64-encode/resource=`, `data://`, `expect://` | the sink is a **stream opener**, not a file reader, so it resolves schemes |
| `/proc/self/environ`, `/proc/<pid>/fd/N`, `/var/log/apache2/access.log` | no traversal needed; the readable file **is** the secret, or becomes it via log poisoning |

The `/.&./` row is a worked example of a derived candidate rather than a known
one. A [source-reported case](https://x.com/sirbagoza/status/2122866976183710164)
shows a 200 with passwd-like output against a 400 for a conventional request,
but the route and transformation are unknown. `.&.` is not normally a
parent-directory component, so do not assume Apache, PHP, or a filesystem reads
it as `..`; something in the chain would have to be collapsing it. Preserve
literal versus percent-encoded `&`, which can delimit query parameters. A status
delta alone is not proof of a file read.

## Locating the filter

Each probe narrows position. Run every one against a benign owned-file control.

1. **Baseline** — a legitimate file. Record status, length, timing, body shape.
2. **`../` with no filename** — blocked on shape alone means the filter is early
   and pattern-based.
3. **`%2e%2e%2f` against `../`** — *different* responses mean the filter is
   pre-decode; *identical* means post-decode, or two decoders.
4. **`....//`** — passing where `../` blocked means a non-recursive stripper.
5. **Double-encoded** — passing means two decode passes with the filter between.
6. **Append a known-good extension** — a changed verdict means suffix validation
   exists, so NUL and truncation become the targets.

Then build the payload the filter passes and the opener interprets.

If no probe discriminates, the filter is not where you think it is. Find the
actual consumer before trying more strings; a payload list does not substitute
for knowing the pipeline.

## Deriving a new family

When the families above are spent, do not stop at the list. Ask which pipeline
stage you have not yet disagreed with:

- a decoder you have not fed a non-canonical form;
- a normalizer whose unknown-segment behavior you have not probed, which is the
  `/.&./` class of candidate;
- a join you have not tried to escape with an absolute or UNC-style path;
- an opener whose scheme handling you have not tested;
- a suffix check you have not tried to truncate past.

A new family is one stage plus one disagreement. Record it as an unverified
candidate with its reasoning and the control comparison that would prove or kill
it, the way `/.&./` is recorded above.
