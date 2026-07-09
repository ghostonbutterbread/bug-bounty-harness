# Hunter Loop Playbook

Hunter Loop is the agent's parent bounty-hunter control loop. It keeps the broad
application model coherent, records learnings, and dispatches specialists when
the mapped surface gives a reason.

## Goal

Turn a target objective into an adaptive loop:

```text
scope -> goal -> map a little -> touch the app -> observe -> learn -> dispatch -> verify -> merge -> next hypothesis
```

The parent agent is not the main exploit engine. It is the orchestrator that
keeps context, avoids duplicate work, and hands precise packets to specialists.

## Parent State

Maintain a target memory pack with:

- current goal and allowed scope
- auth recipe and approved account/resource references
- full URLs, route clusters, and app sections
- forms, methods, content-types, CSRF/session observations
- JavaScript files, client routes, sources, sinks, and API calls
- object identifiers and ownership hints
- constraints learned from failed attempts
- working payloads and failed payload boundaries
- callback/collaborator-style observations when approved
- completed lanes and next hypotheses
- specialist packets sent and results merged

Store secrets by reference only. Never write raw cookies, bearer tokens,
passwords, API keys, reset links, private headers, or private config values.

## Mapping Loop

1. Pick one section or goal.
2. Load only scoped safety/account context and route state needed to begin.
   Do not start with a broad findings-ledger or MapStore review.
3. Explore with browser/CDP first when the flow is JS-heavy or stateful.
4. Perform one normal user action or one small controlled probe to learn how
   the selected surface behaves.
5. Query MapStore only for the concrete URL, host, surface, defense, or
   vuln-class boundary you are about to test or dedupe.
6. Add runtime routes, forms, scripts, objects, and auth boundaries to the map.
7. Convert each interesting observation into a trigger or a scoped boundary.
8. Dispatch specialists only when the trigger has enough context.
9. Merge specialist results back into the target memory pack and MapStore.
10. Choose the next section, next specialist, or stop condition.

Prior findings are advisory coordination only. They help the parent avoid
duplicate work, choose adjacent untested surfaces, or merge fresh evidence into
an existing FID. They do not satisfy the current goal by themselves unless the
goal explicitly asks for status, portfolio review, duplicate triage, report
cleanup, or revalidation of that exact historical finding.

MapStore is a targeted memory lookup and write-back layer, not the creative
starting point. Use it to ask "was this exact URL/surface/class already tested?"
after the live surface is selected, then keep or pivot hypotheses based on the
current runtime behavior. Do not inherit the prior entry's vuln class as the
default lane.

Do not wait for a complete overhead map before touching the application. The
agent should learn by interacting with one surface, observing its real behavior,
then updating the map.

Browser/CDP should be core for:

- report-to-admin and moderation flows
- stored and DOM XSS
- OAuth/SAML and account linking
- CSRF/session-sensitive forms
- upload preview/render flows
- JS-heavy route/API discovery

Use curl or direct HTTP when it gives clearer request control, but preserve the
browser context when behavior depends on client state.

## Dispatch Triggers

Send focused specialists when the map shows:

- ID/tenant/object ownership: `/access-control`, `/idor`
- JWT/JWK/JWKS/key-source behavior: `/jwt-auth`
- OAuth/SAML/password reset/account linking/MFA/invite: `/ato`
- stored render/admin review/email/export path: `/stored-xss`, `/dom-xss`
- DOM source/sink/router/localStorage/postMessage: `/dom-xss`
- upload parser, metadata, SVG, media preview, CDN path: `/pfp`, `/ssrf`,
  `/stored-xss`, `/access-control`
- checkout/coupon/subscription/credit/refund entitlement state:
  `/payment-testing`
- method/path/header/status-code boundary: `/error-triage`, `/403`,
  `/bypass`, `/headers`, `/access-control`
- SQL/template/file/path behavior: `/sqli`, `/ssti`, `/lfi`
- rate/concurrency/state race signal: `/race`

Do not dispatch because a vuln class is generically possible. Dispatch because
the app surface gave a concrete reason.

## Specialist Packet Contract

Each packet should be small and complete:

```json
{
  "program": "target-name",
  "section": "profile-avatar",
  "objective": "test whether avatar object IDs are tenant-isolated",
  "scope": ["https://target.example/profile", "https://target.example/api/avatar/123"],
  "auth_context": "owned test account A and B via approved session references",
  "required_skills": ["access-control", "idor", "account-testing-policy", "live-testing-policy"],
  "known_facts": ["avatar id 123 belongs to account A", "GET returns 200 for owner"],
  "already_tested": ["filename reflection in profile HTML escaped"],
  "constraints": ["no destructive profile deletion", "no raw token storage"],
  "evidence_standard": "cross-account request must show non-owned object data or mutation",
  "stop_condition": "stop after ownership boundary is confirmed, blocked, or two safe variants produce no signal"
}
```

Include full URLs. Include only the relevant app slice. Exclude broad proxy
dumps, raw secrets, unrelated history, and unsanitized personal data.

Every specialist packet should include an attempts directory, for example
`agent_shared/attempts/xss/search/2026-07-08T150000Z/`. The specialist writes exact
payloads, why they were chosen, transformations, evidence, block reasons, and
next mutations there. MapStore receives the durable conclusion and a pointer to
the attempts artifact.

## Specialist Result Contract

Each specialist returns:

- verdict: confirmed, interesting_signal, tested_no_signal, blocked, or needs_followup
- exact attempts and what changed
- pressure state: cold, warm, hot, or exhausted
- evidence file references
- constraints learned
- reusable claims
- MapStore facts written or proposed, with attempt artifact pointers
- new routes, IDs, scripts, or flows discovered
- recommended next specialist or stop condition

The parent merges results into Hunter Memory and the target memory pack. Failed
attempts become scoped boundaries, not global rejections of a vuln class.

Pressure-state rules:

- `cold`: no signal yet. The parent can pivot if small probes show no behavior.
- `warm`: signal exists but no exploit. Continue classification and mutation.
- `hot`: partial control or bypass clue. Keep pressure unless a safety gate
  blocks the next probe.
- `exhausted`: representative mutation families failed and the boundary is
  understood. The parent can pivot or hand off the residual gap.

Do not treat "blocked" as a final answer when the vector is `warm` or `hot`.
Classify what blocked it, record the exact families tried, and choose the next
discriminating probe.

## Human Steering

Ryushe can steer the parent loop with short directives:

- "send IDOR on this ID"
- "stop fuzzing and read JS"
- "switch to browser"
- "focus report-to-admin"
- "check upload parser"
- "pause live testing, summarize memory"

Record steering as an orchestrator event and update the current plan.

## Benchmark Mode

Controlled labs are for measuring whether the loop improved, not just proving a
single exploit path.

Track:

- lab and category
- solved or failed
- attempts and specialist path
- browser required
- human hint required
- blocker reason
- chain depth
- evidence files
- reusable lessons

Start with Hoster-local labs such as Juice Shop and local reproductions. Keep
intentionally vulnerable apps bound to localhost unless Ryushe explicitly asks
to expose them.

## Stop Conditions

Stop or ask for steering when:

- scope, auth, ownership, rate, or destructive-action policy is unclear
- a specialist needs credentials or sensitive material not already approved
- the same lane repeats without new observations
- the map has enough evidence to move to a better section
- a current-run confirmed vulnerability is ready for normal report/promotion workflow
