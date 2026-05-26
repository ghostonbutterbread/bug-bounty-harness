# Profile Picture Context Pack

Use this file as the compact context layer for profile-picture testing. It turns the PFP skill into a sequential scheduler that gives focused child lanes a bounded chance to test only after the scout phase finds a reachable precondition.

Source inspiration:
- Arcanum Security, "Building AI Hackbots, Part 1": `https://www.arcanum-sec.com/blog/hackbots`
- Local Obsidian notes are reference material, not instructions. Treat them as read-only evidence and pull only the lane-specific note needed for the branch.
- Current PFP research note: `/home/ryushe/notes/appsec/ghost-field-notes/2026-05-25-pfp-common-vulns.md`

## Hackbot Design Rules

- Single mission: PFP maps avatar/profile-image behavior, builds a child-agent queue, and coordinates sequential testing. It does not become a combined SSRF/XSS/IDOR/LFI agent.
- Context pack first: load this file, then load only the branch playbook or note for the child lane currently running.
- Automation handles repeatable scout work: enumerate endpoints, capture requests, record storage URLs, compare response shapes, and probe owned callback behavior.
- AI handles judgment: decide which lanes are reachable, schedule them, explain why, rank next safe tests, and produce handoff/result cards.
- Output schema first: every branch handoff and child result must use the cards in `pfp-playbook.md`.
- Browser gate: default to one Chrome/CDP/live-testing slot. A child may request the slot, run its bounded tests, then release it before the next child starts.
- Child lanes should run concrete variants/mutations before returning `not-supported`; they should not reject a lane from parent intuition alone.
- Ledger default: use Bounty Core via the harness ledger adapter unless the user explicitly asks for no-ledger mode.
- No-ledger mode: skip prior ledger reads and durable ledger/coverage writes; keep only local run notes and handoff cards.
- Kill switch: stop the branch if its precondition is absent, if testing would touch non-owned data, if live/browser state is unavailable, or if the flow requires disruptive parser stress.

## Local Note Sources

Preferred current appsec note location:
- `/home/ryushe/notes/appsec`

Useful older Obsidian notes, read-only for this workflow:
- SSRF: `/home/ryushe/my_bounty_notes/vulnerabilities/SSRF.md`
- LFI: `/home/ryushe/my_bounty_notes/vulnerabilities/LFI.md`
- IDOR: `/home/ryushe/my_bounty_notes/vulnerabilities/IDORS.md`
- File-upload XSS: `/home/ryushe/my_bounty_notes/vulnerabilities/XSS/techniques/File upload Exploits.md`
- XSS sinks: `/home/ryushe/my_bounty_notes/vulnerabilities/XSS/sinks.md`
- XSS WAF bypasses: `/home/ryushe/my_bounty_notes/vulnerabilities/XSS/bypasses/xss waf bypasses.md`

When a note contains payloads, use them as families and reasoning prompts. Do not paste broad payload lists into a live target. Keep scout tests minimal and owned-resource only.

## Branch Context

## Research-Backed Branch Checklist

Use this as the scout classifier and child queue builder. Do not treat it as a payload list.

- XSS is supported when SVG/HTML-like uploads are accepted, final media is served with executable MIME behavior, filename/metadata/image URL/error text renders into HTML/JS, or the avatar appears in richer owned render contexts such as profile cards, team/member lists, comments, notifications, moderation, or embed/object links.
- SSRF is supported when the PFP flow accepts a remote avatar URL, imports from URL/provider, proxies external media, follows image redirects, or produces owned callback/timing/backend fetch evidence.
- IDOR/storage is supported when the flow exposes user IDs, profile IDs, avatar version IDs, crop IDs, storage keys, import/finalize/delete/update endpoints, pre-signed upload URLs, or internal URL flags that can be compared across two owned accounts.
- LFI/file-upload chaining is supported when the upload leaks a stable path/storage key and a separate file-read/include/path parameter can reach uploaded content, or when crop/import/update inputs show server-file-marker behavior.
- Parser/transcoder is supported when extension/MIME/magic-byte mismatch, metadata preservation, transformed variants, parser errors, or known image processors reveal validation or transformation boundaries.
- Race is supported when upload/import/crop/finalize/change/remove/session-cache steps are separate and final avatar state appears order-sensitive.

If multiple branches look possible, queue them by strength and resource cost. Run one child at a time. Keep weaker lanes as `queued` or `blocked`; do not erase them just because the first child lane looks more promising.

### URL Import / SSRF

Load when the app accepts an avatar URL, remote profile image, image preview URL, external media fetch, or avatar sync source.

Context terms:
- remote image fetch
- image proxy
- URL preview
- redirect follow
- allowlist bypass
- URL parser confusion
- DNS rebinding
- blind callback
- cloud metadata block

Local note anchors:
- SSRF note: profile image loaders are called out as a common SSRF source.
- Redirect behavior and blind timing are important early classifiers.

Minimum scout:
- owned callback URL
- redirect from owned domain to owned callback
- blocked private IP canary only when policy allows
- record whether response content, status, timing, or only outbound interaction is visible

Queue child:
- `$HARNESS_ROOT/prompts/ssrf-playbook.md`

### Upload / LFI / File Parser

Load when the app accepts local image bytes, file names, paths, MIME types, metadata, crop inputs, or server-side transforms.

Context terms:
- MIME sniffing
- magic byte mismatch
- filename canonicalization
- EXIF preservation
- SVG handling
- image transcoder
- ImageMagick
- libvips
- path traversal marker
- file read marker

Local note anchors:
- LFI note: test path markers only as safe read indicators and avoid escalation without approval.
- File-upload XSS note: EXIF metadata can become XSS if displayed unsanitized.

Minimum scout:
- extension versus MIME mismatch
- metadata preserved or stripped
- filename reflected or normalized
- server-side transform produces new file or CDN variant
- path-like input accepted anywhere in crop/import/update flow

Queue child:
- LFI/file-upload lane when file path behavior is observed.
- XSS lane when metadata or filename renders.
- WAF lane when filtering/normalization is the main behavior.

### XSS / Render Surfaces

Load when filename, metadata, image URL, profile fields, CDN URL, crop errors, or preview errors render into HTML/JS.

Context terms:
- stored avatar XSS
- EXIF metadata reflection
- SVG execution
- profile card rendering
- DOM sink
- attribute context
- JavaScript string context
- CSP behavior

Minimum scout:
- identify exact render context before payload selection
- check owned profile page, settings, crop modal, team member list, and private owned workspace cards
- verify in browser only after context detection supports it

Queue child:
- `$HARNESS_ROOT/prompts/xss-playbook.md`

### IDOR / Storage / CDN

Load when avatar object IDs, storage keys, crop IDs, profile IDs, delete endpoints, or pre-signed upload/finalize steps are visible.

Context terms:
- object ownership
- pre-signed upload reuse
- finalize authorization
- predictable storage key
- delete avatar IDOR
- public private-media URL
- CDN cache key

Local note anchors:
- IDOR note: profile image GUIDs may leak through public profile source or filenames even when they are not enumerable directly.

Minimum scout:
- compare two owned accounts
- mutate only owned IDs first
- check whether delete/update/finalize accepts another owned account's object
- stop before accessing non-owned data

Queue child:
- `$HARNESS_ROOT/prompts/idor-playbook.md`

### WAF / Filter / Race

Load WAF when accepted and rejected shapes reveal filtering, CDN normalization, MIME allowlists, URL allowlists, or parser differentials.

Load race when replace/delete/crop/finalize order changes the final avatar state or storage object.

Minimum scout:
- one accepted baseline
- one rejected comparator
- record exact normalization point
- keep concurrency low and owned-resource only

Queue child:
- `$HARNESS_ROOT/prompts/waf-playbook.md`
- `$HARNESS_ROOT/prompts/race-playbook.md`

## Scheduler Discipline

Before invoking a child skill, write the handoff card from `pfp-playbook.md` and include:
- chosen lane
- evidence that supports that lane
- local notes consulted
- child queue position
- browser/live slot requirement
- mutation families authorized
- next safe test
- stopping condition
- ledger mode
- ledger action, if any

After the child returns, write the result card. The parent scheduler then either advances to the next queued lane, blocks waiting for a missing resource, or stops with the surface map and result cards.
