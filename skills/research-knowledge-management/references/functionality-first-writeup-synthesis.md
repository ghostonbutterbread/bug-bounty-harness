# Functionality-first write-up synthesis

**Status:** On-demand BBH research method. Use from `/research-knowledge-management`
when asked to synthesize disclosed cases for a product class or when concrete
observed behavior needs source-backed analogies. This is literature-to-hypothesis
work, **not** target reconnaissance, live testing, a finding, or permission to
create a program-specific MapStore fact.

## Build a mechanism survey

1. Frame actors, objects, relationships, lifecycle steps, and downstream
   consumers as *questions*. A category analogy does not establish that a
   particular target has a feature or flaw.
2. Search diverse primary disclosed reports, researcher technical posts,
   project advisories, and vendor postmortems. Product documentation establishes
   intended feature shape, not exploitation. Record each candidate's canonical
   URL, body-access status, and source type. Deduplicate report identities;
   when coverage is broad, keep separate counts for search hits, candidates,
   readable bodies, and distinct substantive mechanisms. An incomplete index
   is not a platform census or a vulnerability count. For structured public
   report formats, fetch through `/safe-fetch` (for example a canonical
   `/reports/<id>.json` only when that endpoint exists). A missing safe-fetch
   helper is a hard stop, not a fallback to direct external-content retrieval.
   Retain only fields needed to answer the question: title, program, status,
   disclosure date, severity rating and its author, researcher narrative versus
   team summary, and source URL. Never echo whole JSON; attachments may contain
   signed URLs and bodies may contain secrets. Distinguish team-summary-only
   entries from readable researcher narratives, and audit high/critical ratings
   as researcher- versus team-assigned. A curated sample or historical `resolved`
   status proves neither prevalence nor current exposure.
3. Admit claims only from bodies actually read. A title, search snippet, HTTP
   success with a JavaScript shell, or inaccessible page is a discovery lead.
   If rendering or an archive is needed, preserve both canonical and mirror
   provenance and pass the external text through `/safe-fetch` before analysis;
   follow `/blocked-page-recovery` for gated pages. If the body cannot be read,
   keep the narrow lead labeled `snippet-only` rather than filling its gaps.
4. Make one evidence card per distinct case: product/feature, attacker role and
   prerequisites, controlled input, trust crossing, *observed* effect,
   deployment/version or user-interaction conditions, and downstream origin or
   execution identity when relevant. Separate platform defect from customer
   configuration, custom code, integration incident, and adjacent analogy.
   Capture vendor disposition (including WONTFIX/out-of-scope) separately from
   the researcher's claimed impact. A callback alone is not internal reachability.
5. Cluster cases by functionality—invitation, association, export, webhook,
   automation identity, portal, import, attachment, renderer, or AI consumer—
   rather than by vulnerability label. Rank qualitatively by *observed* target
   reachability, authority difference, potential consequence, and ability to
   run a bounded owned discriminator; disclosure counts are not prevalence.

## Return an actionable, bounded handoff

For each selected feature cluster, give: evidenced recognition signal, actor
and object boundary, one server-side invariant, plausible non-vulnerable
explanation, next smallest authorized observation, and the existing specialist
skill that owns testing. Do not assert a vendor-specific behavior on an
unobserved target, prescribe a generic payload list, or use a research case as
proof of present-day impact. For staff/public-visible forms or artifacts,
classify that consumer and load `public-forums` before proposing an active
marker. Keep a source-to-claim citation ledger with the task artifact; a link
list without read bodies is not verification.

Route outputs to their current owners:

- **ResearchMap:** only a narrow, reviewed portable mechanism with source
  status, recognition signal, discriminator, and caveat; raw case anthologies
  and broad methodology stay outside atomic cards.
- **Program Docs:** a compact, source-labeled model for a *named* application's
  actual integration or role/workflow once relevant evidence exists.
- **MapStore:** only separately verified concrete target behavior; never write
  a case analogy as an application fact.
- **Hypothesis Ledger/Leads:** a target-grounded question under their own
  private/public and duplicate controls; existing class skills own test proof.

Verify cited bodies and qualifications before promotion. For a proposed
reusable skill or reference, delimit its runtime instructions from supporting
case notes, get independent source/role/consumer-boundary review, and follow
the canonical skill-promotion process. A verified proposal is not an active
runtime skill until its reviewed source and projections are integrated.
