# Reset Recipient Parsing: Mechanisms, Not Magic Strings

Use when reset requests accept unusual whitespace, multiple emails, duplicate fields, nested values, or an address interpreted differently during lookup and delivery. This expands the examples in [ATO patterns](ato-patterns.md), not a mandatory payload checklist. Existing scope, mail ownership, rate, cleanup, and secret-handling boundaries in `/password-reset` still apply. No live target testing is authorized by a public disclosure.

## Follow the identity through the consumers

Reason about **wire bytes → transport decoding → validation/account lookup → recipient construction → mail delivery → token redemption → final account/session**. Not every application has separate components; identify observed transformations rather than inventing an internal architecture. Mark inferred stages as unknown until requests, owned inboxes, authorized logs, or source support them.

Use two distinct owned account/inbox fixtures A and B. A models the account being recovered; B models an independently controlled recipient. Establish normal A-only and B-only behavior, then compare the signal-led mutation. Where permitted, an additional owned inbox not registered on either account distinguishes authorized secondary-address recovery from arbitrary delivery. Do not assume plus aliases are independent mailboxes.

Record the request content type and redacted value shape, actual recipient inbox, which account the delivered token can reset, and any remaining login/factor requirement. A `200`, an email's displayed `To`, or an echoed address cannot establish the final account binding. Use only authorized mail metadata; do not inspect provider systems or expose raw links/tokens.

## Whitespace and decoding order

**Signal / mechanism:** the UI trims a value, the API accepts an encoded alternative, or lookup and mail delivery appear to disagree. Ask whether trimming, splitting, or decoding happens before one consumer and after another. Leading/trailing whitespace around one address is distinct from whitespace *between* addresses and from a newline introducing a mail header.

**Comparison / control:** preserve the baseline content type. In form data, compare a literal-space representation with `%20`, `%09`, `%0a`, or `%0d%0a` only for the character implicated by the observation. A form `+` may decode to space; a literal plus in an address needs appropriate transport encoding. In JSON, compare an actual JSON escape such as `\t` or `\n` with the literal characters `%09` or `%0a`: JSON parsing alone is not URL decoding. `%250a` is a hypothesis about an *additional* percent-decoding stage, not a newline by itself. Preserve the exact transmitted representation; an editor may re-encode it. Recompare A alone to distinguish harmless trimming from a second recipient or wrong-account selection.

**Falsifier / limit:** consistent rejection or consistent normalization to A with delivery and redemption bound to A closes that tested mismatch, not every encoding family. Whitespace acceptance alone is not ATO. MIME encoded-word decoding is a separate mechanism below, not another spelling of URL encoding.

## Multiple recipients and secondary-address recovery

**Signal / mechanism:** an array/list is accepted, an API supports recovery through secondary email, or mail construction accepts more values than account lookup verifies. One address may select A while another receives A's usable recovery authority. GitLab's CVE-2023-7028 advisory documents reset delivery to an unverified address, multiple-email JSON arrays, and the secondary-email recovery feature involved.[1]

**Comparison / control:** adapt the existing array and delimiter examples to the observed schema; compare A-only, B-only, A+B, and reversed order. Commas, semicolons, pipes, and whitespace are candidate separators, not interchangeable mail syntax. Determine whether the recipient is a verified recovery address of A; use the unregistered owned inbox when that distinction matters. Check whether mail delivered to B actually redeems for A rather than containing B's own reset.

**Falsifier / limit:** independent account-bound emails for A and B, rejection of the list, or delivery only to A's verified recovery addresses does not establish cross-account authority. An unauthorized password reset can be real while MFA still prevents login; do not report a demonstrated MFA bypass without its own evidence.[1]

## Duplicate parameters and merged input sources

**Signal / mechanism:** the request uses form/query parameters, or an edge/API adapter may collapse duplicates differently from a later consumer. First-wins, last-wins, collection, and concatenation are possibilities to observe—not framework guarantees.[2]

**Comparison / control:** use the duplicate and scalar/array examples in ATO patterns, reverse their order, and compare both single-value controls. If the actual endpoint consumes query and body inputs together, compare those sources independently before combining conflicting owned values. Observe whether validation/account lookup selects one value while recipient construction uses another or the whole collection. A query/body merge is a separate hypothesis from duplicates within one source.

**Falsifier / limit:** consistent use of one authorized identity throughout is not a vulnerability. Order-dependent response wording or a parser error is only a lead until delivery or final binding crosses the boundary.[2]

## JSON shape and field precedence

**Signal / mechanism:** the real schema exposes `email`, a nested account selector, or another delivery/recovery field. Scalar-to-array coercion, an unchecked alternate field, or differing field precedence may separate the lookup identity from the recipient.

**Comparison / control:** start with fields observed in browser JavaScript, a captured request, product/API documentation, or authorized source. Compare each meaningful field alone before conflicting A/B values; keep unknown-field rejection distinct from a used field. Duplicate JSON member names are another parser-differential hypothesis: an early parser may discard them before a later consumer sees them. Compare both orders without assuming either survives.

**Falsifier / limit:** ignored extras, rejected shapes, or consistently bound scalar values close those cases. A successful request with `backup_email` does not show that field influenced delivery. Do not infer mass assignment or ATO from acceptance alone.

## Mailbox grammar and encoded-word parsing

**Signal / mechanism:** the observed mail stack or source supports address comments, quoted local parts, encoded-word decoding, or domain-based identity decisions. PortSwigger's original research demonstrates application/mailer disagreements, including MIME Q-encoded whitespace (`=20` or `_`) and stack-specific decoding. Those cases concern email-domain/identity access controls; they do **not** prove a reset takeover on a new application.[3]

**Comparison / control:** identify the relevant library/configuration before adapting a disclosed vector. Use owned domains and inboxes only, with an ordinary address control; compare what the application treats as the identity/domain with the actual authorized delivery destination. MIME Q-encoding is not percent encoding, and `_` is not universally whitespace. If only domain verification is affected, route that primitive through ATO's identity-lifecycle lane; keep reset-delivery/token-binding checks here.

**Falsifier / limit:** decoding that preserves the intended mailbox, no supported decoder, or consistent rejection does not establish a parser exploit. Do not infer a mailer/version from one accepted character or send a crafted address through non-owned relay destinations. Broader email splitting, Unicode, and legacy routing research is not automatically applicable to this reset flow.[3]

## Learn from disclosures without cargo-culting

A post is a discovery lead, not target proof. Follow it to the original advisory, report, source/patch, or research; preserve author/date, affected stack/configuration where known, the differing consumers, an owned control, and the result that would falsify the hypothesis. Label unverified details explicitly. Extend this reference with a distinct mechanism, not every encoded spelling; public research never changes the live-testing boundary. No Twitter account, feed, or automation is configured by this guidance.

## Sources and applicability

[1] GitLab, January 11, 2024: CVE-2023-7028 advisory and FAQ. Historical affected versions and MFA qualifications, not a claim that current GitLab is vulnerable: https://about.gitlab.com/releases/2024/01/11/critical-security-release-gitlab-16-7-2-released/

[2] OWASP WSTG-INJT-04, HTTP Parameter Pollution: component discrepancies and single-value controls; duplicate handling alone is not impact: https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/04-HTTP_Parameter_Pollution/

[3] Gareth Heyes / PortSwigger, August 7, 2024, updated June 27, 2025, Splitting the email atom: original email-parser research and case studies, not universal password-reset payloads: https://portswigger.net/research/splitting-the-email-atom
