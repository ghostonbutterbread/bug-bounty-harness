# Public 403 Resources

Use this index only after the `403` skill's ownership, scope, baseline, and
lane-selection gates. These are research and candidate-generation sources, not
authorization to send every variation or execute third-party code.

## Selection Rule

1. Start with the local lane pack: path normalization, trusted headers, or auth
   state.
2. Choose one source that adds an untested family; do not use several tools that
   duplicate the same permutations.
3. Transcribe or review the minimum relevant candidates into the approved
   request path or local harness. Never run a downloaded tool against a live
   target without inspecting its request behavior, honoring program rate rules,
   and recording the attempt.
4. Treat a response-code or body-length change only as a lead. Confirm protected
   route reachability or an authorization delta on an approved resource.

## Primary Methodology and Review Sources

- **PortSwigger/403-bypasser** —
  <https://github.com/PortSwigger/403-bypasser>. Public BApp source that
  demonstrates path-position permutation behavior and header-payload insertion;
  inspect its implementation and payload lists locally before relying on a
  behavior claim.
- **Arcanum-Sec hack_tips: 403bypass** —
  <https://github.com/Arcanum-Sec/hack_tips/blob/main/403bypass.md>. Broad
  manual checklist. Treat individual entries as hypotheses and classify them
  into the local route, header, or auth lanes before testing.

## Candidate-Generation Tools — Inspect Before Use

- **iamj0ker/bypass-403** — <https://github.com/iamj0ker/bypass-403>. Large
  established script collection; use it only as a reviewed source of candidate
  families, not as a blanket live scanner.
- **devploit/nomore403** — <https://github.com/devploit/nomore403>. 401/403
  response-differential tool; review request count, redirects, headers, and
  concurrency before any approved use.
- **gotr00t0day/forbiddenpass** —
  <https://github.com/gotr00t0day/forbiddenpass>. Alternative candidate
  generator; compare its coverage with the selected local pack to avoid
  duplicate traffic.
- **slicingmelon/gobypass403** —
  <https://github.com/slicingmelon/gobypass403>. Focuses on 401/403 and URL
  parser/WAF variants. If a WAF or challenge is observed, route through `/waf`
  and the HTTP-status policy before considering it.
- **LocaMartin/403** — <https://github.com/LocaMartin/403>. Small Node CLI
  advertising path, header, IP-context, method, encoding, and proxy variants;
  treat its low-maintenance surface as a review-only source unless separately
  vetted.

## Supporting Corpora

- **SecLists** — <https://github.com/danielmiessler/SecLists>. General security
  testing lists; use only a relevant, bounded subset after program rules permit
  content discovery or request variation.
- **Assetnote Commonspeak2 wordlists** —
  <https://github.com/assetnote/commonspeak2-wordlists>. Generated wordlists;
  use only where discovery is in scope and a focused list is justified.

## Exclusions and Routing

- Do not treat tools as authoritative vulnerability proof, or infer a bypass
  from a `200`, body-length change, soft redirect, cache artifact, or public
  page.
- JWT, bearer-token, signature, claim, or key behavior belongs to `/jwt-auth`.
- Object, tenant, or role comparisons belong to `/idor` or `/access-control`.
- WAF, bot challenges, or rate limits are not 403-bypass evidence; route to
  `/waf` and the HTTP-status policy.
- Do not download, install, or execute code from this index automatically.

## Refresh Procedure

Use `safe-fetch` for external content. On refresh, verify that each URL
resolves, record repository activity and license separately when deciding
whether to promote a tool, remove dead links, and keep only sources that add a
distinct technique, methodology, or corpus. Search public GitHub for `403
bypass` and public vendor resources for `403 forbidden`, then deduplicate
against this index.
