# Scope path normalization integration dossier

- **Status:** blocked; candidate is not approved for integration or activation
- **Owner:** BBH task `t_28a974bd`; parent owns integration and closure
- **Branch:** `fix/scope-path-normalization`
- **Worktree:** `/home/ryushe/worktrees/bbh-scope-path-normalization`
- **Fetched base:** `origin/beta` at `52252b96c6d6eb9ebd44f81b9646e6be3ab4214b`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-29
- **Owning feature branch/ref:** `fix/scope-path-normalization`
- **Latest prior immutable recovery checkpoint:** `d58ada77058f0044cfba44c88817ec3e1c27eed9` (initial candidate and dossier)
- **Feature implementation commit(s):** `f601c942fb6280f5b592b6f10eb140eb1d366231`
- **References:** PC-20261029-173518-a6033739; user-specified offline synthetic reproduction

## Intent and implemented candidate

Deny scope-path normalization bypasses without inventing authorization for a path-only allow. `ScopeValidator` historically used raw string prefix matches, ignored scheme and port, allowed a bare hostname to stand in for a URL path, and used the same URL matcher for allows and exclusions. Exclusions override matching allows. Domain/wildcard/IP/CIDR entries apply at host granularity. Consumers include `recon_ry.validate_start_scope`, `recon.bus.scope_violations`, FuzzAgent, XSS, and other callers; a Boolean validator is not an interception layer.

The branch candidate rejects ambiguous paths whenever a host-matching path restriction is relevant: percent signs at any encoding depth, dot/trailing-dot segments, repeated separators, backslashes, semicolons, whitespace, controls, non-ASCII, and colon-bearing targets for exclusions. Ambiguous excluded patterns deny that host; ambiguous allowed patterns do not match. URL excludes cover both schemes and all ports, are case-insensitive, include a directory without its final slash, and wildcard denies include the apex. URL allows require the declared scheme and effective port, a full URL even for origin roots, and a path boundary unless an explicit trailing `*` requests a prefix. Normal path-safe URLs and domain-only scopes remain usable. The strict error suggests checking scope and using an unambiguous full URL. `strict=False` remains warning-only.

Independent review blocked the earlier candidate because percent-encoded hosts and authority backslash/userinfo can be interpreted differently by common clients, bypassing host-specific exclusions; root URL allows also lost their scheme/port when matching bare hosts. The follow-up refuses ambiguous/malformed authorities before allow or deny comparisons, including percent, userinfo, non-ASCII, backslash before query/fragment, invalid/empty ports, control characters, alternate numeric IP forms, and malformed bracket syntax. Invalid exclusion authorities fail closed for **all** targets, since their true host cannot safely be inferred; invalid allows never grant. Equivalent IPv6 literals and DNS root labels are normalized before comparisons. Host-only grants remain host-only grants. These are intentional compatibility changes, not normalization into a new authorization.

This is a lexical candidate, not proof of arbitrary server, proxy, redirect, rewrite, alias, or client routing behavior. Normalizing an ambiguous target must not be used to infer permission. Rejecting all percent-encoded paths and several other valid spellings with path restrictions is an intentional compatibility cost requiring independent review. Existing URL-only allows for other schemes/ports and bare hosts are intentionally narrowed.

## Evidence and review

- TDD: `test_dot_segment_cannot_bypass_exclusion` failed against base (True instead of False), then passed. Additional RED/GREEN cycles covered controls, Unicode/whitespace, suffix dot/colon, scheme/port, and wildcard/root-label exclusions.
- Offline pytest using the beta checkout's `.venv/bin/python`, `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, with Python socket `connect`/`connect_ex` patched to raise: `agents/test_scope_path_normalization.py agents/test_scope_validator.py tests/test_scope_host_normalization.py`: **151 passed, 10 subtests passed**. New fixtures use reserved `example.test` and temporary scope roots; no target requests.
- Same network-blocked runner: `agents/test_recon_ry.py -k 'not remote and not queue and not auth'`: **21 passed, 42 deselected**. A new test exercises real `validate_start_scope` and `recon.bus.scope_violations` with the actual validator and synthetic saved scope.
- `python -m compileall -q` on changed Python files and `git diff --check` passed. Validator imported from this worktree. Test environment's Bounty Core direct-url commit matches `requirements.txt` pin `6c36ee88a60073e1b687ec32deeade24ffafdd4f`.
- Stable topology: `origin/master` is an ancestor of beta and contains the same raw `target_path.startswith(pattern_path)` matching; stable impact/lowest-ancestor ownership requires parent decision. No stable or descendant propagation performed; explicit task requires feature from beta and no integration.
- **Independent review:** earlier candidate BLOCKED on the authority and root-origin cases above. Fresh independent re-review of the *new branch tip* is mandatory; passing tests do not approve it. Review must inspect the full diff and dossier, reproduce the encoded-host and backslash cases against clients without network, challenge malformed allow/deny handling and IPv6 equivalence, rerun the offline suites, and examine compatibility and remaining parser mismatches. Parent owns dispatch and release decision.
- Follow-up RED: targeted new tests produced 5 expected failures for encoded authority, authority backslash, ambiguous exclusion, and two root origin allows; further RED cycles produced 2 failures for empty port/IPv6 exclusion, 2 for root-label wildcard/malformed bare exclusion, and 2 for outer controls. Follow-up GREEN with sockets and DNS blocked in-process: `agents/test_scope_path_normalization.py agents/test_scope_validator.py tests/test_scope_host_normalization.py` **171 passed, 10 subtests passed**; `agents/test_recon_ry.py -k 'not remote and not queue and not auth'` **21 passed, 42 deselected**. The real synthetic start-guard/bus fixture now covers normal, dot-segment, encoded-host, authority-backslash, and empty-port URLs. The review transcript truncates/redacts the original backslash fixture, so the regression uses an equivalent synthetic backslash-before-@ case, not a claim to reproduce every byte of that fixture. Source imports resolved to this worktree; installed bounty-core pin still matched the manifest. No target requests, external network, push, integration, or deployment. Fetch deliberately deferred because this task prohibits network; re-fetch/reconcile before any later integration.

### Residual parser/transport limits

This is a conservative lexical boundary, **not** a proof of behavior for every URL parser, proxy, DNS resolver, upstream redirect, application rewrite, host alias, transport or TLS authority. Other clients may normalize additional forms, interpret a validated value differently, follow redirects, override Host/SNI, or resolve an allowed hostname to an unintended endpoint. `is_out_of_scope` treats an invalid target as excluded when an exclusion is present, but is not a standalone allow decision. Tool annotations are stripped by the existing shared contract; the consumer must send exactly the checked value. Host-only grants still authorize any path/origin on that host except separately enforced exclusions; URL-only root grants no longer authorize bare hosts. Independently verify each actual consumer's input interpretation, redirects and every resulting request, or fail closed; `strict=False` only warns. In-process socket/DNS blocking in tests is not a sandbox for subprocesses; these test selections are offline and no subprocess network action was requested.

## Blocker: consumer cannot enforce the path deny

`agents/scope_seed_files.py:160-196` explicitly defers path-scoped URL entries because Recon-Ry's scope files are host-only. `agents/recon_ry.py:303-304` discards deferred exclusion entries while producing remote scope files. An offline synthetic saved scope containing `*.example.test` and excluded `https://api.example.test/private/` produced only `_scope/in-scope-hosts.txt` containing `*.example.test`, no out-of-scope file, and `recon_scope_file_lines` returned `([], ['https://api.example.test/private'])`. The start guard only checks the seed; it cannot prove every URL requested by downstream recon/crawlers or redirects remains outside the excluded path. This candidate therefore does not establish a safe end-to-end general contract; **do not integrate or activate as a complete fix**.

- **Missing evidence:** independently verified enforcement of path exclusions for every request, including redirects and downstream consumers, or a deliberate fail-closed policy that excludes affected hosts/runs. Any lexical allow also cannot by itself prove arbitrary application rewrites.
- **Command/fixture:** retain the synthetic saved-scope fixture described above; write an offline regression exercising the actual launch and effective downstream request/redirect gate without traffic. A host-only format cannot encode a path deny.
- **Trigger:** parent selects an authorized consumer-level remediation and coordinates with Recon-Ry ownership per `AGENTS.md`; rerun validator and consumer tests plus independent review.
- **Why it blocks:** otherwise a valid public seed can launch a host-scoped crawler whose generated scope omits the path exclusion.
- **Next step:** parent decide whether to refuse such runs, conservatively exclude entire affected hosts, or implement and verify a real request-level path guard in the owning Recon-Ry tool; do not silently widen authorization.

## Resume and decision gates

- **Owning branch:** `fix/scope-path-normalization`; recover via its committed branch tip.
- **Exact resume point:** parent requests fresh independent review of the current committed tip, addresses any new findings, separately resolves the Recon-Ry consumer blocker above, reruns offline regressions, decides stable ancestor propagation, and compares to freshly fetched `origin/beta` before any integration.
- **Integration gate:** blocked by missing consumer enforcement and independent review.
- **Activation/promotion:** not authorized; no activation or stable promotion performed.
- **Decision:** 2026-10-29 — retained blocked candidate and consumer finding for parent; no complete general safety claim.
