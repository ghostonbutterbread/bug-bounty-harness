# BBH Agent Entry Card

For a BBH skill being authored or migrated that runs a repository-owned script,
use `bbh <repository-relative-script-path> ...`—for example,
`bbh agents/manual_hunter.py ...`. Do not add a checkout path or a
`HARNESS_ROOT` fallback: `bbh` resolves its own installed symlink and does not
accept a repository-root override. This makes the command run from the selected
beta or stable checkout. Direct Python commands are legacy and must be migrated
before use. See [`docs/bbh-launcher.md`](../docs/bbh-launcher.md) when authoring
or changing a runnable BBH skill command.

Use this as the compact runtime entry point for a Bug Bounty Harness agent.

For public, paid-program selection **before** an authorized target is chosen,
load `/program-finder`. A shortlist is not testing permission: once a program
is selected, the normal published scope and AI Policies gates below still apply.

1. Before any live action, load `general-security-testing-policy`, then
   `live-testing-policy`. Also load `resource-safety-policy` for every agent
   task: it governs local artifact search and processing, including when a
   broad corpus is legitimate but must be scanned with bounded, streaming
   methods. Load only the minimum ordered live-testing overlay(s) required for
   the next decision. Before running a bug-bounty script to investigate a
   target, load `/bb-script-rules` alongside the relevant BBH skill; find
   runnable scripts in that skill and its index. Before assigning or writing
   a helper, load `/script-manager` and use `SCRIPT_POLICY.md`'s short
   reuse/extend/new decision when assigning a specific script job. For
   exploratory packets without known tooling, have the worker make that
   decision when scripting becomes useful, before creating or promoting a
   helper. Program-only maintained helpers are indexed in the resolved program
   lane, not the BBH launcher.
   Load `/data-store-guidance` early, before choosing persistent reads or writes;
   it is the store-ownership map: what each store holds and its owning skill.
2. Authority order is published program rules and scope → AI Policies → BBH
   runtime mechanics. BBH does not override scope, account, rate, or impact
   decisions.
3. Begin from the current user goal and a selected current surface. At a
   concrete URL, feature, or component, use a bounded MapStore Application
   Behavior query as an optional orientation map rather than rediscovering
   known input-to-consumer edges from scratch. Verify relevant edges live and
   explore beyond the map; absence means unknown, not safe. Do not preload
   broad prior leads, findings, or peer theory queues. For a live application
   hunt, consult `/live-map` for class-neutral browser/proxy and source/stack
   understanding of the relevant flow; use each view to inform the next. Do not
   wait for a complete map before following a strong lead, and keep explicitly
   offline work offline. When a current hunt needs to understand relevant JS,
   load `/js` and its `references/analysis-lens.md`; this analyzes the current
   question without starting a standalone JS campaign. The live-map runtime
   route map is distinct from MapStore's named, factual
   Application Behaviors; create/update a Behavior only from concrete URL
   observations through `/map-store`. Keep class-specific testing and lineage
   with the specialist lane.
4. Use `/hunter-loop` only for bounded orchestration; route each plausible
   selected surface to one specialist lane. When no signal exists, run an
   adaptive, class-appropriate live discovery sequence to establish or reject
   it; signal controls escalation severity, not permission to test.
   For a server-side execution question load `/rce` as the class entry; it
   routes mapping, primitive exploration, later consumers, stack research, and
   bounded validation. For a solo primary hunter needing distinct sidecars,
   load `hunt-orchestration-policy` for admission and `/hunt-orchestration` for
   BBH evidence and handoff mechanics; Bunny remains opt-in.
   For any potentially destructive proof, prefer a recreated, task-owned
   disposable local Docker/VM instance, preserve evidence, then remove and
   verify only its resources. Isolation does not authorize live impact; if a
   safe local reproduction is unavailable, stop and name the blocker.
   For an observed open-source component, version, and reachable feature, load
   `/vulnerability-patch-research` for concurrent CVE/diff research and its
   detailed disposable-local-proof reference.
5. `/data-store-guidance` describes store purposes; operational details stay with
   each store's owning skill.
6. For shared evidence, storage, projections, or secret-reference work, read
   `docs/bounty-core-evidence-and-secrets-workstream.md`: Bounty Core owns
   generic primitives; BBH modules own their domain semantics; raw evidence has
   one canonical source and projections are regenerated.
   If an agent observes an unsafe action, stop and contain it first; explicitly
   record a factual, non-secret incident with
   `bbh scripts/safety_incident.py --program <program> --lane <lane> --profile <absolute-path-to-context/target_profile.json> record --producer <producer> --run-id <run-id> --category <category> --severity <unknown|low|medium|high|critical> --action <action> --subject <subject> --impact <impact> --containment <containment>`.
   Add `--no-notify` to persist without delivery. This is agent reporting, not
   automatic interception or comprehensive coverage; see
   [`docs/bbh-launcher.md`](../docs/bbh-launcher.md).
7. Include the selected policy chain, one BBH lane, evidence pointers, exact
   stop condition, and account/browser lane only when required in every child
   packet. After recording a proven FID, resolve the frozen `report_dir` from
   the ledger (`reports/<FID>-<initial-vulnerability-slug>/` for new findings,
   with `reports/<FID>/` still valid for historical packets). Fill its
   `EVIDENCE.md`; load `impact-escalation` and its available matching class
   overlay to investigate material application-impact chains under the live
   policy chain, then reconcile verified effects into that same FID and
   evidence packet. A missing overlay does not invent impact or delay the
   initial capture. Load the standalone `bunny-report-and-triage` skill
   directly for the one FID-named final report. If it is unavailable, stop
   rather than using a deprecated BBH writer or inventing another final file.
   After independent review, register the existing final path with `agents/finding_report.py`;
   registration does not submit. Do not generate a rough `REPORT.md` or a
   competing `SUBMISSION.md` for new findings. Preserve
   older packet files and every unrequested region in a targeted revision. PoC
   creation follows `poc-tooling-policy`. Standalone or scripted PoC editing follows `triager-first-poc-authoring`;
   a simple inline `curl` does not load that authoring skill. Live execution
   remains governed by the policy chain above.
   When security testing needs a browser, use `/chromium-test` and request it
   through `browser_provisioner.py` on the browser node. Its default `--proxy
   mitm` starts a task-owned listener, imports its CA before Chrome starts, and
   gives the agent its own traffic; release the browser, then finish the task
   proxy after any direct replay. Do not launch `chromium_test.py` directly or
   silently fall back to Caido/shared 8080. Ordinary, non-security web browsing
   uses Hermes's managed browser provider without this provisioner or MITM.
8. Do not use remote-pi peer coordination by default. Use the owning
    provisioner directly (including browser provisioning), without peer lookup
    or broadcast. Only if the operator explicitly asks you to contact another
    agent, first load `pi-cordinator`; then load upstream `agent-network` for
    transport before `/remote-pi`, `list_peers`, inbox/replies, or `agent_send`.
    Keep that exchange resource-only and never disclose the vulnerability.

See the selected skill for commands, evidence requirements, and runner details.
