# Bunny role-native pipeline

Status: stages 1–4 passed; final proof-to-report gate prepared; not released.
Owner: Hermes / Kanban bug-bounty-harness t_8db7e67e.
Source: Discord thread 1564434386651193377; implementation authorization 1564454258743582820; fresh Hoster trial approval 1564460993071816745.
Inspiration: user's MAPTA diagram; adapt operational coordination, not a new evidence store.

## Branch and scope

- Feature: `feat/bunny-pipeline`, worktree `/home/ryushe/worktrees/bbh-bunny-pipeline`.
- Base: `9e0702536791c49d38e9b5cc48442dea91e613ee` (fetched origin/beta).
- Intended integration target: `beta`, not main.
- Owners: `skills/bunny/` canonical role definitions and `bunny-collaborative` behavior.
- No live target traffic, real account creation, external submission, global provider changes, or unattended scheduler in these trials. Fixtures and isolated store records are explicitly synthetic.
- Hoster raw run: `/home/ryushe/.hermes/cache/scratch/bunny-stage1-20261027T015526Z-dd31e4/`.
- Durable local evidence: `/home/ryushe/.hermes/state/validation/bunny-pipeline/`.

## Incremental gates

1. Actual native canonical recon/hunter/verifier/reporter identities, required skill reads, effective route, and terminal process states. Portable fallback is defined using the same role files; untested harnesses remain untested.
2. Recon writes through the existing MapStore into an isolated fixture root; hunter retrieves the exact reference and acknowledges pickup. Missing pointers fail before acknowledgment; no parent evidence transcription.
3. Coordinator resolves a synthetic operational prerequisite and conflicting ownership; unrelated work can proceed. Worker continues investigative work, not provisioning.
4. Native follow-up/resume preserves investigator lineage and evidence. Blunt pushback reaches that investigator; harness deadlines and process/provider failures are distinguished from voluntary completion.
5. Independent verifier reconstructs an actual local-fixture candidate, including a negative control. Reporter gates require owner evidence and verified proof; no real finding or external submission.

Each behavior gate uses real model calls and native transport on a synthetic local program. Repair and rerun failed gates before admitting the next. Structural tests, behavioral evidence, and runtime activation are separate receipts.

## Implemented behavior and tests

- Pi package exports the four canonical role files; `advertise: true` enables native discovery. No alternate role copies per harness.
- Native role/skill dispatch reference is linked from the router and collaborative mode. Restricted Pi parents must preserve extension coordination tools in their `--tools` allowlist.
- Explicit offhand mode remains ordinary scoped workers; collaborative role files must not silently change that mode.
- Store handoffs use existing canonical owners, exact pointer envelopes, and recipient read-before-ACK. Native peer messaging is conditional; a coordinator may forward the envelope without reauthoring evidence.
- Focused source tests: 22 passed after test-first REDs for discovery, dispatch, offhand isolation, tool selection, pointer pickup, async dependency barriers, operational ownership, investigative acceptance, continuity, and terse blunt challenges.
- Latest broad run: 373 passed, 1 skipped, 3 failed, with 196 subtests passed. All three failures reproduced on unchanged base using the same interpreter: stack-to-program index missing Outputs/Mutates; direct-checkout example rejected by lane-safety; upload-surface expects obsolete wording. No unrelated source was repaired or excluded-and-called-green.
- Feature `.venv` installed via repository setup; Bounty Core resolved through that environment.

## Stage 1 receipts

- Historical preapproval preparation: `deleg_c90a48b7` staged nothing and launched nothing because approval expired. Its receipt is historical, not a behavioral pass. Fresh approval above preceded all remote staging.
- Attempt 01: actual parent/model/skill reads succeeded, but read-only CLI tool selection excluded all extension tools. Zero children; parent refused generic substitution. Stopped only its task-owned unit and read back inactive/dead.
- Attempt 02 candidate: `d9bb19ee1c6e8207289d97d2198db853259b407e`. Separate immutable snapshot; uploaded archive and controller hashes matched remote read-back.
- Actual native children: recon `1cba8864-cf93-44a1-ba46-7773f1d9759d`; hunter `e13c7615-fae7-4f8d-8c1b-ec5d5b9539ba`; verifier `bb4249f2-dc0f-402b-ba1c-6717e7d5c253`; reporter `718cacdd-4929-44c9-8412-6f694dcdc231`.
- Independently parsed child session records: all four native identities complete; each has successful reads of its own canonical role, collaborative skill, and fixture; one successful native supervisor checkpoint; no shell/write calls. Actual model-change events record `zai/glm-5.3-flash`, thinking max. All four runners have observed exit code 0 and resumable disposition. Reporter correctly withheld a report with absent proof.
- Parent made four schema-invalid `get` calls (`agent` wrongly nested in options), then corrected to the top-level field before launching; all retained in raw RPC events. No failed launch or role substitution.
- Verified receipt: `/home/ryushe/.hermes/state/validation/bunny-pipeline/stage1-dd31e4/verified-receipt.json`; raw attempts 01/02 copied beside it. Verification script remains in the run scratch directory.
- Hoster unit `hoster-bunny-stage1-dd31e4-02.service` read back inactive/dead, Result=success, empty ControlGroup. No task tunnel or live-pane change.

## Stage 2 result and Stage 3 next step

Candidate `cc8e403951a54b93b56f77b52ec39b05c40a3bd0` adds pointer pickup. Actual Pi coordinator dispatched through `hoster-bunny-stage2-dd31e4.service` under `/user.slice`, with bounded memory and separate `attempt-stage2/` sessions. Snapshot archive SHA-256: `39508f0ab62bbc43ee0efbb87a39b5b0fcf2b839fcdac9b21dafa1808a518c5e`, matched remotely. The fixture uses the existing Hoster MapStore CLI/environment, not a replacement store implementation. Preflight `resolve_storage(..., root_override=.../stage2-store, create=False)` resolved every path into explicit-local fixture storage.

Next: Stage2 attempt `attempt-stage2` failed pickup, not publication: recon's actual MapStore write/read-back and nonblocking supervisor update succeeded, while the hunter correctly refused to ACK a missing path and remained in `need_decision`. The coordinator selected an async parallel workflow, whose aggregate completion was held by the waiting hunter; it waited for a producer notification instead of draining the queued producer pointer. One schema-invalid parallel packet (`options` nested in tasks) preceded its corrected launch. Stop/read-back: task unit inactive/dead, Result=success, empty ControlGroup; no unrelated process touched. Raw attempt and isolated store copied to durable local evidence. The disposable collector also counted composite lifecycle status files as children; its rerun deduplicates actual session files. Repair: individual async runs for dependent role handoffs, exact native supervisor reply, and pending checks at attention/completion; retain composite workflows for independent leaves. Rerun with separate snapshot, session, and store roots (`snapshot-stage2b`, `attempt-stage2b`, `stage2b-store`). Stage3 remains unadmitted.

Hermes fallback acceptance `deleg_46588160` completed read-only: transcript confirms successful canonical hunter/mode and fixture reads and no mutation. It explicitly identifies general-child role loading, not a native named-role selector; inherited model route was not independently verified. Trace: `/home/ryushe/.hermes/cache/delegation/live/deleg_46588160/task-0.log`.

Stage2b passed at `641fa5fd3b517599b1e7a53bc04b6f1f68300f50`. Independent parser receipt: `/home/ryushe/.hermes/state/validation/bunny-pipeline/stage2-verified-receipt.json`. Exactly one MapStore index row; producer recon `49221382-93be-4596-8b70-0f25685bb9b4` wrote/read back; hunter `01efa5be-d310-4ca0-a3f7-3badf002d83e` failed the missing-pointer read, awaited the exact native supervisor reply, read the corrected record, then ACKed and retrieved the marker that was absent from notifications. Both canonical roles complete, runner exit 0; parent made no shell/write calls. Recon first misplaced `--root` before `write`; argparse rejected it without a write, then corrected invocation wrote once. The negative missing-pointer error was expected. Task unit read back inactive/dead, Result=success, empty ControlGroup.

Two trial lessons are addressed before continuation: evidence authorship is not the hunter's surface lease (the hunter's final prose conflated them), and Pi's inferred coding acceptance added irrelevant Git/changed-files reports to investigative roles. Source now separates those owners and permits non-coding acceptance criteria without disabling actual verification gates.

Stage3 passed at `85b811390b1d1e750b841818676308ec0fcaee5c`; receipt `/home/ryushe/.hermes/state/validation/bunny-pipeline/stage3/verified-receipt.json`. Same coordinator session prefix verified; original hunter `01efa5be-d310-4ca0-a3f7-3badf002d83e` natively resumed as `86982c13-4451-454a-ad3f-a869fa4595ad` (new process/run, retained investigator and session). Independent recon `7169190b-b062-42e6-a278-d7fab346760e` completed before prerequisite release. Parent wrote/read back only the two admitted operational files; the protected busy fixture's SHA-256 remained `daba420df79d2604c8093a5a6d255e7d979e8d0334037cefc842335772d80c5f`. Hunter read the allocated binding before ACK; both roles read-only, complete, exit 0, and no coding acceptance-report block. Ownership distinction corrected. Unit inactive/dead, Result=success. This proves local-file operational coordination, not actual browser provisioning or login.

Stage4 attempt at `5f4fc6b4bdd4ec0e34b8edfaac847b7804dec5dc` is **partial, not passed**: native resume, three live replies consumed in one process, three investigator-chosen discriminators, honest no-finding, read-only calls and exit 0 independently checked. However, all three steers appended unwanted motivational qualification paragraphs. Receipt `/home/ryushe/.hermes/state/validation/bunny-pipeline/stage4/verified-receipt.json`. Source repair keeps the challenge terse and the motivational/evidence distinction internal, not repeated in every steer. Stage4b replays that scenario against the repair, retaining the latest investigator; prior unexecuted lenses may be reused, so this is not additional security coverage. Stage5 remains unadmitted. Stage4b was blocked before dispatch because the test harness transcribed a nonexistent MapStore path; the coordinator correctly refused to spawn or fabricate replacement evidence. No child launched. Stage4c binds the packet directly to Stage2's verified producer receipt and checks the original observation digest, preserving that evidence owner. This is a harness repair, not a new application observation.

Stage4c passed: receipt `/home/ryushe/.hermes/state/validation/bunny-pipeline/stage4c/verified-receipt.json`; retained hunter resumed as `f5ac4ebf-d94c-4864-b3eb-3cea9883a57c`, one process, three actual native replies consumed, no motivational-disclaimer paragraphs, honest no-finding and no real Coverage verdict. Two recovered invocation/read mistakes remain in the receipt; a rejected resume submission did not create another child, and the malformed mode-file path was corrected before reasoning continued. This is not forced-timeout recovery or a live target test.

Stage5 admits an intentionally vulnerable owned pure-function fixture, not a deployed service. Retained primary will write real observed proof through canonical Attempts, a fresh verifier must distinguish the candidate from a protected control, the finding owner must populate EVIDENCE.md, then a fresh canonical reporter loads the standalone skill and writes one exclusively created, clearly fixture-limited FID report. No live targets, accounts or production evidence stores. Source skill/test bytes remain identical to independently reviewed `d57e96fcf753824fdbc9671d8aac1176f37b7f70`; only dossier status changes afterward. Final acceptance and independent behavioral audit remain pending.

## Alignment and release boundary

Read `AGENTS.md`, `agents/index.md`, `SCRIPT_POLICY.md`, Bunny router/modes, and owning coding/coordination/branch policies. No change to remote-pi cross-campaign peer policy, testing authority, aggregate rates, approvals, or global model routing. Parent-child envelopes do not grant peer broadcast permission.

Independent source review passed at `d57e96fcf753824fdbc9671d8aac1176f37b7f70` (22 focused tests independently rerun; no blockers). Durable receipt: `/home/ryushe/.hermes/state/validation/bunny-pipeline/review/source-review.json`. This is not release approval: final proof/report acceptance, independent behavioral audit, beta integration and production runtime projection remain pending. Existing consumer projections remain untouched. Feature checkpoints: package `990e76214b4f43707111486766140270231966e3`, initial dispatch `e686d3139f9c16e167664fe227c4ec9857056810`, restricted-parent repair `d9bb19ee1c6e8207289d97d2198db853259b407e`, pointer handoff `cc8e403951a54b93b56f77b52ec39b05c40a3bd0`. Later dossier-only checkpoints may follow.
