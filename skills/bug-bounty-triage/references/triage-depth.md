# Triage depth checklist (upstream-derived)

Load only when a confirmed finding has a concrete unresolved impact or reproduction question. This is a *decision aid*, not a payload list or authorization to run tests. Program rules, `live-testing-policy`, ownership, and the specialist class policy control each probe. A reporting-only worker writes the question for the finding owner instead.

## Evidence and reproduction audit

- Is the role, tenant, plan, feature location, build/version (when material), object lifecycle, and necessary account state explicit?
- For each target-specific value, is there a safe, repeatable way for the reviewer to derive it from their own account? Never copy a researcher credential, cookie, session token, verification code, unrelated ID, or another user's data to make an example runnable.
- Does a custom callback/listener have a minimal runnable setup, expected startup signal, network reachability, and decisive receipt? An unspecified "configure listener" step is incomplete.
- Does each decisive action show its relevant request and observation beside the step, then an independent verification of effect? A status code or reflection alone supports only its narrower observation.
- Is the secure expected result contrasted with actual behavior using an owned negative control? Are all side effects and cleanup accounted for?
- Would the report stand on its own without access to local paths or internal reports? Does it avoid repeated tutorial prose without omitting a non-obvious product-specific step?

## Material escalation questions

For each class, first state the **changed security boundary**, required access, smallest controlled proof, likely side effects, and stop condition. Only proceed when this changes the claim materially and the class policy permits the specific action.

- **BOLA/IDOR:** controlled object read versus allowed write; another owned role or tenant; persistence after relationship removal. Use two owned fixtures and test only role/tenant boundaries the operator can control. Do not guess admin IDs or browse third-party records.
- **XSS:** rendering across contexts or persistence; victim interaction; whether a controlled privileged action can actually occur. A script firing is not session exfiltration, admin execution, or enduring account takeover.
- **SSRF:** whether the server fetched an owned external callback and whether a different trust boundary is plausibly reachable. Internal addresses, metadata endpoints, file schemes, or credential exposure require the dedicated SSRF policy and a bounded safe proof; not a default checklist.
- **SQLi:** prove query influence with bounded non-sensitive data; ask whether broader data reach is possible without dumping or modifying non-owned data. File writes, stacked mutations, and command execution are not automatic follow-ups.
- **Auth/role/OAuth:** test only owned low/high-role fixtures; clarify whether the user must navigate/login, whether MFA is actually bypassed, and whether access persists after revocation. Do not call an observed login redirect silent takeover.
- **Open redirect:** identify an actual security-relevant integration and controlled victim/user condition. The redirect alone does not prove token theft or ATO.
- **Upload:** distinguish accepted bytes, stored object, and later execution/rendering. Do not upload a web shell or destructive payload merely to seek higher severity.
- **Race/payment:** require the relevant race/payment live policy and controlled metered-effect boundary; a double-spend claim needs independently verified balance/entitlement effect, not duplicate HTTP responses.

Classify each result as **verified**, **supported inference**, or **untested**. Escalate only with proof; do not inflate scope, CVSS metrics, business harm, or payout from generic examples. When further validation needs out-of-scope identity, third-party data, internal infrastructure, destructive action, or unavailable permission, stop and retain the narrower proven claim.

## Recipient-only audit

Read only the prepared `SUBMISSION.md` as a triager. Confirm title and summary lead with the strongest demonstrated non-subsumed impact; each claim maps to source evidence; prerequisites explain how to derive values; the PoC and flag usage match the actual artifact; all cross-origin requests have full URLs; no internal commentary or credentials leak; and the smallest remediation addresses the demonstrated failed boundary. Internal verdict, untested alternatives, and uncertainty about future research remain in `EVIDENCE.md`/rough `REPORT.md`, not in a polished submission.
