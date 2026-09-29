# Business Model and Issue Families

Use this focused reference after the `/business-logic` entry skill selects a concrete workflow. These are lenses, not a fixed checklist or permission to touch non-owned resources. Prefer combinations of normal actions and compare the resulting server-side effect with the business's intended invariant. `business-logic-modeling` owns the broader intent and owner-expectation interpretation; `impact-fit-policy` owns incremental attacker advantage and consequence, and specialist skills own the actual tests.

## Business-operation sketch

For the selected feature, keep a short non-secret model:

```text
Purpose and value delivered:
Actors and legitimate roles:
Artifact/value and its owner:
Normal path and state transitions:
Who can create / see / use / rotate / revoke / audit it:
Expected visibility to the owner:
Expected behavior after exit / cancellation / transfer / expiry:
Observed behavior versus asserted intent (with source):
Misuse hypothesis, benign explanation, owned discriminator:
Downstream effect and additional advantage (proven versus conditional):
```

Use documentation, ordinary UI, role definitions, observed backend state, and comparable owned accounts as distinct evidence sources. If they disagree, preserve the disagreement rather than quietly treating a UI promise or personal expectation as contract.

## Candidate families

- **Sequence and state:** skip, repeat, reverse, or resume steps; finalize before approval; reuse a terminal action after cancellation or expiration. Is the required predecessor state checked at the actual consumer? Route to `/assumption-testing` or `/access-control` workflow pack.
- **Actor and artifact relationship:** a role can operate on its own object but may not see another actor's existing secret, approve its own work, or act after membership changes. Distinguish creation authority, retrieval, possession, and downstream use. Route to `/access-control`, `/idor`, and owned account comparison.
- **Value and entitlement:** client-supplied price, quantity, coupon, credit, quota, plan, trial, or reward counters differ from trusted server calculations; value is granted twice or survives cancellation. Route to `payment-testing-policy` for financial effects and `race-live-policy` for concurrency.
- **Time and cross-feature composition:** a check occurs at issuance but not consumption; an export, integration, retry, background worker, bulk endpoint, or alternate client acts on stale state. Map the consumer and verify its owned effect rather than infer impact from an intermediate response.
- **Visibility and attribution:** owner notification, audit, approval, or creation records imply that a capability was never shared; a separate read path may quietly distribute an existing artifact. Verify what the owner can actually observe; absent UI evidence alone does not prove absent audit logs.

PortSwigger documents unexpected values, omitted inputs, workflow order, and inconsistent enforcement as logic-flaw patterns. OWASP WSTG emphasizes understanding the whole business process and its limits; OWASP's business-logic guidance distinguishes general role permission from contextual permission on this object in this state. Use these patterns to generate hypotheses, not to claim the application necessarily promised a specific rule.

## D16 interpretation lesson (sanitized)

An editor's permission to **mint** credentials was intended. That did not answer whether the editor could **retrieve an owner-created credential** without the owner reasonably knowing it was disclosed. The distinct hypothesis is hidden exposure of a different credential, not simply the editor's ability to create its own. An editor's departure may make retained possession more consequential, but does not itself prove that a program-scoped credential is revoked, or should be revoked. Separate retrieval, owner visibility, retained possession, downstream validity, and expected revocation into independently evidenced links. Do not put real credential values into notes or proofs.

## Further reading

- [OWASP WSTG — Introduction to Business Logic](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/10-Business_Logic/00-Introduction_to_Business_Logic)
- [OWASP Business Logic Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html)
- [PortSwigger Web Security Academy — Business logic vulnerabilities](https://portswigger.net/web-security/logic-flaws)
