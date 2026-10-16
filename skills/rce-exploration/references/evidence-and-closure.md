# Evidence and Closure

## Attempt record

Record: authorization/scope; owned resource; input/control field; baseline;
transformation and candidate sink; execution identity/context; each bounded
mutation and reason; response/job/callback observation; inert negative control;
preconditions; cleanup; and closure or escalation reason.

## False-positive checklist

Before reporting RCE, rule out: client-side rendering; reflection; generic error
handling; WAF/CDN block page; cache/retry/background timing; parser reachability
without interpreter semantics; operator-only configuration; dependency version
without environment match; and a known advisory without a target-specific
precondition match.

## Remediation framing

Prefer removing the interpreter boundary. When it must remain, recommend the
control matching the path: structured process APIs and validated arguments;
template data binding rather than source construction; type allowlists and safe
formats; strict content validation plus non-executable storage; current vendor
fixed version/workaround; least privilege, sandboxing, and egress restriction.

## Closure states

- **Cold:** no evidenced sink/control after the mapped test sequence.
- **Blocked:** a prerequisite is missing or authorization prevents safe proof;
  state the required approval/evidence needed.
- **Known exposure:** advisory match is plausible but environment/preconditions
  are unresolved; hand off an exposure-triage record, not an RCE claim.
- **Confirmed:** bounded proof, context, negative control, and cleanup record
  are complete; follow the finding/report process.
