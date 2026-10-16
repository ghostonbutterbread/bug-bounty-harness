# RCE Precondition Matrix

Complete this before calling a candidate confirmed or reporting severity. Empty
cells are unknowns, not favorable assumptions.

| Dimension | Evidence to retain |
|---|---|
| Attacker control | Exact input, ownership/auth state, whether control is direct, stored, async, or automatic |
| Transformation chain | Decode/canonicalize/rewrite steps, content sniffing, validators, persistence, queues, retries, consumers |
| Sink semantics | Parser/interpreter/process API, shell versus direct invocation, template data versus source, type policy, feature flags |
| Environment | Product/component, exact version, runtime, package type, container, deployment topology, extension/plugin state |
| Execution context | Process/worker identity, permissions, sandbox/container, filesystem and egress boundary |
| Reachability | Endpoint/message/file path, trigger conditions, authentication/role, timing/worker availability |
| Mitigations | Fixed version, configuration, allowlist, isolation, disablement, vendor workaround, compensating controls |
| Proof | Baseline, negative control, controlled effect, correlation, alternative explanations ruled out, cleanup |
| Novelty | Advisory/CVE status, exact affected range, duplicate check, target-specific deviation from known issue |

## Confidence labels

- **Suspected:** input and a plausible sink are mapped, but reachability is not demonstrated.
- **Reachable risky mechanism:** evidence shows the relevant parser/interpreter/API is reached; no controlled effect yet.
- **Controlled application effect:** a safe controlled signal crosses the proposed boundary with a negative control.
- **Confirmed bounded impact:** execution or comparable capability is evidenced in the actual context, privilege and preconditions are known, and the proof stayed within the approved boundary.

Never upgrade a label from a CVE match, scanner output, parser error, reflection,
or package fingerprint alone.
