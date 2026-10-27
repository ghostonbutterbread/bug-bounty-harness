# Bunny role dispatch

Use the current harness's native transport with the canonical role definitions
in this skill's `agents/` directory. A role is instructions and capabilities,
not a display label. Launch the selected specialist, not a generic `worker`
with a renamed task. Do not create a second set of role files per harness.
These role files implement collaborative mode. In explicit offhand mode use
ordinary scoped workers under `bunny-offhand`; do not launch these collaborative role files
or require those workers to load a Bunny mode skill.

## Resolve once per campaign

Resolve this skill's actual directory and the required policy/specialist skill
locations in the selected runtime. Record the transport, resolved role file,
worker ID, effective model/provider, and native session/result reference in the
existing campaign record. A missing runtime projection is an operational
request to the coordinator, not a reason for the hunter to rewrite its role.
Keep only selected skills in the packet; do not inject an entire skill library.

Custom children may have neither a skills catalog nor a skill-loading tool.
Give them readable resolved paths and tell them to read the role/mode and
selected skill bodies before acting. A catalog entry alone is not a loaded
skill. At initial acceptance, read back the native role identity and confirm
required skill access from the child's actual reads, not just its claimed name.
The normal authorization and model/approval gates in `bunny` still apply.

## Pi: select real named agents

Pi with `pi-subagents` discovers the four role files as `bunny-hunter`,
`bunny-recon`, `bunny-verifier`, and `bunny-reporter`. The package manifest next
to this skill exports `./agents`; install/register that local package using
Pi's supported package mechanism when deployment is intended. Do not install
another copy of the role definitions into each harness's agent directory.

For an invocation-scoped coordinator or isolated trial, resolve `BUNNY_DIR` to
this skill directory and include this environment variable when starting Pi:

```bash
PI_SUBAGENT_EXTRA_AGENT_DIRS="$BUNNY_DIR/agents" pi
```

This exposes the same canonical files without global configuration edits.
An already-running Pi parent does not acquire a new process environment; use
its supported package/discovery reload, or start an owned coordinator with
that environment. Do not restart unrelated sessions. Discover the installed
extension's available agents and confirm their resolved files before dispatch.

Use the role as the actual agent selector, for example:

```javascript
subagent({
  agent: "bunny-hunter",
  task: "<scoped packet with readable mode/policy paths and evidence references>",
  async: true,
  options: { agentScope: "user", context: "fresh" }
})
```

Use `bunny-recon`, `bunny-verifier`, or `bunny-reporter` for those responsibilities.
Use the runtime's actual per-worker model override when requested; do not
replace the selected provider/model through task text. Read back the native
result/status identity. If discovery fails, diagnose package registration,
scan roots, project trust, disabled overrides, or stale session discovery;
do not silently fall back to `worker`. Foreground blocking children cannot
ask their parent for a blocking decision; collaborative checkpoint work uses
an asynchronous child and the native supervisor reply channel.

When restricting a Pi coordinator's tools, remember that the `--tools`
allowlist replaces the whole selection, including extension tools. A read-only
parent still needs its coordination tools, for example
`--tools read,grep,find,ls,subagent,bg_wait,subagent_supervisor`.
Do not diagnose missing agent definitions when the parent simply cannot call
the installed extension. Excluding only `subagents_enable` keeps delegation
eager on runtimes that support it; it does not restore an allowlisted-out tool.

## Other harnesses: same role, native envelope

When a native named-agent selector is registered, select that role and verify
its effective definition. Otherwise use a general native subagent and include
the resolved role file plus the bounded packet, explicitly requiring the child
to read it first. In Hermes `delegate_task`, put the role and paths in `goal`
and `context`; a title is not a system-role override. Verify the child's reads
and behavior rather than claiming a named system profile was selected. Do not
use a narrow implementation persona as the fallback for autonomous hunting.

Reuse this role-and-packet contract across transports; do not invent a process
launcher or custom messaging bus when the harness already supplies one. For
an interactive CLI fallback, use Bunny's existing PTY, model, approval, and
Hoster ownership rules. Record unsupported steering/resume explicitly.

## Offline trials

Label synthetic program observations and fixture conclusions as synthetic.
Use isolated store roots and task-owned run/session directories. Real model
calls are allowed, but no real program requests, account creation, credentials
in packets, or writes to production evidence stores. Retain native transcripts
and verify roles, reads, calls, and artifacts; a model's final summary alone
does not prove that the pipeline ran. These trials establish workflow behavior,
not a live browser/login deployment or a real vulnerability finding.
