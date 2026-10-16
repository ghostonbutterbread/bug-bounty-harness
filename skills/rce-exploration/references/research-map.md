# RCE Research Map

This is a curated, source-backed map rather than an attempt to catalogue the
entire web. Read public cases to improve hypothesis formation, then rebuild the
chain from target-specific evidence; a public exploit is never proof that a
separate target is vulnerable.

## Canonical technique references

- **Command construction.** OWASP distinguishes command injection from code
  injection and emphasizes unsafe user input reaching a system shell; first
  establish the command-building and privilege context.[1] PortSwigger's topic
  coverage separately treats visible and blind command-injection behavior,
  reinforcing the need for signal-appropriate validation rather than response
  reflection alone.[3]
- **Deserialization.** OWASP's cheat sheet organizes review around language and
  format-specific deserialization behavior plus safer alternatives. Research
  should identify the precise format/library and trust boundary before assuming
  a gadget or execution path.[2]
- **Uploads and processors.** PortSwigger frames upload risk as a chain that may
  include validation, static serving, configuration handling, parsing, and
  race/URL-based processing. Acceptance of an upload alone is not an execution
  result.[4]
- **Template engines.** PortSwigger's SSTI material separates detection,
  engine identification, documented behavior, and object-chain reasoning. The
  skill therefore requires engine identification before execution validation.[5]
- **Parser chains.** PortSwigger's XXE coverage includes altered content types,
  uploads, hidden surface, blind behavior, and parser configuration—useful
  prompts for mapping parser-to-executor chains without assuming RCE.[6]

## Report-mining questions

When reading a public report or advisory, extract only reusable structure:

1. What was the initial attacker-controlled asset or field?
2. Which transformations and trust-boundary crossings mattered?
3. What exact component acted as the interpreter or executor?
4. What prerequisite made the chain viable (version, config, role, feature,
   worker, deployment, or file path)?
5. What evidence distinguished execution from an error, parser behavior, or
   client-side effect?
6. What bounded proof would establish impact without a shell, data access, or
   persistence?
7. Which mitigations severed the chain: removal of shell use, structured APIs,
   non-executable storage, strict parser settings, signatures, sandboxing,
   privilege separation, or egress controls?

## Recurring research patterns

- **Boundary mismatch:** a validator and downstream consumer parse different
  representations.
- **Second consumer:** a benign upload/import later reaches a converter,
  previewer, extractor, renderer, or worker with different assumptions.
- **Confused data/code role:** user content becomes template source, config,
  command fragment, object graph, or build/job setting.
- **Privilege drift:** a low-privilege action schedules work in a more-privileged
  background context.
- **Feature composition:** no individual feature executes input, but two
  legitimate components create an interpreter path.

## Case-study intake bar

Add a public report only if it has a stable primary URL and enough detail to
identify a sink/control chain, evidence method, prerequisites, and remediation.
Record the report's scope/date separately from the general lesson; do not carry
live payloads into this skill.

## Sources

[1] https://owasp.org/www-community/attacks/Command_Injection
[2] https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
[3] https://portswigger.net/web-security/os-command-injection
[4] https://portswigger.net/web-security/file-upload
[5] https://portswigger.net/web-security/server-side-template-injection
[6] https://portswigger.net/web-security/xxe
