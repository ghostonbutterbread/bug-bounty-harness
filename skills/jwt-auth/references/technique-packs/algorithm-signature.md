# Algorithm And Signature

Use when JWT authorization may accept `alg:none`, unsigned tokens, stripped signatures, or unverified modified payloads.

## Checks

- Change only payload role/scope/subject and keep the original signature to test no-signature verification.
- Set header `alg` to `none` and remove the signature segment.
- Try uppercase/lowercase algorithm variants only when the parser appears permissive.
- Try one array-wrapped auth claim such as `role: ["guest", "admin"]` when the app already uses claim arrays.

## Evidence Required

- Same full URL changes from denied to authorized because of the token mutation.
- Protected role, data, or action is reachable with the modified token.
- Original denied and mutated successful responses are captured.

## Stop

Stop if success only shows caller-owned data, generic content, or parser error differences.
