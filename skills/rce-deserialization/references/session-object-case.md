# Session Object Case: Carrier, Integrity, Consumer

## Report-derived lesson

Simon Koeck's DevSite write-up (published October 12, 2026) describes an OAuth
flow stored as pickle bytes inside a readable signed session cookie. The object
exposed an OAuth client secret reused as the session signing key. The author
reports verifying that reuse, then constructing accepted state whose flow object
was unpickled by the callback. Controlled timing comparisons and rejection
controls supported invocation during reconstruction; the report does not describe
shell execution. Its fixes target the exposed credential, signing-key separation,
server-side flow storage, and replacement of client-bound pickle.[1]

The transferable lesson is the conjunction of **accepted object-byte control +
behavior-capable reconstruction + a reachable trigger**. A cookie issued by the
server can become an attacker-controlled producer when its integrity boundary
fails. A later callback can be the sink even when the issuing route is harmless.
The exact cookie keys, hosts, payload, reward, and timing values are not the method.

## Distinctions that prevent cargo-cult testing

- Flask's documented default session interface uses a tagged JSON serializer,
  not pickle.[2] A bytes tag is a reason to inspect the inner representation,
  not proof that it is pickle or that every route loads it.
- Python warns that unpickling untrusted or tampered data can execute arbitrary
  code.[3] That behavior differs from ordinary data decoding; JSON outside the
  object does not change the semantics of a later object loader.
- `pickletools` disassembles without executing pickle bytecode.[4] Inspection
  still needs bounded input/decompression and redacted output. It identifies
  structure, not the target's consumer or execution authority.
- Intact signing can prevent accepted byte modification. Key exposure/reuse was
  an essential edge in this case, not an optional detail to omit from a lead.
- The report's timing method is historical evidence, not standing permission to
  occupy workers. Proof selection belongs to `rce-validation` and live policy.

## Transfer questions

What part of the round-tripped state is readable, replaceable, or authenticated?
Does a wrapper hide a second serializer? Which handler reconstructs that object,
under what types/configuration and identity? Does validation happen before or
after reconstruction? Which edge would the next observation actually resolve?
For a different runtime, research its own reconstruction semantics and reachable
classes rather than substituting a familiar gadget list.

## Primary sources and capture provenance

Retrieved October 19, 2026 through safe-fetch; sanitized documents were used as
evidence only. Capture identifiers below reopen the primary source; raw captures
remain in quarantine, not this skill. No secrets or executable payloads copied.

[1] Simon Koeck, "How I Found a $90,000 Remote Code Execution Vulnerability in Google".
Source: https://simonkoeck.com/writeups/google-devsite-flask-session-pickle-rce
Capture: safe-fetch://quarantine/20261019T180958Z-be69cc516c/raw.bin
SHA-256: 0da5555353a8bddb2129e4714381beda72a0defa678df8699b20e9444e5e4a87

[2] Flask API, SecureCookieSessionInterface.serializer / TaggedJSONSerializer.
Source: https://flask.palletsprojects.com/en/stable/api/#flask.sessions.SecureCookieSessionInterface.serializer
Capture: safe-fetch://quarantine/20261019T181302Z-bbfd9624c7/raw.bin
SHA-256: 6e6b6f9e01b93f54b97e3c5e55cd6d223c0fe12ab102e3e55bbd63250888f372

[3] Python documentation, pickle security warning.
Source: https://docs.python.org/3/library/pickle.html
Capture: safe-fetch://quarantine/20261019T181006Z-2527ceb38e/raw.bin
SHA-256: ec39ee19e296177e2ea70b0dfe0b57e9fdfa55d3b4b991b0232064ed95133d98

[4] Python documentation, pickletools command-line usage.
Source: https://docs.python.org/3/library/pickletools.html
Capture: safe-fetch://quarantine/20261019T181107Z-1663110f04/raw.bin
SHA-256: 22caba66cad9f04da2fa94111e2b340ac0aee595c563117fdbc1dc36c5160cf8
