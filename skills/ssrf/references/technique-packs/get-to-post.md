# GET-only SSRF → POST-capable downstream request

**Status:** active on-demand SSRF reference. **Owner:** `skills/ssrf/` in the BBH canonical repository. **Canonical path:** this file. **Supersedes:** none. **Implementation commit:** none — documentation-only reference (see Git history). This is a method-boundary investigation aid, not permission to send a state-changing request. Apply program scope, `live-testing-policy`, and the SSRF skill's proof/attempt rules first.

## First separate the two requests

An outer `GET /preview?url=...` says nothing by itself about the server's **inner** request method. Point it at an owned recorder and capture the inner method, path, headers, body, redirects, and final destination. A DNS hit is not an HTTP method measurement. A fetcher that only issues HTTP GET cannot normally be made to send HTTP POST by placing `POST` in the URL path or query. An HTTP redirect changes the destination; 307/308 preserve the original method and 303 directs a retrieval request, so a redirect from GET is not a GET→POST conversion.[4]

## Choose a route from observed capabilities

1. **Fetcher already supports method and body:** inspect the feature/API for a documented method option, body/template field, custom headers, webhook test, or event trigger. Verify the resulting request at an owned receiver, rather than assuming that the outer request method is forwarded. A webhook may produce its own POST with an application-generated body and event context; that is a *different sink*, not a magical conversion of a GET-only URL fetcher. GitLab's webhook documentation is one example of an event-driven POST surface.[6]
2. **Fetcher accepts a raw-capable scheme:** if the actual backend supports `gopher://` or another suitable TCP/protocol adapter, an attacker-selected URL may carry bytes that begin with an HTTP POST request line. This is a **new protocol connection** carrying a hand-built HTTP/1.1 message, not an HTTP GET with a changed verb. Prove scheme acceptance and exact bytes only with an owned local receiver first. The disclosed PlayStation image-renderer SSRF used an outer GET, an attacker-controlled redirect, and a Gopher destination to send SMTP commands; it illustrates the protocol-boundary primitive, **not** an observed HTTP POST.[1] libcurl's documented redirect-protocol defaults are HTTP, HTTPS, FTP, and FTPS, so do not assume an HTTP→Gopher redirect is followed: test direct scheme acceptance separately from redirect handling and record the actual library/configuration.[3]
3. **GET reaches a server-side action gateway:** an internal endpoint might intentionally act on GET, accept a method-override convention, or enqueue a POST to another service. These are *application-specific* chains. Confirm the gateway's configuration and the resulting method at an owned receiver; `?_method=POST` is not a generic HTTP feature. Express's example method-override middleware explicitly starts from POST in its default configuration; a GET-only SSRF does not automatically inherit that capability.[5]
4. **Server-side renderer/browser:** if the sink renders attacker-controlled HTML or script rather than merely fetching a URL, a controlled page may cause a form submission or other secondary request. Verify that rendering actually executes and that egress, cookies, CSRF defenses, and browser policy permit the request. Treat this as a separate browser-action surface, not a property of a plain HTTP client.
5. **No supported route:** if an owned receiver consistently observes only GET, other schemes are rejected, redirects preserve GET, and no secondary action sink exists, record the method boundary as unproven and pivot. Do not label an internal POST endpoint reachable merely because its host answers an SSRF GET.

## Owned-receiver byte check for the raw-protocol route

Only on a disposable receiver you control, build a **single benign** HTTP/1.1 POST. The Gopher `/_` selector pattern below is client-specific: the client may append a trailing CRLF, normalize escapes, block the scheme, or interpret a redirect differently. Capture bytes and compare the exact request, including body length; do not paste this URL into a live target before the live-policy/scope decision.

```python
from urllib.parse import quote

host, port = "127.0.0.1", 8000  # your owned receiver
body = b"ok"  # harmless owned-fixture marker
authority = f"{host}:{port}"
raw = (b"POST /probe HTTP/1.1\r\n"
       + f"Host: {authority}\r\n".encode("ascii")
       + b"Content-Type: text/plain\r\n"
       + b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
       + b"Connection: close\r\n\r\n" + body)
url = f"gopher://{authority}/_" + quote(raw.decode("ascii"), safe="")
print(url)
```

With a local HTTP server listening on `127.0.0.1:8000`, a client that actually supports Gopher can be pointed at this URL. Verify the receiver logged `POST /probe` and the `ok` body. If a URL is embedded in an outer query or redirect `Location`, encode **that layer separately**; inspect the final decoded destination instead of assuming one or two encoding passes. Do not generalize this one-client result to the target's backend. The PlayStation report's Gopher-through-redirect behavior and libcurl's documented redirect defaults are different configurations, not contradictory proof of universal redirect support.[1][3]

## Boundary, impact, and stop rule

A bare callback establishes fetching, not POST capability, internal reachability, privileged authority, or impact. Collect separate evidence for each: inner method/body at your receiver; destination reachability; response or attributable effect; and authorization/privilege. A raw-protocol POST, CRLF/header injection, request smuggling, or renderer-submitted form may modify data. Before any live proof, classify the effect and use an explicitly owned no-side-effect fixture or obtain the approval required by `live-testing-policy`; stop on out-of-scope or uncontrolled effects. Avoid using cloud metadata token endpoints, internal admin actions, or third-party inboxes as method probes. A header-setting field can also have order-of-execution limits: in disclosed GitLab import research, a proposed `remote_attachment_request_header` path was reported as assigned after the URL fetch, not as a verified way to alter that request.[2]

## Sources

[1] https://hackerone.com/reports/811136 — HackerOne #811136 PlayStation SSRF on image renderer
[2] https://hackerone.com/reports/826361 — HackerOne #826361 GitLab project import SSRF
[3] https://curl.se/libcurl/c/CURLOPT_REDIR_PROTOCOLS_STR.html — libcurl redirect protocol options
[4] https://www.rfc-editor.org/rfc/rfc9110.html — RFC 9110 HTTP Semantics
[5] https://expressjs.com/en/resources/middleware/method-override — Express method-override middleware
[6] https://docs.gitlab.com/user/project/integrations/webhooks — GitLab webhooks
