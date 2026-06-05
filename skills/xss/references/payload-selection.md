# XSS Idea Seeds

Use these as retrieval seeds, not rules and not a complete list. Pick ideas that
match the observed context, mutate freely, and follow signal.

## Reflection

- reflected hidden input value into later `innerHTML`
- reflected hidden input value into form clone/template clone
- reflected attribute value consumed by client script
- reflected URL parameter copied into DOM after load
- reflected path segment copied into DOM after router render
- reflected error message rendered as HTML
- reflected search term rendered in results count/title
- reflected query echoed into script bootstrap JSON
- reflected query echoed into JavaScript string
- reflected JSON value later parsed into HTML
- reflected markdown rendered into HTML
- reflected SVG/XML preview
- reflected filename/content-disposition into HTML
- reflected redirect target into link `href`
- reflected image URL into `src/srcset`
- reflected CSS value into style attribute/block
- reflected `Referer` into diagnostics/error page
- reflected `Host` or forwarded host into absolute link/script
- reflected content type mismatch
- reflected parameter only in mobile/desktop view
- reflected value only after client-side hydration

## Stored

- profile display name rendered in notification
- design/document title rendered in notification
- comment text rendered in email or notification preview
- uploaded filename rendered in attachment list
- image metadata rendered in gallery/admin view
- product/review title rendered in admin dashboard
- saved address/name rendered during checkout
- workspace/team name rendered in invite flow
- project/folder name rendered in breadcrumb
- saved search/filter name rendered in sidebar
- API-created field rendered but UI-created field sanitized
- draft value rendered differently from published value
- export/PDF/email template renders stored field
- webhook/event log renders attacker-controlled field
- moderation/support queue renders user content
- deleted/archived object still rendered in activity feed
- notification body sanitizes differently than title
- admin view sanitizes differently than public view
- mobile app/webview renders stored field differently
- stored value becomes DOM source on later page

## DOM

- query/hash copied to `innerHTML`
- full URL copied with `location.toString()`
- fragment keeps raw delimiters that query encodes
- router state copied into HTML
- `postMessage` data copied into HTML
- local/session storage copied into HTML
- cookie value copied into HTML
- JSON from API inserted with template string
- markdown parser fed from URL/storage/API
- sanitizer output passed to `innerHTML`
- DOMPurify/trusted helper used with wrong config
- `document.write` fed by location or referrer
- `insertAdjacentHTML` fed by API data
- `outerHTML` replacement with partial markup
- template element cloned after attacker update
- client-side search highlighting around attacker input
- Angular/React/Vue escape bypass via explicit trust/render helper
- hydration mismatch between server HTML and client render
- client decodes entities before assigning HTML
- browser repairs malformed markup into executable shape

## Attribute

- single-quote breakout
- double-quote breakout
- unquoted attribute whitespace breakout
- slash separator before event handler
- malformed quote recovery
- event handler on SVG/MathML/HTML
- autofocus plus focus handler
- animation/transition handler
- `srcdoc` iframe payload
- `data-*` attribute read by framework and rendered
- attribute entity decoded before DOM insertion
- duplicate attributes, browser chooses dangerous one
- sanitized attribute later concatenated into HTML
- safe attribute moved into dangerous attribute by script

## JavaScript

- quoted string close plus statement terminate
- escaped quote/backslash differential
- `</script>` parser breakout
- JSON bootstrap breakout
- template literal `${...}`
- backtick close
- callback/function-name parameter
- object key/value injection
- regex literal context
- URL encoded before script parse, decoded by client
- script data block consumed by client parser
- source map/debug route exposes sink/source hints

## URL And Navigation

- `javascript:` in link navigation
- encoded `javascript:` decoded before navigation
- control-char/newline scheme confusion
- scheme-relative URL confusion
- redirector chain into URL sink
- same-origin open redirect feeds script/link sink
- `data:` HTML/SVG URL
- `blob:` URL from attacker-controlled content
- base tag changes relative script/link targets
- `srcset` parser oddities
- iframe `srcdoc` from URL/body
- CSP relative-script/base-uri confusion
- allowlist parses differently than browser
- server validates URL, browser navigates decoded URL

## Parser And Filter Bypass

- double decode
- partial decode
- entity then percent decode
- mixed case tag/event names
- null byte or replacement char behavior
- tab/newline/form-feed separators
- comments inside tag/attribute
- malformed closing tags
- namespace confusion SVG/MathML/HTML
- mXSS/browser repair
- duplicate parameters, frontend/backend pick different value
- array/object parameter shape confusion
- content-type mismatch
- charset mismatch
- UTF-7/legacy charset probe when headers are strange
- WAF sees raw bytes, browser sees decoded DOM
- sanitizer sees one tree, browser repairs another tree

## Useful Local Sources

- `/home/ryushe/projects/bug_bounty_harness/prompts/xss-payloads.md`
- `/home/ryushe/Shared/word_lists/xss/payloads.txt`
- `/home/ryushe/.axss/knowledge.db`
