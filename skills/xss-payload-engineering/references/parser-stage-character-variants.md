# Parser-Stage Character Variants

Use this reference when a warm/hot XSS vector is affected by stripping, encoding,
normalization, parsing, or re-rendering. It is a **stage-mismatch test guide**,
not a generic bypass corpus. A visually similar character is not automatically a
syntactic substitute.

## Core Rule

Record the exact bytes and Unicode code points at each observed boundary:

```text
submitted → edge/WAF → server/router decode → validator/filter → storage →
template/serializer → browser HTML parser → DOM sink/reparse → executable consumer
```

For every useful comparison, hold the context constant and change one property:
raw ASCII delimiter; escaped/encoded representation; compatibility variant;
control/whitespace; or second-parser representation. Record the first stage
where the forms become equal, disappear, or diverge.

## What The HTML Parser Actually Recognizes

HTML tokenization operates on decoded Unicode code points. The markup delimiter
is specifically U+003C LESS-THAN SIGN (`<`); U+003E GREATER-THAN SIGN (`>`),
U+0022 QUOTATION MARK (`"`), U+0027 APOSTROPHE (`'`), U+0026 AMPERSAND (`&`),
and ASCII whitespace have context-specific grammar roles. HTML's ASCII
case-insensitivity applies to ASCII letters, not to arbitrary Unicode letters.

**Important negative control:** U+FF1C FULLWIDTH LESS-THAN SIGN (`＜`) and
U+FF1E FULLWIDTH GREATER-THAN SIGN (`＞`) are different code points. In normal
HTML tokenization they are text, not tag delimiters. They become relevant only
if an application applies compatibility normalization (for example NFKC), a
custom mapping, or a later parser before the security check or before a reparse.
The same rule applies to halfwidth/fullwidth and script-confusable characters:
test an observed transform, not a folklore equivalence.

## Representation Families And Their Preconditions

| Family | Only matters when… | Controlled comparison | Interpretation |
| --- | --- | --- | --- |
| Percent encoding | A URL/router/framework or decoder handles the value before a later check | raw versus once-encoded versus twice-encoded delimiter marker | Establish decode order and whether the checker and consumer see the same string. |
| HTML character references | The value is consumed in an HTML text/attribute context that resolves references | literal punctuation versus named/numeric reference | A reference produces a character token in that parse; it does **not** retroactively create an HTML tag token. Re-evaluate only if the resulting DOM/text is serialized and reparsed. |
| JavaScript escapes | The value reaches a JavaScript string/template/identifier grammar | literal character versus JavaScript escape form | Relevant at the JavaScript parser stage, not as an initial HTML-tag delimiter. |
| JSON escapes | A JSON parser decodes the value before it reaches HTML/DOM/template code | literal character versus JSON `\u` escape | Relevant only if JSON decoding precedes the security decision or feeds a later unsafe sink. |
| CSS escapes | The value reaches CSS grammar or a style-related DOM consumer | literal versus CSS escape form | Keep separate from HTML/JS tests; CSS grammar has different tokenization. |
| Unicode normalization | A framework, database, identifier/slug layer, or sanitizer explicitly normalizes | raw ASCII versus NFC/NFD versus NFKC/NFKD-compatible variant | Find whether normalization occurs before or after filtering. NFC/NFD and NFKC/NFKD answer different equivalence questions. |
| Confusables/lookalikes | A human review, custom blacklist, or application mapping relies on visual appearance | ASCII token versus same-looking Unicode code point | Usually a review/allowlist issue, not browser parser equivalence. Use UTS #39 as a detection source, never as a browser grammar table. |
| Controls/ASCII whitespace | The observed grammar treats a control or whitespace character specially | space, tab, LF, CR, form feed, and a rejected control as separate trials | Do not collapse “whitespace” into one case. HTML preprocessing and URL/JS/CSS grammars differ; record the exact code point. |
| Legacy encoding mismatch | Bytes can be interpreted under different declared/sniffed encodings by producer and consumer | only an owned test page with fixed raw-byte fixtures and declared charset variants | UTF-8 normally eliminates this class. Do not infer it from a Unicode glyph; prove an actual byte/charset disagreement. |

## Sanitizer Or Blacklist Matrix

When a defense appears to remove only one character (for example `>`), do not
immediately substitute lookalikes. First use inert markers to establish all of:

1. whether it filters raw input, decoded input, normalized input, stored text,
   serialized HTML, or a later DOM value;
2. whether it decodes zero, one, or multiple times;
3. whether it normalizes before or after filtering;
4. whether the browser receives text, an attribute, a parsed node, or a value
   that is reparsed by an unsafe sink; and
5. whether edge and origin see identical bytes.

A meaningful finding is a **differential**: the control is rejected/removed at
one stage but the equivalent consumer representation survives at a later stage.
A lookalike that remains literal text is a negative result, not an XSS bypass.

## Browser And Parser Boundaries Worth Naming

Keep these as candidate boundaries in the capability profile when evidence
supports them:

- transport decoding and URL/form parsing;
- server-side framework decoding/normalization;
- HTML tokenizer and tree builder;
- `textContent` versus HTML-parsing DOM sinks;
- DOM serialization followed by a second HTML parse;
- JSON/data-island parsing followed by templating or DOM insertion;
- markdown/XML/SVG/MathML parser transitions;
- JavaScript, CSS, and URL parsers after HTML attribute extraction.

Use a browser proof and DOM inspection to decide which boundary actually exists.
Do not claim a character bypass from a raw HTTP reflection alone.

## Sources

- [WHATWG HTML: parsing model and tokenization](https://html.spec.whatwg.org/multipage/parsing.html#tokenization) — decoded code points feed the tokenizer.
- [WHATWG HTML: syntax and character references](https://html.spec.whatwg.org/multipage/syntax.html#character-references) — HTML syntax uses explicit ASCII code points and context-limited character references.
- [WHATWG Encoding Standard: security background](https://encoding.spec.whatwg.org/#security-background) — producer/consumer encoding disagreement is a distinct, byte-level issue; UTF-8 is recommended.
- [Unicode UAX #15: normalization forms](https://www.unicode.org/reports/tr15/) — canonical versus compatibility equivalence and the meaning of NFC/NFD/NFKC/NFKD.
- [Unicode UTS #39: security mechanisms](https://unicode.org/reports/tr39/) — confusable detection is a security/review mechanism, not HTML syntax.
- [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html) — historical filter-evasion cases; validate browser/version/context rather than assuming portability.
