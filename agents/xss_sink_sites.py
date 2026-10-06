"""Bounded, non-exhaustive API-level XSS review seeds in JavaScript text.

These signatures name *places to inspect*, not attacker control or browser proof.
Keep the historical broad `sinks` categories in js_analyzer.py for consumers.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class SiteRule:
    signature: str
    family: str
    tier: str  # html, code, url, candidate
    pattern: re.Pattern[str]
    needles: tuple[str, ...]


def rule(signature: str, family: str, tier: str, pattern: str, *needles: str, flags: int = 0) -> SiteRule:
    return SiteRule(signature, family, tier, re.compile(pattern, flags), needles)


_ASSIGN = r"\s*(?:\+=|=(?!=|>))"
_ARG = r"\s*\(\s*(?=[^\s)])"
_JQ = (r"(?:\bjQuery|(?<![\w$])\$)\s*\([^)]{0,120}\)\s*\.\s*"
       r"(?:(?:find|filter|eq|first|last|closest|parent|children|end|addBack)"
       r"\s*\([^()]{0,120}\)\s*\.\s*){0,2}")
_EVENT_NAMES = (
    "abort", "animationend", "animationstart", "beforeinput", "blur", "change",
    "click", "contextmenu", "dblclick", "drag", "drop", "error", "focus",
    "input", "keydown", "keypress", "keyup", "load", "message", "mousedown",
    "mouseenter", "mouseleave", "mousemove", "mouseout", "mouseover", "mouseup",
    "pointerdown", "pointerup", "reset", "resize", "scroll", "submit", "touchend",
    "touchstart", "unload", "wheel",
)
_HTML_PROPS = ("innerHTML", "outerHTML")
_SCRIPT_PROPS = ("text", "textContent", "innerText", "innerHTML", "src")
_JQ_HTML_METHODS = (
    "add", "after", "append", "appendTo", "before", "html", "insertAfter",
    "insertBefore", "prepend", "prependTo", "replaceAll", "replaceWith",
    "wrap", "wrapAll", "wrapInner",
)


def _sites() -> tuple[SiteRule, ...]:
    rules = [
        rule(f"document.{method}", "dom_write", "html",
             rf"\bdocument\s*(?:\.\s*{method}|\[\s*['\"]{method}['\"]\s*\])\s*\(", "document", method)
        for method in ("write", "writeln")
    ]
    for name in _HTML_PROPS:
        rules.append(rule(f"Element.{name}", "dom_write", "html",
                          rf"(?:\.\s*{name}\b|\[\s*['\"]{name}['\"]\s*\]){_ASSIGN}", name))
    rules.extend([
        rule("Element.insertAdjacentHTML", "dom_write", "html", r"(?:\.\s*insertAdjacentHTML|\[\s*['\"]insertAdjacentHTML['\"]\s*\])\s*\(", "insertAdjacentHTML"),
        rule("Document.execCommand(insertHTML)", "html_parse", "html", r"\bdocument\s*\.\s*execCommand\s*\(\s*['\"]insertHTML['\"]\s*,", "document", "execCommand", "insertHTML"),
        rule("DOMParser.parseFromString(text/html)", "html_parse", "candidate", r"\.\s*parseFromString\s*\(\s*[^,)]{1,160},\s*['\"]text/html['\"]", "parseFromString", "text/html"),
        rule("Document.parseHTMLUnsafe", "html_parse", "candidate", r"\b(?:document|Document)\s*\.\s*parseHTMLUnsafe\s*\(", "parseHTMLUnsafe"),
        rule("Element.setHTMLUnsafe", "html_parse", "html", r"\.\s*setHTMLUnsafe\s*\(", "setHTMLUnsafe"),
        rule("Range.createContextualFragment", "html_parse", "candidate", r"\.\s*createContextualFragment\s*\(", "createContextualFragment"),
        rule("fbjs.createNodesFromMarkup", "html_parse", "candidate", r"\bcreateNodesFromMarkup\s*\(\s*(?=[^\s'\"`)])", "createNodesFromMarkup"),
        rule("HTMLIFrameElement.srcdoc", "iframe_srcdoc", "html", rf"\.\s*srcdoc\b{_ASSIGN}", "srcdoc"),
        rule("HTMLIFrameElement.setAttribute(srcdoc)", "iframe_srcdoc", "html", r"\.\s*setAttribute\s*\(\s*['\"]srcdoc['\"]\s*,", "setAttribute", "srcdoc"),
    ])
    frame = r"(?:\b(?:iframe|frame)\b|\bdocument\s*\.\s*querySelector\s*\(\s*['\"]iframe['\"]\s*\))"
    for name in ("nodeValue", "value", "textContent"):
        rules.append(rule(f"HTMLIFrameElement.attributes.srcdoc.{name}", "iframe_srcdoc", "html",
                          rf"{frame}\s*\.\s*attributes\s*(?:\.\s*srcdoc|\[\s*['\"]srcdoc['\"]\s*\])\s*\.\s*{name}{_ASSIGN}",
                          "attributes", "srcdoc", name))
    for event in _EVENT_NAMES:
        rules.append(rule(f"Element.on{event}", "event_handler", "candidate",
                          rf"(?:\.\s*on{event}\b|\[\s*['\"]on{event}['\"]\s*\]){_ASSIGN}", f"on{event}"))
        rules.append(rule(f"Element.setAttribute(on{event})", "event_handler", "candidate",
                          rf"\.\s*setAttribute(?:NS)?\s*\(\s*['\"]on{event}['\"]\s*,", "setAttribute", f"on{event}"))
    for name in _SCRIPT_PROPS:
        tier = "url" if name == "src" else "code"
        rules.append(rule(f"HTMLScriptElement.{name}", "script_content", tier,
                          rf"\b(?:script|scriptElement|scriptTag)\s*(?:\.\s*{name}\b|\[\s*['\"]{name}['\"]\s*\]){_ASSIGN}", name))
    rules.extend([
        rule("eval", "eval", "code", r"(?<![\w$.])eval\s*\(", "eval"),
        rule("window.eval", "eval", "code", r"\b(?:window|globalThis|self)\s*\.\s*eval\s*\(", "eval"),
        rule("Function", "eval", "code", r"(?<![\w$.])(?:new\s+)?Function\s*\(", "Function"),
        rule("jQuery.globalEval", "eval", "code", r"(?:\bjQuery|(?<![\w$])\$)\s*\.\s*globalEval\s*\(", "globalEval"),
        rule("eval.call", "eval", "code", r"(?<![\w$.])eval\s*\.\s*call\s*\(", "eval", "call"),
        rule("Reflect.construct(Function)", "eval", "code", r"\bReflect\s*\.\s*construct\s*\(\s*Function\s*,\s*\[", "Reflect", "Function"),
    ])
    for name in ("setTimeout", "setInterval"):
        rules.append(rule(f"{name}(string)", "string_timer_candidate", "code", rf"\b{name}\s*\(\s*['\"`]", name))
        rules.append(rule(f"{name}(candidate)", "string_timer_candidate", "candidate",
                          rf"\b{name}\s*\(\s*(?!['\"`]|function\b|async\b|\(|[\w$]+\s*=>)([A-Za-z_$][\w$]*)\s*,", name))
    rules.extend([
        rule("importScripts", "script_import", "url", r"\bimportScripts\s*\(", "importScripts"),
        rule("import(dynamic)", "script_import", "url", r"(?<![\w$.])import\s*\(\s*(?!['\"`])", "import"),
        rule("Worker(url)", "script_import", "url", r"\bnew\s+Worker\s*\(\s*(?!['\"`])[^\s)]", "Worker"),
        rule("jQuery.getScript", "script_import", "url", r"(?:\bjQuery|(?<![\w$])\$)\s*\.\s*getScript\s*\(", "getScript"),
        rule("jQuery.ajax(script)", "script_import_candidate", "candidate", r"(?:\bjQuery|(?<![\w$])\$)\s*\.\s*ajax\s*\(\s*\{[^}]{0,200}\bdataType\s*:\s*['\"]script['\"]", "ajax", "dataType", "script"),
        rule("window.open", "navigation", "url", r"\bwindow\s*\.\s*open\s*\(", "window", "open"),
        rule("Navigation.navigate", "navigation", "url", r"\bnavigation\s*\.\s*navigate\s*\(", "navigation", "navigate"),
        rule("Location.href", "navigation", "url", rf"\b(?:location|window\.location|document\.location)\s*(?:\.\s*href|\[\s*['\"]href['\"]\s*\]){_ASSIGN}", "location", "href"),
        rule("HTMLObjectElement.data", "url_attribute", "url", rf"\b(?:object|objectElement)\s*\.\s*data{_ASSIGN}", "data"),
        rule("jQuery.parseHTML", "jquery_parse", "candidate", r"(?:\bjQuery|(?<![\w$])\$)\s*\.\s*parseHTML\s*\(", "parseHTML"),
        rule("jQuery.constructor(candidate)", "jquery_selector_candidate", "candidate",
             r"(?:\bjQuery|(?<![\w$])\$)\s*\(\s*(?:(?:window\s*\.\s*)?location\s*\.\s*(?:hash|search)|(?:html|markup|fragment|template|payload|untrusted|user\w*|input|selector|hash)\w*)\s*\)",
             "(", ")", flags=re.IGNORECASE),
        rule("AngularJS.$compile", "framework_template_candidate", "candidate", r"(?<![\w$])\$compile\s*\(\s*(?!['\"`])\w+\s*\)\s*\(", "$compile"),
        rule("WinJS.Utilities.setInnerHTMLUnsafe", "framework_raw_html", "html", r"\bWinJS\.Utilities\.setInnerHTMLUnsafe\s*\(", "WinJS.Utilities", "setInnerHTMLUnsafe"),
        rule("WinJS.Utilities.setOuterHTMLUnsafe", "framework_raw_html", "html", r"\bWinJS\.Utilities\.setOuterHTMLUnsafe\s*\(", "WinJS.Utilities", "setOuterHTMLUnsafe"),
        rule("Lit.unsafeHTML", "framework_raw_html", "html", r"\bunsafeHTML\s*\(", "unsafeHTML"),
        rule("Lit.unsafeSVG", "framework_raw_html", "html", r"\bunsafeSVG\s*\(", "unsafeSVG"),
        rule("Lit.unsafeStatic(template)", "framework_template_candidate", "candidate", r"\b(?:html|svg)\s*`[^`]{0,120}\$\{\s*unsafeStatic\s*\(", "unsafeStatic"),
        rule("React.dangerouslySetInnerHTML", "framework_raw_html", "html", r"\bdangerouslySetInnerHTML\s*=", "dangerouslySetInnerHTML"),
        rule("Vue.v-html", "framework_raw_html", "html", r"\bv-html\s*=", "v-html"),
        rule("Vue.compile", "framework_template_candidate", "candidate", r"\bVue\s*\.\s*compile\s*\(\s*(?!['\"`)]|null\b)(?:/\*[\s\S]{0,100}?\*/\s*)?[A-Za-z_$][\w$]*", "Vue", "compile"),
        rule("Alpine.x-html", "framework_raw_html", "html", r"\bx-html\s*=", "x-html"),
        rule("Svelte.@html", "framework_raw_html", "html", r"\{@html\s+", "@html"),
        rule("Astro.set:html", "framework_raw_html", "html", r"\bset:html\s*=", "set:html"),
        rule("Angular.Renderer2.setProperty(innerHTML)", "framework_raw_html", "html", r"\b(?:renderer|renderer2)\.setProperty\s*\(\s*[^,()]{1,100},\s*['\"]innerHTML['\"]\s*,", "setProperty", "innerHTML"),
        rule("AngularJS.$sce.trustAsHtml", "framework_trust_bypass", "candidate", r"\$sce\s*\.\s*trustAsHtml\s*\(", "$sce", "trustAsHtml"),
        rule("Object.assign(innerHTML,candidate)", "dom_write", "candidate", r"\bObject\.assign\s*\(\s*(?:el|element|node|iframe|script|document\.querySelector\([^)]{1,80}\))\s*,\s*\{\s*innerHTML\s*:\s*", "Object.assign", "innerHTML"),
        rule("Object.assign(location,href)", "navigation", "url", r"\bObject\.assign\s*\(\s*(?:window\s*\.\s*)?location\s*,\s*\{\s*href\s*:\s*", "Object.assign", "location", "href"),
        rule("Location.set", "navigation", "url", rf"\b(?:window\.)?location{_ASSIGN}", "location"),
    ])
    for method in ("assign", "replace"):
        rules.append(rule(f"Location.{method}", "navigation", "url",
                          rf"\b(?:window\.)?location\s*\.\s*{method}\s*\(", "location", method))
    for name in ("href", "src", "action", "formaction"):
        rules.append(rule(f"Element.setAttribute({name})", "url_attribute", "url",
                          rf"\.\s*setAttribute\s*\(\s*['\"]{name}['\"]\s*,", "setAttribute", name))
    for signature, receiver, prop in (
        ("HTMLAnchorElement.href", "(?:anchor|a)", "href"),
        ("HTMLIFrameElement.src", "(?:iframe|frame)", "src"),
        ("HTMLFormElement.action", "form", "action"),
        ("HTMLButtonElement.formAction", "(?:button|submitButton)", "formAction"),
        ("HTMLEmbedElement.src", "embed", "src"),
    ):
        rules.append(rule(signature, "url_attribute", "url",
                          rf"\b{receiver}\s*(?:\.\s*{prop}\b|\[\s*['\"]{prop}['\"]\s*\]){_ASSIGN}", prop))
    for name in _JQ_HTML_METHODS:
        rules.append(rule(f"jQuery.{name}", "jquery_html", "html",
                          _JQ + rf"{name}{_ARG}", name))
    for name in _HTML_PROPS:
        rules.append(rule(f"jQuery.prop({name})", "jquery_html_property", "html",
                          _JQ + rf"prop\s*\(\s*['\"]{name}['\"]\s*,", "prop", name))
    rules.extend([
        rule("HTMLIFrameElement[srcdoc]", "iframe_srcdoc", "html", rf"(?:\b(?:iframe|frame)\b|\bdocument\s*\.\s*querySelector\s*\(\s*['\"]iframe['\"]\s*\))\s*\[\s*['\"]srcdoc['\"]\s*\]{_ASSIGN}", "srcdoc"),
        rule("Window[location][href]", "navigation", "url", rf"\bwindow\s*\[\s*['\"]location['\"]\s*\]\s*\[\s*['\"]href['\"]\s*\]{_ASSIGN}", "window", "location", "href"),
        rule("Element.setAttributeNS(xlink:href)", "url_attribute", "url", r"\.\s*setAttributeNS\s*\(\s*[^,)]{1,100},\s*['\"]xlink:href['\"]\s*,", "setAttributeNS", "xlink:href"),
        rule("Handlebars.SafeString", "framework_trust_bypass", "candidate", r"\b(?:new\s+)?Handlebars\s*\.\s*SafeString\s*\(", "Handlebars", "SafeString"),
        rule("TrustedTypes.createPolicy", "trusted_types_policy_candidate", "candidate", r"\btrustedTypes\s*\.\s*createPolicy\s*\(", "trustedTypes", "createPolicy"),
        rule("TrustedTypes.createHTML", "trusted_types_policy_candidate", "candidate", r"\.\s*createHTML\s*\(", "createHTML"),
        rule("AngularJS.$sce.trustAsJs", "framework_trust_bypass", "candidate", r"\$sce\s*\.\s*trustAsJs\s*\(", "$sce", "trustAsJs"),
    ])
    for name in ("Html", "Script", "Url", "ResourceUrl"):
        rules.append(rule(f"Angular.DomSanitizer.bypassSecurityTrust{name}", "framework_trust_bypass", "candidate",
                          rf"\.\s*bypassSecurityTrust{name}\s*\(", f"bypassSecurityTrust{name}"))
    for name in ("href", "src", "action", "formaction", "onerror", "onload"):
        for method in ("attr", "prop"):
            rules.append(rule(f"jQuery.{method}({name})", "jquery_attribute", "url" if not name.startswith("on") else "candidate",
                              _JQ + rf"{method}\s*\(\s*['\"]{name}['\"]\s*,", method, name))
    for event in _EVENT_NAMES:
        rules.append(rule(f"Element.setAttributeNS(on{event})", "event_handler", "candidate",
                          rf"\.\s*setAttributeNS\s*\(\s*[^,)]{{1,100}},\s*['\"]on{event}['\"]\s*,", "setAttributeNS", f"on{event}"))
    return tuple(rules)


SITE_RULES = _sites()
_SCRIPT_CREATE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*document\s*\.\s*createElement\s*\(\s*['\"]script['\"]\s*\)\s*;")
_RAW_INTERPOLATION_HEAD = re.compile(r"\+\s*\(\s*null\s*!=\s*\(\s*([A-Za-z_$][\w$]*)\s*=")

def _js_code_chars(text: str, start: int, limit: int):
    """Yield code positions, skipping quoted strings and JS comments conservatively."""
    index = start
    limit = min(len(text), limit)
    while index < limit:
        char = text[index]
        following = text[index + 1] if index + 1 < limit else ""
        if char in "'\"`":
            quote = char
            index += 1
            while index < limit:
                if text[index] == "\\":
                    index += 2
                elif text[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            continue
        if char == "/" and following == "*":
            end = text.find("*/", index + 2, limit)
            index = limit if end < 0 else end + 2
            continue
        if char == "/" and following == "/":
            end = text.find("\n", index + 2, limit)
            index = limit if end < 0 else end + 1
            continue
        if char == "/":
            # A closed slash-delimited token is conservatively treated as a
            # regex literal. Ambiguous division can cause a missed candidate,
            # never a claimed raw output based on regex contents.
            cursor = index + 1
            in_class = False
            while cursor < limit and text[cursor] not in "\r\n":
                if text[cursor] == "\\":
                    cursor += 2
                    continue
                if text[cursor] == "[":
                    in_class = True
                elif text[cursor] == "]":
                    in_class = False
                elif text[cursor] == "/" and not in_class:
                    index = cursor + 1
                    break
                cursor += 1
            if index == cursor + 1:
                continue
        yield index, char
        index += 1

def _matching_delimiter(text: str, opened: int, left: str, right: str, limit: int) -> int:
    """Find one balanced close in code; -1 means unknown."""
    depth = 0
    for index, char in _js_code_chars(text, opened, limit):
        if char == left:
            depth += 1
        elif char == right:
            depth -= 1
            if depth == 0:
                return index
    return -1

def _direct_return_append(text: str, template_start: int, begin: int) -> bool:
    previous_return = -1
    depth = 0
    brace_depth = 0
    for index, char in _js_code_chars(text, template_start, begin):
        if char == "{":
            brace_depth += 1
            continue
        if char == "}":
            brace_depth -= 1
            if brace_depth < 2:
                previous_return = -1
            continue
        if (char == "r" and text.startswith("return", index)
                and brace_depth == 2
                and (index == 0 or not (text[index - 1].isalnum() or text[index - 1] in "_$"))
                and (index + 6 == len(text) or not (text[index + 6].isalnum() or text[index + 6] in "_$"))):
            previous_return = index
            depth = 0
        elif previous_return < 0 or index < previous_return + len("return"):
            continue
        elif char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == ";" and depth == 0:
            previous_return = -1
    return previous_return >= 0 and brace_depth == 2 and depth == 0

def _discarded_by_comma(text: str, end: int) -> bool:
    """Reject a later top-level comma before the return expression ends."""
    depth = 0
    for _, char in _js_code_chars(text, end, end + 1024):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return False
            depth -= 1
        elif depth == 0:
            if char == ",":
                return True
            if char == ";":
                return False
    return False

def _compiled_raw_interpolations(text: str, per_rule: int) -> tuple[list[dict], bool]:
    """Bounded Handlebars precompile hint, not proof of a controlled HTML value."""
    if "template({" not in text or "lookupProperty" not in text:
        return [], False
    hits: list[dict] = []
    position = 0
    windows = 0
    template_start = -1
    template_end = -1
    while (position := text.find("null", position)) != -1:
        windows += 1
        if windows > 10_000:
            return hits, True
        start = max(0, position - 8)
        head = _RAW_INTERPOLATION_HEAD.search(text[start:position + 80])
        position += 4
        if not head or start + head.start() > position - 4:
            continue
        begin = start + head.start()
        alias = head.group(1)
        if not (template_start <= begin < template_end):
            template_start = text.rfind("template({", 0, begin)
            template_end = (_matching_delimiter(text, template_start + len("template("), "{", "}", len(text))
                            if template_start >= 0 else -1)
        if not (template_start <= begin < template_end) or not _direct_return_append(text, template_start, begin):
            continue
        assignment_open = text.find("(", position, start + head.end())
        if assignment_open < 0:
            continue
        assignment_close = _matching_delimiter(text, assignment_open, "(", ")", position + 500)
        if assignment_close < 0:
            continue
        expression = text[start + head.end():assignment_close]
        if "invokePartial" in expression or ".call(" in expression:
            continue
        suffix = re.match(r"\s*\?\s*" + re.escape(alias) + r"\s*:\s*(['\"])\1\s*\)", text[assignment_close + 1:assignment_close + 40])
        if not suffix:
            continue
        end = assignment_close + 1 + suffix.end()
        if _discarded_by_comma(text, end):
            continue
        context = text[max(template_start, begin - 8_000):begin]
        if "lookupProperty" not in context:
            continue
        call = re.match(r"\s*([A-Za-z_$][\w$]*)\s*\(", expression)
        if "escapeExpression" in expression or (call and re.search(
                rf"\b{re.escape(call.group(1))}\s*=\s*[\w$]+\.escapeExpression\b", context)):
            continue
        hits.append({"signature": "Handlebars.compiledRawInterpolation(candidate)",
                     "family": "framework_template_candidate", "tier": "candidate",
                     "start": begin, "end": end})
        if len(hits) > per_rule:
            return hits[:per_rule], True
    return hits, False


def scan_sink_sites(text: str, *, max_hits: int = 200, per_rule: int = 8) -> dict:
    """Find bounded site offsets in one artifact. Offsets are Unicode character indices."""
    if max_hits < 1 or per_rule < 1:
        raise ValueError("sink-site limits must be positive")
    hits: list[dict] = []
    truncated = False
    for item in SITE_RULES:
        if item.signature == "jQuery.constructor(candidate)":
            anchors = ("$(", "jQuery(")
            if not any(anchor in text for anchor in anchors):
                continue
        else:
            if not all(needle in text for needle in item.needles):
                continue
            anchors = (max(item.needles, key=len),)
        seen: set[tuple[int, int]] = set()
        windows = 0
        for anchor in anchors:
            position = 0
            while (position := text.find(anchor, position)) != -1:
                windows += 1
                if windows > 10_000:
                    truncated = True
                    break
                begin = max(0, position - 600)
                fragment = text[begin:min(len(text), position + 400)]
                for match in item.pattern.finditer(fragment):
                    start, end = begin + match.start(), begin + match.end()
                    if not (start <= position < end) or (start, end) in seen:
                        continue
                    seen.add((start, end))
                    hits.append({"signature": item.signature, "family": item.family, "tier": item.tier,
                                 "start": start, "end": end})
                if len(seen) > per_rule:
                    truncated = True
                    break
                position += len(anchor)
            if windows > 10_000 or len(seen) > per_rule:
                break
        if len(seen) > per_rule:
            del hits[-(len(seen) - per_rule):]
    raw_sites, raw_truncated = _compiled_raw_interpolations(text, per_rule)
    hits.extend(raw_sites)
    truncated |= raw_truncated
    # Follow a literal script-element alias only inside a small window; a generic
    # appendChild/textContent call is not a script-content execution site.
    if "createElement" in text and "script" in text:
        for index, match in enumerate(_SCRIPT_CREATE.finditer(text)):
            if index >= per_rule:
                truncated = True
                break
            alias = re.escape(match.group(1))
            window = text[match.end():match.end() + 240]
            suffixes = re.finditer(
                rf"(?<![\w$.]){alias}(?![\w$])\s*\.\s*(?:(append|appendChild)\s*\(\s*document\s*\.\s*createTextNode\s*\(|(text|textContent|innerText|innerHTML|src)\s*=(?!=|>))",
                window,
            )
            for suffix in suffixes:
                prefix = window[:suffix.start()]
                # Do not infer binding identity across JS scopes or arrow bodies.
                # The remaining straight-line hint is deliberately non-exhaustive.
                if any(mark in prefix for mark in ("{", "}", "=>")):
                    continue
                if re.search(rf"\b(?:const|let|var)\s+{alias}\b|(?<![\w$.]){alias}(?![\w$])\s*=(?!=|>)", prefix):
                    continue
                method = suffix.group(1) or suffix.group(2)
                signature = (f"HTMLScriptElement.{method}(textNode)" if suffix.group(1)
                             else f"HTMLScriptElement.alias.{method}")
                start = match.end() + suffix.start()
                hits.append({"signature": signature, "family": "script_alias_candidate", "tier": "candidate" if method != "src" else "url",
                             "start": start, "end": match.end() + suffix.end()})
    hits.sort(key=lambda hit: (hit["start"], hit["signature"]))
    if len(hits) > max_hits:
        truncated = True
        hits = hits[:max_hits]
    return {"hits": hits, "truncated": truncated}
