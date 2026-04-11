#!/usr/bin/env python3
"""
APK Surface Analyzer — targeted static analysis for Android APKs.
Runs without shared_brain overhead. Targets smali, manifest, and assets.
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional

# ── imports ──────────────────────────────────────────────────────────────────
_AGENT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _AGENT_DIR.parent
for p in map(Path, sys.path):
    if _PROJECT_ROOT.as_posix() in p.as_posix():
        break
else:
    sys.path.insert(0, _PROJECT_ROOT.as_posix())

try:
    sys.path.insert(0, str(Path.home() / "projects" / "bounty-tools"))
    from subagent_logger import SubagentLogger, compute_pte_lite
except ImportError:
    SubagentLogger = None

    def compute_pte_lite(**kw: any) -> int:
        return (
            int(kw.get("prompt_tokens") or 0)
            + int(kw.get("completion_tokens") or 0)
            + int(kw.get("tool_output_tokens") or 0)
        )


# ── helpers ───────────────────────────────────────────────────────────────────
def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _tokens(text: str | bytes | None) -> int:
    if text is None:
        return 0
    size = len(text) if isinstance(text, bytes) else len(str(text).encode())
    return max(0, (size + 3) // 4)


def _safe_span(logger, **kw) -> None:
    if logger is None:
        return
    try:
        logger.log_span(**kw)
    except Exception:
        pass


# ── findings ─────────────────────────────────────────────────────────────────
@dataclass
class Finding:
    fid: str
    severity: str
    surface: str
    title: str
    description: str
    file: str
    line: Optional[int]
    evidence: str
    remediation: str


FINDINGS: list[Finding] = []
FINDING_COUNTER = 0


def add(severity: str, surface: str, title: str, description: str,
        file: str = "", line: int = 0, evidence: str = "", remediation: str = "") -> None:
    global FINDING_COUNTER
    FINDING_COUNTER += 1
    fid = f"SC{FINDING_COUNTER:02d}"
    FINDINGS.append(Finding(fid, severity, surface, title, description,
                            file, line, evidence, remediation))


# ── scanners ─────────────────────────────────────────────────────────────────
def scan_manifest(apk_dir: Path, logger=None) -> None:
    manifest_path = apk_dir / "AndroidManifest.xml"
    if not manifest_path.exists():
        return

    content = manifest_path.read_text(encoding="utf-8", errors="replace")
    start = time.time()

    # Exported components
    exported = re.findall(r'android:exported="true"', content)
    if len(exported) > 20:
        add("HIGH", "android-manifest",
            f"{len(exported)} exported components — large attack surface",
            f"The manifest declares {len(exported)} exported components. "
            "Every additional exported component is a potential entry point for other apps.",
            str(manifest_path), 0,
            f"{len(exported)} android:exported=\"true\" occurrences",
            "Review each exported component. Set android:exported=\"false\" unless "
            "the component must be accessible to other apps.")

    # Custom URL schemes
    schemes = re.findall(r'android:scheme="([^"]+)"', content)
    schemes = [s for s in schemes if s not in ("content", "file", "http", "https")]
    if schemes:
        add("HIGH", "android-manifest",
            f"Custom URL schemes: {', '.join(schemes)}",
            "Custom URL schemes allow other apps or webpages to trigger app actions. "
            "If the handling activity doesn't validate input, this enables deep-link attacks.",
            str(manifest_path), 0,
            ", ".join(schemes),
            "Validate all incoming URI parameters. Use allowlist for allowed actions.")

    # allowBackup
    if 'android:allowBackup="true"' in content:
        add("MEDIUM", "android-manifest",
            "allowBackup enabled — app data accessible via ADB",
            "With allowBackup, 'adb backup' or a rooted device can extract "
            "shared preferences, databases, and files.",
            str(manifest_path), 0, "android:allowBackup=\"true\"",
            "Set android:allowBackup=\"false\" or use encryptedSharedPreferences.")

    # cleartext traffic
    if "cleartextTrafficPermitted=" in content:
        match = re.search(r'cleartextTrafficPermitted="([^"]+)"', content)
        if match and match.group(1) == "true":
            add("MEDIUM", "android-manifest",
                "Cleartext HTTP traffic permitted",
                "App allows cleartext (unencrypted) network traffic. "
                "Attacker on same network can intercept/modify data.",
                str(manifest_path), 0, "cleartextTrafficPermitted=\"true\"",
                "Use HTTPS only. Set networkSecurityConfig to block HTTP.")

    # Exported activities
    activities = re.findall(r'<activity[^>]*android:exported="true"[^>]*android:name="([^"]+)"', content)
    sensitive = [a for a in activities if any(x in a.lower() for x in
                ["auth", "login", "payment", "admin", "debug", "settings", "upload", "widget"])]
    if sensitive:
        add("MEDIUM", "android-manifest",
            f"Sensitive exported activities: {', '.join(sensitive)}",
            "Activities handling auth, payments, or settings are exported. "
            "Other apps can launch these activities directly.",
            str(manifest_path), 0,
            ", ".join(sensitive),
            "Protect with permissions or set android:exported=\"false\".")

    # Exported receivers
    receivers = re.findall(r'<receiver[^>]*android:exported="true"[^>]*android:name="([^"]+)"', content)
    if receivers:
        add("LOW", "android-manifest",
            f"Exported BroadcastReceivers: {', '.join(receivers[:5])}",
            "Exported receivers can be triggered by any other app. "
            "If they perform privileged actions, this is a vulnerability.",
            str(manifest_path), 0,
            f"{len(receivers)} exported receivers",
            "Use LocalBroadcastManager or set android:exported=\"false\".")

    _safe_span(logger, span_type="tool", phase="scan", level="RESULT",
               message=f"Manifest scan: {len(FINDINGS)} findings",
               tool_name="apk_surface_analyzer", tool_category="android",
               target=str(apk_dir),
               params={"scanned": "AndroidManifest.xml"},
               prompt_tokens=_tokens(content),
               completion_tokens=0,
               context_tokens_before=_tokens(content),
               context_tokens_after=_tokens(content),
               tool_output_tokens=0,
               pte_lite=compute_pte_lite(prompt_tokens=_tokens(content),
                                          completion_tokens=0, tool_output_tokens=0,
                                          context_tokens_after=_tokens(content)),
               latency_ms=int((time.time() - start) * 1000),
               input_bytes=len(content.encode()),
               output_bytes=0, success=True)


def scan_smali(apk_dir: Path, logger=None, max_files: int = 500) -> None:
    """Scan smali files for vulnerability patterns. Limit to max_files for speed."""
    smali_dirs = list(apk_dir.glob("smali*/"))
    if not smali_dirs:
        return

    start = time.time()
    total_bytes = 0
    findings_at_start = len(FINDINGS)

    # Critical patterns
    PATTERNS = [
        # (regex, severity, surface, title, evidence_template, remediation)
        (r"setJavaScriptEnabled\(Z\)V.*addJavascriptInterface",
         "CRITICAL", "webview-rce",
         "WebView with JavaScript enabled + addJavascriptInterface",
         "setJavaScriptEnabled + addJavascriptInterface in same method",
         "Remove addJavascriptInterface or ensure injected objects are safe."),

        (r"addJavascriptInterface",
         "HIGH", "webview-rce",
         "addJavascriptInterface detected — check injected objects",
         "addJavascriptInterface called — verify injected object methods are safe",
         "Audit injected Java objects. Remove if not required."),

        (r"Runtime\.getRuntime\(\)\.exec",
         "HIGH", "command-injection",
         "Runtime.exec() call — possible command injection",
         "Runtime.getRuntime().exec() found",
         "Validate and sanitize all inputs to exec(). Use ProcessBuilder instead."),

        (r"ProcessBuilder",
         "MEDIUM", "command-injection",
         "ProcessBuilder usage — verify input sanitization",
         "ProcessBuilder detected",
         "Ensure all process arguments come from trusted sources."),

        (r"loadClass\(.*\.class\)",
         "HIGH", "code-execution",
         "Dynamic class loading — potential code execution",
         "loadClass() call detected",
         "Verify class names come from trusted sources only."),

        (r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader",
         "HIGH", "code-execution",
         "Dynamic dex/code loading — potential RCE",
         "DexClassLoader or equivalent found",
         "Ensure loaded DEX comes from app's own assets, not external source."),

        (r'android\.intent\.action\.VIEW.*setData',
         "MEDIUM", "intent-redirect",
         "Intent with VIEW action and setData — possible open redirect",
         "Intent.setData() with VIEW action",
         "Validate URI scheme and host before dispatching."),

        (r"openFile\(.*ParcelFileDescriptor",
         "HIGH", "file-provider",
         "ContentProvider openFile() — verify URI validation",
         "openFile() method in ContentProvider",
         "Validate URI parameters. Don't trust user-controlled path components."),

        (r"startActivity\(.*Intent",
         "MEDIUM", "intent-hijacking",
         "Programmatic startActivity — verify intent destination",
         "startActivity() call found",
         "Use explicit intents with component names where possible."),

        (r"PendingIntent\.getBroadcast|PendingIntent\.getActivity",
         "HIGH", "pendingintent-hijacking",
         "PendingIntent without setComponent — hijackable",
         "PendingIntent.getBroadcast/Activity without setComponent",
         "Always use setComponent() or setPackage() on PendingIntents."),

        (r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE",
         "HIGH", "file-permission",
         "World-readable/writable file modes — data leakage",
         "MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE detected",
         "Use MODE_PRIVATE. For cross-app sharing, use ContentProvider with permissions."),

        (r"SharedPreferences.*MODE_WORLD",
         "HIGH", "file-permission",
         "SharedPreferences with world access — sensitive data at risk",
         "SharedPreferences with MODE_WORLD_*",
         "Use encryptedSharedPreferences or ContentProvider with permissions."),

        (r"WebView.*evaluateJavascript",
         "MEDIUM", "webview-rce",
         "WebView evaluateJavascript — verify JS source",
         "evaluateJavascript() call",
         "Only evaluate JS from trusted, app-controlled sources."),

        (r"sqliteDatabase.*rawQuery",
         "MEDIUM", "sql-injection",
         "rawQuery with dynamic SQL — potential SQL injection",
         "SQLiteDatabase.rawQuery() with concatenated input",
         "Use parameterized queries instead of string concatenation."),

        (r"Jackson.*ObjectMapper.*readValue",
         "MEDIUM", "deserialization",
         "Jackson deserialization — verify input source",
         "Jackson ObjectMapper.readValue() detected",
         "Don't deserialize untrusted JSON from network or Intent extras."),

        (r"kotlin\.反射|kotlin\.runtime\.reflect",
         "LOW", "reflection",
         "Kotlin reflection — increased attack surface",
         "Kotlin reflection APIs detected",
         "Minimize use of reflection. If needed, validate class names."),

        (r"content://.*\.\./",
         "HIGH", "path-traversal",
         "URI path traversal attempt — content provider may be exploitable",
         "Content URI with ../ path traversal",
         "Canonicalize and validate all URI paths before use."),

        (r"file:///data/data/|file:///data/user/",
         "MEDIUM", "file-access",
         "Direct access to app data directory — verify necessity",
         "Hardcoded path to /data/data/",
         "Use Context methods for data directory access instead of hardcoded paths."),
    ]

    file_count = 0
    for smali_dir in smali_dirs:
        for smali_file in smali_dir.rglob("*.smali"):
            if file_count >= max_files:
                break
            try:
                content = smali_file.read_text(encoding="utf-8", errors="replace")
                total_bytes += len(content.encode())
                rel_path = smali_file.relative_to(apk_dir).as_posix()

                for pattern, severity, surface, title, evidence, remediation in PATTERNS:
                    matches = list(re.finditer(pattern, content, re.IGNORECASE | re.DOTALL))
                    if matches:
                        for m in matches[:3]:  # cap per-pattern per-file
                            line_num = content[:m.start()].count("\n") + 1
                            snippet = content[max(0, m.start()-40):m.end()+40].strip().replace("\n", " ")
                            add(severity, surface, title, f"{title} in {rel_path}",
                                rel_path, line_num, snippet[:200], remediation)
            except OSError:
                continue
            file_count += 1
            if file_count >= max_files:
                break

    elapsed = int((time.time() - start) * 1000)
    new_findings = len(FINDINGS) - findings_at_start

    _safe_span(logger, span_type="tool", phase="scan", level="RESULT",
               message=f"Smali scan: {new_findings} findings from {file_count} files",
               tool_name="apk_surface_analyzer", tool_category="android",
               target=str(apk_dir),
               params={"files_scanned": file_count, "max_files": max_files},
               prompt_tokens=total_bytes // 4,
               completion_tokens=0,
               context_tokens_before=total_bytes // 4,
               context_tokens_after=total_bytes // 4,
               tool_output_tokens=0,
               pte_lite=compute_pte_lite(
                   prompt_tokens=total_bytes // 4,
                   completion_tokens=0, tool_output_tokens=0,
                   context_tokens_after=total_bytes // 4),
               latency_ms=elapsed,
               input_bytes=total_bytes,
               output_bytes=0, success=True)


def scan_assets(apk_dir: Path, logger=None) -> None:
    """Scan assets for hardcoded secrets and interesting files."""
    assets_dir = apk_dir / "assets"
    if not assets_dir.exists():
        return

    start = time.time()
    total_bytes = 0
    findings_at_start = len(FINDINGS)

    SECRET_PATTERNS = [
        (r"api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9_-]{20,}['\"]",
         "CRITICAL", "secrets",
         "Hardcoded API key detected", "", "Rotate and use secure storage (Android Keystore)."),
        (r"secret['\"]?\s*[:=]\s*['\"][A-Za-z0-9_!-]{16,}['\"]",
         "CRITICAL", "secrets",
         "Hardcoded secret detected", "", "Remove hardcoded secrets. Use Android Keystore or server-side retrieval."),
        (r"password['\"]?\s*[:=]\s*['\"][^'\"\s]{8,}['\"]",
         "HIGH", "secrets",
         "Hardcoded password detected", "", "Remove hardcoded passwords."),
        (r"token['\"]?\s*[:=]\s*['\"][A-Za-z0-9_-]{20,}['\"]",
         "HIGH", "secrets",
         "Hardcoded token detected", "", "Use secure token storage."),
        (r"private[_-]?key['\"]?\s*[:=]",
         "CRITICAL", "secrets",
         "Private key hardcoded", "", "Remove immediately. Use secure key storage."),
        (r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)?\s*PRIVATE\s+KEY-----",
         "CRITICAL", "secrets",
         "Private key material in assets", "", "Remove from APK. Use Android Keystore."),
    ]

    INJECTION_PATTERNS = [
        (r"<script[^>]*src\s*=\s*['\"]https?://",
         "HIGH", "remote-code-injection",
         "External script loaded from asset HTML", "",
         "Never load remote scripts from HTML assets."),
        (r"eval\s*\(", "HIGH", "code-injection",
         "eval() call in JavaScript asset", "",
         "Remove eval(). Use safe alternatives."),
        (r"document\.write\s*\(", "MEDIUM", "xss",
         "document.write() in JavaScript asset", "",
         "Avoid document.write(). Use textContent or innerHTML with sanitization."),
    ]

    for asset_file in assets_dir.rglob("*"):
        if not asset_file.is_file():
            continue
        try:
            content = asset_file.read_bytes()
            total_bytes += len(content)
            rel_path = asset_file.relative_to(apk_dir).as_posix()

            # Text files only for pattern matching
            if b"\x00" in content[:1024]:  # binary
                continue
            try:
                text = content.decode("utf-8", errors="replace")
            except Exception:
                continue

            for pattern, severity, surface, title, _, remediation in SECRET_PATTERNS + INJECTION_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    snippet = text[max(0, re.search(pattern, text, re.IGNORECASE).start()-50):
                                     re.search(pattern, text, re.IGNORECASE).end()+50]
                    add(severity, surface, title,
                        f"{title} in {rel_path}",
                        rel_path, 0, snippet[:200], remediation)

        except OSError:
            continue

    new_findings = len(FINDINGS) - findings_at_start
    _safe_span(logger, span_type="tool", phase="scan", level="RESULT",
               message=f"Asset scan: {new_findings} findings",
               tool_name="apk_surface_analyzer", tool_category="android",
               target=str(apk_dir),
               params={"scanned": "assets/"},
               prompt_tokens=total_bytes // 4,
               completion_tokens=0,
               context_tokens_before=total_bytes // 4,
               context_tokens_after=total_bytes // 4,
               tool_output_tokens=0,
               pte_lite=compute_pte_lite(prompt_tokens=total_bytes // 4,
                                          completion_tokens=0, tool_output_tokens=0,
                                          context_tokens_after=total_bytes // 4),
               latency_ms=int((time.time() - start) * 1000),
               input_bytes=total_bytes,
               output_bytes=0, success=True)


def write_report(program: str, apk_dir: Path, output_dir: Path, logger=None) -> list[dict]:
    """Write findings report to output directory."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(FINDINGS, key=lambda f: (
        severity_order.get(f.severity, 4), f.fid))

    today = datetime.now().strftime("%d-%m-%Y")

    # Markdown report
    report_path = output_dir / f"apk_surface_{today}.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# APK Surface Analysis — {program}\n\n")
        f.write(f"**APK:** `{apk_dir}`\n")
        f.write(f"**Date:** {today}\n")
        f.write(f"**Findings:** {len(sorted_findings)}\n\n")

        for finding in sorted_findings:
            f.write(f"---\n\n")
            f.write(f"### [{finding.fid}] {finding.title}\n\n")
            f.write(f"**Severity:** {finding.severity} | **Surface:** {finding.surface}\n\n")
            f.write(f"**File:** `{finding.file}`")
            if finding.line:
                f.write(f":{finding.line}")
            f.write("\n\n")
            f.write(f"**Description:** {finding.description}\n\n")
            if finding.evidence:
                f.write(f"**Evidence:**\n```\n{finding.evidence}\n```\n\n")
            f.write(f"**Remediation:** {finding.remediation}\n\n")

    # JSON output
    json_path = output_dir / f"apk_surface_{today}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump([asdict(f) for f in sorted_findings], f, indent=2)

    # Severity summary
    summary = {sev: sum(1 for f in FINDINGS if f.severity == sev)
               for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    print(f"\n[apk_surface_analyzer] Scan complete: {len(FINDINGS)} findings")
    print(f"  CRITICAL: {summary.get('CRITICAL', 0)} | HIGH: {summary.get('HIGH', 0)} "
          f"| MEDIUM: {summary.get('MEDIUM', 0)} | LOW: {summary.get('LOW', 0)}")
    print(f"  Report: {report_path}")
    print(f"  JSON: {json_path}")

    _safe_span(logger, span_type="tool", phase="finish", level="RESULT",
               message=f"APK scan complete: {len(FINDINGS)} findings",
               tool_name="apk_surface_analyzer", tool_category="android",
               target=str(apk_dir),
               params={"total": len(FINDINGS), "critical": summary.get("CRITICAL", 0),
                       "high": summary.get("HIGH", 0)},
               success=True)

    return [asdict(f) for f in sorted_findings]


# ── main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="APK Surface Analyzer")
    parser.add_argument("program", help="Bug bounty program name")
    parser.add_argument("apk_dir", help="Path to extracted APK directory")
    parser.add_argument("--output-dir", help="Override output directory")
    parser.add_argument("--max-smali", type=int, default=500,
                        help="Max smali files to scan (default: 500)")
    args = parser.parse_args()

    program = args.program
    apk_dir = Path(args.apk_dir).expanduser().resolve()

    if not apk_dir.exists():
        print(f"[ERROR] APK directory not found: {apk_dir}")
        sys.exit(1)

    # Determine output dir
    base = Path.home() / "Shared" / "bounty_recon" / program / "ghost"
    output_dir = Path(args.output_dir) if args.output_dir else (base / "reports_source")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Logger
    log = None
    if SubagentLogger:
        try:
            log = SubagentLogger("apk_analyzer", program, f"apk_{int(time.time())}")
            log.start(target=str(apk_dir), mode="surface-scan")
        except Exception:
            pass

    print(f"[apk_surface_analyzer] Starting scan of {apk_dir}")
    print(f"[apk_surface_analyzer] Output: {output_dir}")

    scan_manifest(apk_dir, log)
    scan_smali(apk_dir, log, max_files=args.max_smali)
    scan_assets(apk_dir, log)

    results = write_report(program, apk_dir, output_dir, log)

    if log:
        try:
            log.finish(success=True)
        except Exception:
            pass

    return results


if __name__ == "__main__":
    main()
