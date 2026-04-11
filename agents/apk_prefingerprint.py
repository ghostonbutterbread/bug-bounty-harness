"""Fast APK prefingerprint for progressive attack-surface mapping."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree as ET

_AGENT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _AGENT_DIR.parent
if _PROJECT_ROOT.as_posix() not in (p.as_posix() for p in map(Path, sys.path)):
    sys.path.insert(0, _PROJECT_ROOT.as_posix())
_BOUNTY_TOOLS_ROOT = Path.home() / "projects" / "bounty-tools"
if _BOUNTY_TOOLS_ROOT.as_posix() not in (p.as_posix() for p in map(Path, sys.path)):
    sys.path.insert(0, _BOUNTY_TOOLS_ROOT.as_posix())

from agents.apk_surface_registry import ApkSurfaceRegistry

try:
    from subagent_logger import SubagentLogger, compute_pte_lite
except ImportError:  # pragma: no cover
    SubagentLogger = None

    def compute_pte_lite(**kwargs: Any) -> int:
        return (
            int(kwargs.get("prompt_tokens") or 0)
            + int(kwargs.get("completion_tokens") or 0)
            + int(kwargs.get("tool_output_tokens") or 0)
        )


ANDROID_NS = "http://schemas.android.com/apk/res/android"
DEFAULT_MAX_RUNTIME_SECONDS = 60


def _estimate_tokens(text: str | bytes | None) -> int:
    if text is None:
        return 0
    payload = text if isinstance(text, bytes) else str(text).encode("utf-8", errors="replace")
    return max(0, (len(payload) + 3) // 4)


def _safe_log_span(logger: SubagentLogger | None, **fields: Any) -> None:
    if logger is None:
        return
    try:
        logger.log_span(**fields)
    except Exception:
        pass


def _android_attr(element: ET.Element, name: str) -> str:
    return str(element.attrib.get(f"{{{ANDROID_NS}}}{name}") or "").strip()


def _sanitize_program_name(program: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(program or "").strip()) or "default_program"


def _resolve_class_name(package_name: str, raw_name: str) -> str:
    name = str(raw_name or "").strip()
    if not name:
        return ""
    if name.startswith("."):
        return f"{package_name}{name}"
    if "." not in name and package_name:
        return f"{package_name}.{name}"
    return name


def _relative_to(root: Path, path: Path) -> str:
    try:
        return str(path.resolve(strict=False).relative_to(root.resolve(strict=False)))
    except ValueError:
        return str(path.resolve(strict=False))


def _run(cmd: list[str], cwd: Path, timeout_seconds: int = DEFAULT_MAX_RUNTIME_SECONDS) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
        return completed.returncode, completed.stdout, completed.stderr
    except FileNotFoundError:
        return 127, "", f"tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
        return 124, stdout, f"timed out after {timeout_seconds}s {stderr}".strip()


@dataclass(frozen=True)
class HintPattern:
    key: str
    regex: str
    severity_score: float
    category: str
    tags: tuple[str, ...]


HINT_PATTERNS = (
    HintPattern(
        key="webview",
        regex=(
            r"Landroid/webkit/WebView;|->addJavascriptInterface\(|->evaluateJavascript\("
            r"|->setJavaScriptEnabled\(Z\)V|->setAllowFileAccess\(|->setAllowUniversalAccessFromFileURLs\("
        ),
        severity_score=0.8,
        category="webview_classes",
        tags=("webview", "javascript"),
    ),
    HintPattern(
        key="command-exec",
        regex=r"Ljava/lang/Runtime;->exec\(|Ljava/lang/ProcessBuilder;|->execve\(",
        severity_score=0.9,
        category="smali_hints",
        tags=("exec", "command"),
    ),
    HintPattern(
        key="dynamic-loader",
        regex=r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader|Ljava/lang/ClassLoader;",
        severity_score=0.8,
        category="smali_hints",
        tags=("loader", "code-loading"),
    ),
    HintPattern(
        key="pending-intent",
        regex=r"Landroid/app/PendingIntent;->get(?:Activity|Broadcast|Service)\(",
        severity_score=0.7,
        category="smali_hints",
        tags=("pending-intent", "ipc"),
    ),
    HintPattern(
        key="jni-load",
        regex=r"Ljava/lang/System;->loadLibrary\(|Ljava/lang/System;->load\(|^\.method .* native ",
        severity_score=0.7,
        category="smali_hints",
        tags=("jni", "native"),
    ),
    HintPattern(
        key="content-provider",
        regex=r"->openFile\(|->query\(|->insert\(|->update\(|->delete\(",
        severity_score=0.75,
        category="smali_hints",
        tags=("provider", "storage"),
    ),
    HintPattern(
        key="ordered-broadcast",
        regex=r"sendOrderedBroadcast|registerReceiver|setResultData",
        severity_score=0.6,
        category="smali_hints",
        tags=("broadcast", "receiver"),
    ),
)


def _find_manifest(extracted_root: Path) -> Path:
    candidate = extracted_root / "AndroidManifest.xml"
    if candidate.exists():
        return candidate
    nested = sorted(extracted_root.rglob("AndroidManifest.xml"))
    if nested:
        return nested[0]
    raise FileNotFoundError(f"AndroidManifest.xml not found under {extracted_root}")


def _extract_apk(apk_path: Path, extracted_root: Path, logger: SubagentLogger | None) -> tuple[Path, list[str]]:
    warnings: list[str] = []
    if apk_path.is_dir():
        manifest_candidate = apk_path / "AndroidManifest.xml"
        if manifest_candidate.exists():
            return apk_path.resolve(strict=False), warnings
        raise FileNotFoundError(f"directory target does not look extracted: {apk_path}")

    extracted_root.parent.mkdir(parents=True, exist_ok=True)
    manifest_marker = extracted_root / "AndroidManifest.xml"
    if manifest_marker.exists():
        return extracted_root.resolve(strict=False), warnings

    started = time.time()
    apktool_path = shutil.which("apktool")
    command_text = ""
    if apktool_path:
        cmd = [apktool_path, "d", "-f", "-o", str(extracted_root), str(apk_path)]
        command_text = " ".join(cmd)
        rc, stdout, stderr = _run(cmd, cwd=extracted_root.parent)
        response_text = "\n".join(part for part in (stdout, stderr) if part)
        _safe_log_span(
            logger,
            span_type="tool",
            phase="prefingerprint",
            level="RESULT" if rc == 0 else "ERROR",
            message="apktool extraction",
            tool_name="apktool",
            tool_category="apk",
            target=str(apk_path),
            params={"output_dir": str(extracted_root)},
            prompt_tokens=_estimate_tokens(command_text),
            completion_tokens=0,
            context_tokens_before=_estimate_tokens(command_text),
            context_tokens_after=_estimate_tokens(command_text),
            tool_output_tokens=_estimate_tokens(response_text),
            pte_lite=compute_pte_lite(
                prompt_tokens=_estimate_tokens(command_text),
                completion_tokens=0,
                tool_output_tokens=_estimate_tokens(response_text),
                context_tokens_after=_estimate_tokens(command_text),
            ),
            latency_ms=int((time.time() - started) * 1000),
            input_bytes=len(command_text.encode("utf-8", errors="replace")),
            output_bytes=len(response_text.encode("utf-8", errors="replace")),
            success=rc == 0,
            error=None if rc == 0 else stderr[:400],
        )
        if rc == 0:
            return extracted_root.resolve(strict=False), warnings
        warnings.append(f"apktool extraction failed: {stderr.strip() or stdout.strip() or f'rc={rc}'}")

    if extracted_root.exists():
        shutil.rmtree(extracted_root)
    extracted_root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(apk_path) as archive:
        archive.extractall(extracted_root)
    warnings.append("apktool unavailable or failed; fell back to raw ZIP extraction")
    return extracted_root.resolve(strict=False), warnings


def _find_smali_file(extracted_root: Path, class_name: str, cache: dict[str, str]) -> str:
    normalized = str(class_name or "").strip()
    if not normalized:
        return ""
    if normalized in cache:
        return cache[normalized]
    class_path = Path(*normalized.replace("$", ".").split(".")).with_suffix(".smali")
    for smali_root in sorted(extracted_root.glob("smali*")):
        candidate = smali_root / class_path
        if candidate.exists():
            cache[normalized] = _relative_to(extracted_root, candidate)
            return cache[normalized]
    cache[normalized] = ""
    return ""


def _parse_manifest(
    extracted_root: Path,
    manifest_path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    package_name = str(root.attrib.get("package") or "").strip()
    version_name = _android_attr(root, "versionName")
    version_code = _android_attr(root, "versionCode")
    sdk_elem = root.find("uses-sdk")
    min_sdk = _android_attr(sdk_elem, "minSdkVersion") if sdk_elem is not None else ""
    target_sdk = _android_attr(sdk_elem, "targetSdkVersion") if sdk_elem is not None else ""
    app_elem = root.find("application")
    application_flags = {
        "allow_backup": _android_attr(app_elem, "allowBackup") if app_elem is not None else "",
        "debuggable": _android_attr(app_elem, "debuggable") if app_elem is not None else "",
        "uses_cleartext_traffic": _android_attr(app_elem, "usesCleartextTraffic") if app_elem is not None else "",
        "network_security_config": _android_attr(app_elem, "networkSecurityConfig") if app_elem is not None else "",
    }

    permissions: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []
    url_schemes: list[dict[str, Any]] = []
    providers: list[dict[str, Any]] = []
    smali_cache: dict[str, str] = {}

    for permission in root.findall("permission"):
        permissions.append(
            {
                "surface_type": "permission",
                "name": _android_attr(permission, "name"),
                "class_name": "",
                "file_path": _relative_to(extracted_root, manifest_path),
                "evidence": [f"protectionLevel={_android_attr(permission, 'protectionLevel') or 'unspecified'}"],
                "severity_score": 0.4,
                "tags": ["declared-permission"],
                "metadata": {"protection_level": _android_attr(permission, "protectionLevel")},
            }
        )
    for permission in root.findall("uses-permission"):
        permissions.append(
            {
                "surface_type": "permission",
                "name": _android_attr(permission, "name"),
                "class_name": "",
                "file_path": _relative_to(extracted_root, manifest_path),
                "evidence": ["uses-permission"],
                "severity_score": 0.3,
                "tags": ["uses-permission"],
                "metadata": {"max_sdk_version": _android_attr(permission, "maxSdkVersion")},
            }
        )

    if app_elem is not None:
        component_specs = (
            ("activity", "exported-activity"),
            ("activity-alias", "exported-activity"),
            ("service", "exported-service"),
            ("receiver", "exported-receiver"),
            ("provider", "exported-provider"),
        )
        for tag_name, surface_type in component_specs:
            for element in app_elem.findall(tag_name):
                class_name = _resolve_class_name(package_name, _android_attr(element, "name"))
                exported_attr = _android_attr(element, "exported")
                has_intent_filter = bool(element.findall("intent-filter"))
                exported = exported_attr.lower() == "true" or (not exported_attr and has_intent_filter)
                permission_name = _android_attr(element, "permission")
                intent_actions = [
                    _android_attr(action, "name")
                    for intent_filter in element.findall("intent-filter")
                    for action in intent_filter.findall("action")
                    if _android_attr(action, "name")
                ]
                data_specs: list[dict[str, str]] = []
                for intent_filter in element.findall("intent-filter"):
                    for data in intent_filter.findall("data"):
                        data_specs.append(
                            {
                                "scheme": _android_attr(data, "scheme"),
                                "host": _android_attr(data, "host"),
                                "path": _android_attr(data, "path"),
                                "pathPrefix": _android_attr(data, "pathPrefix"),
                                "pathPattern": _android_attr(data, "pathPattern"),
                            }
                        )
                if exported:
                    component_entry = {
                        "surface_type": surface_type,
                        "component_type": tag_name,
                        "name": class_name,
                        "class_name": class_name,
                        "file_path": _find_smali_file(extracted_root, class_name, smali_cache),
                        "exported": True,
                        "evidence": [f"android:exported={exported_attr or 'implicit-via-intent-filter'}"],
                        "severity_score": 0.8 if tag_name in {"provider", "service"} else 0.65,
                        "tags": [tag_name, "manifest", "exported"],
                        "metadata": {
                            "permission": permission_name,
                            "intent_actions": intent_actions,
                            "data_specs": data_specs,
                        },
                    }
                    components.append(component_entry)
                    if tag_name == "provider":
                        authorities = _android_attr(element, "authorities")
                        provider_entry = dict(component_entry)
                        provider_entry["surface_type"] = "content-provider"
                        provider_entry["metadata"] = {
                            **provider_entry.get("metadata", {}),
                            "authorities": authorities,
                            "grant_uri_permissions": _android_attr(element, "grantUriPermissions"),
                            "read_permission": _android_attr(element, "readPermission"),
                            "write_permission": _android_attr(element, "writePermission"),
                        }
                        providers.append(provider_entry)
                for spec in data_specs:
                    scheme = str(spec.get("scheme") or "").strip()
                    if scheme and scheme not in {"http", "https", "content", "file"}:
                        url_schemes.append(
                            {
                                "surface_type": "url-scheme",
                                "name": scheme,
                                "class_name": class_name,
                                "file_path": _find_smali_file(extracted_root, class_name, smali_cache),
                                "evidence": [
                                    f"host={spec.get('host') or '*'} path={spec.get('path') or spec.get('pathPrefix') or spec.get('pathPattern') or '*'}"
                                ],
                                "severity_score": 0.7,
                                "tags": ["deeplink", "intent-filter"],
                                "metadata": {
                                    "host": spec.get("host"),
                                    "path": spec.get("path"),
                                    "path_prefix": spec.get("pathPrefix"),
                                    "path_pattern": spec.get("pathPattern"),
                                },
                            }
                        )

    meta = {
        "package_name": package_name,
        "version_name": version_name,
        "version_code": version_code,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "application_flags": application_flags,
    }
    return meta, components, url_schemes, permissions, providers


def _class_name_from_smali(rel_path: str) -> str:
    path = Path(rel_path)
    parts = list(path.parts)
    if parts and parts[0].startswith("smali"):
        parts = parts[1:]
    return ".".join(Path(*parts).with_suffix("").parts)


def _scan_with_ripgrep(smali_roots: list[Path], pattern: HintPattern) -> list[dict[str, Any]]:
    if not shutil.which("rg") or not smali_roots:
        return []
    cmd = ["rg", "-n", "-H", "-S", "--glob", "*.smali", "-e", pattern.regex, *[str(item) for item in smali_roots]]
    rc, stdout, stderr = _run(cmd, cwd=smali_roots[0].parent, timeout_seconds=DEFAULT_MAX_RUNTIME_SECONDS)
    if rc not in {0, 1}:
        raise RuntimeError(stderr.strip() or stdout.strip() or f"rg returned {rc}")
    grouped: dict[str, dict[str, Any]] = {}
    for raw_line in stdout.splitlines():
        parts = raw_line.split(":", 2)
        if len(parts) != 3:
            continue
        file_path, line_number, snippet = parts
        rel_path = _relative_to(smali_roots[0].parent, Path(file_path))
        bucket = grouped.setdefault(
            rel_path,
            {
                "surface_type": pattern.key if pattern.category == "smali_hints" else "webview",
                "class_name": _class_name_from_smali(rel_path),
                "file_path": rel_path,
                "evidence": [],
                "severity_score": pattern.severity_score,
                "tags": list(pattern.tags),
                "metadata": {"match_count": 0},
            },
        )
        bucket["metadata"]["match_count"] = int(bucket["metadata"].get("match_count") or 0) + 1
        if len(bucket["evidence"]) < 4:
            bucket["evidence"].append(f"{line_number}: {snippet[:220]}")
    return list(grouped.values())


def _scan_with_python(smali_roots: list[Path], pattern: HintPattern) -> list[dict[str, Any]]:
    compiled = re.compile(pattern.regex)
    grouped: dict[str, dict[str, Any]] = {}
    for root in smali_roots:
        for smali_file in root.rglob("*.smali"):
            try:
                text = smali_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            evidence: list[str] = []
            for idx, line in enumerate(text.splitlines(), start=1):
                if not compiled.search(line):
                    continue
                if len(evidence) < 4:
                    evidence.append(f"{idx}: {line[:220]}")
            if not evidence:
                continue
            rel_path = _relative_to(root.parent, smali_file)
            grouped[rel_path] = {
                "surface_type": pattern.key if pattern.category == "smali_hints" else "webview",
                "class_name": _class_name_from_smali(rel_path),
                "file_path": rel_path,
                "evidence": evidence,
                "severity_score": pattern.severity_score,
                "tags": list(pattern.tags),
                "metadata": {"match_count": len(evidence)},
            }
    return list(grouped.values())


def _scan_smali_hints(extracted_root: Path, logger: SubagentLogger | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    smali_roots = [path for path in sorted(extracted_root.glob("smali*")) if path.is_dir()]
    hints: list[dict[str, Any]] = []
    webview_classes: list[dict[str, Any]] = []
    totals: dict[str, int] = {}
    for pattern in HINT_PATTERNS:
        started = time.time()
        matches = _scan_with_ripgrep(smali_roots, pattern) if shutil.which("rg") else []
        if not matches:
            matches = _scan_with_python(smali_roots, pattern)
        totals[pattern.key] = len(matches)
        if pattern.category == "webview_classes":
            webview_classes.extend(matches)
        else:
            hints.extend(matches)
        response_text = json.dumps({"pattern": pattern.key, "matches": len(matches)})
        _safe_log_span(
            logger,
            span_type="tool",
            phase="prefingerprint",
            level="RESULT",
            message=f"smali hint scan: {pattern.key}",
            tool_name="rg" if shutil.which("rg") else "python-fallback",
            tool_category="apk",
            target=str(extracted_root),
            params={"pattern": pattern.key},
            prompt_tokens=_estimate_tokens(pattern.regex),
            completion_tokens=0,
            context_tokens_before=_estimate_tokens(pattern.regex),
            context_tokens_after=_estimate_tokens(pattern.regex),
            tool_output_tokens=_estimate_tokens(response_text),
            pte_lite=compute_pte_lite(
                prompt_tokens=_estimate_tokens(pattern.regex),
                completion_tokens=0,
                tool_output_tokens=_estimate_tokens(response_text),
                context_tokens_after=_estimate_tokens(pattern.regex),
            ),
            latency_ms=int((time.time() - started) * 1000),
            input_bytes=len(pattern.regex.encode("utf-8", errors="replace")),
            output_bytes=len(response_text.encode("utf-8", errors="replace")),
            success=True,
        )
    return hints, webview_classes, {"smali_hint_counts": totals, "smali_roots": len(smali_roots)}


def build_surface_registry(
    program: str,
    apk_path: str | Path,
    *,
    output_root: str | Path | None = None,
    logger: SubagentLogger | None = None,
) -> dict[str, Any]:
    started = time.time()
    program_slug = _sanitize_program_name(program)
    resolved_apk_path = Path(apk_path).expanduser().resolve(strict=False)
    base_root = (
        Path(output_root).expanduser().resolve(strict=False)
        if output_root is not None
        else Path.home() / "Shared" / "bounty_recon" / program_slug / "apk_team"
    )
    extracted_root = base_root / "extracted"
    registry_path = base_root / "surface_registry.json"

    extracted_root, warnings = _extract_apk(resolved_apk_path, extracted_root, logger)
    manifest_path = _find_manifest(extracted_root)
    manifest_meta, components, url_schemes, permissions, providers = _parse_manifest(extracted_root, manifest_path)
    smali_hints, webview_classes, scan_stats = _scan_smali_hints(extracted_root, logger)

    native_libs: list[dict[str, Any]] = []
    for library in sorted(extracted_root.rglob("*.so")):
        native_libs.append(
            {
                "surface_type": "native-library",
                "name": library.name,
                "class_name": "",
                "file_path": _relative_to(extracted_root, library),
                "evidence": [f"size={library.stat().st_size}"],
                "severity_score": 0.7,
                "tags": ["native", "jni"],
                "metadata": {"size_bytes": library.stat().st_size},
            }
        )

    stats = {
        "component_count": len(components),
        "url_scheme_count": len(url_schemes),
        "permission_count": len(permissions),
        "native_lib_count": len(native_libs),
        "webview_class_count": len(webview_classes),
        "content_provider_count": len(providers),
        "smali_hint_count": len(smali_hints),
        "smali_file_count": sum(1 for _ in extracted_root.glob("smali*/**/*.smali")),
        **scan_stats,
    }
    registry = ApkSurfaceRegistry.create(
        registry_path,
        apk_path=resolved_apk_path,
        extracted_root=extracted_root,
        manifest_path=manifest_path,
        package_name=str(manifest_meta.get("package_name") or ""),
        version_name=str(manifest_meta.get("version_name") or ""),
        version_code=str(manifest_meta.get("version_code") or ""),
        min_sdk=str(manifest_meta.get("min_sdk") or ""),
        target_sdk=str(manifest_meta.get("target_sdk") or ""),
        application_flags=dict(manifest_meta.get("application_flags") or {}),
        stats=stats,
    )
    registry.add_entries("components", components)
    registry.add_entries("url_schemes", url_schemes)
    registry.add_entries("permissions", permissions)
    registry.add_entries("native_libs", native_libs)
    registry.add_entries("webview_classes", webview_classes)
    registry.add_entries("content_providers", providers)
    registry.add_entries("smali_hints", smali_hints)
    registry.save()

    result = {
        "program": program_slug,
        "apk_path": str(resolved_apk_path),
        "extracted_root": str(extracted_root),
        "manifest_path": str(manifest_path),
        "surface_registry_path": str(registry_path),
        "package_name": registry.payload.get("package_name"),
        "version_name": registry.payload.get("version_name"),
        "version_code": registry.payload.get("version_code"),
        "stats": stats,
        "warnings": warnings,
        "elapsed_seconds": round(time.time() - started, 2),
    }
    response_text = json.dumps(result, sort_keys=True)
    _safe_log_span(
        logger,
        span_type="tool",
        phase="prefingerprint",
        level="RESULT",
        message="APK prefingerprint complete",
        tool_name="apk_prefingerprint",
        tool_category="apk",
        target=str(resolved_apk_path),
        params={"surface_registry_path": str(registry_path)},
        prompt_tokens=_estimate_tokens(str(resolved_apk_path)),
        completion_tokens=0,
        context_tokens_before=_estimate_tokens(str(resolved_apk_path)),
        context_tokens_after=_estimate_tokens(str(resolved_apk_path)),
        tool_output_tokens=_estimate_tokens(response_text),
        pte_lite=compute_pte_lite(
            prompt_tokens=_estimate_tokens(str(resolved_apk_path)),
            completion_tokens=0,
            tool_output_tokens=_estimate_tokens(response_text),
            context_tokens_after=_estimate_tokens(str(resolved_apk_path)),
        ),
        latency_ms=int((time.time() - started) * 1000),
        input_bytes=len(str(resolved_apk_path).encode("utf-8", errors="replace")),
        output_bytes=len(response_text.encode("utf-8", errors="replace")),
        success=True,
    )
    return result


def _parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a lightweight APK surface registry.")
    parser.add_argument("program")
    parser.add_argument("apk_path")
    parser.add_argument("--output-root")
    return parser.parse_args(list(argv))


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    logger = None
    if SubagentLogger is not None:
        try:
            logger = SubagentLogger("apk_prefingerprint", _sanitize_program_name(args.program), f"apkpf_{int(time.time())}")
            logger.start(target=str(args.apk_path))
        except Exception:
            logger = None
    result = build_surface_registry(args.program, args.apk_path, output_root=args.output_root, logger=logger)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

