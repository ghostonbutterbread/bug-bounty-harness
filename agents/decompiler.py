"""Normalize binaries and scripts into analyzable source and disassembly trees.

This module is intended to run before agent-based static analysis. It never
executes the target binary; it only copies, extracts, disassembles, or
decompiles using external tools when those tools are available.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterable
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

MAX_TOOL_TIMEOUT_SECONDS = 300
MAX_RECURSION_DEPTH = 3
MAX_FILE_SIZE_BYTES = 500 * 1024 * 1024  # 500 MB — raise if target exceeds this
PRINTABLE_STRING_MIN_LENGTH = 4
TEXT_SAMPLE_BYTES = 8192
MAX_GLOB_FILES = 1000
MAX_GLOB_DEPTH = 20

SCRIPT_SUFFIXES = {
    ".bash",
    ".cjs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".mjs",
    ".php",
    ".pl",
    ".ps1",
    ".py",
    ".rb",
    ".sh",
    ".ts",
    ".tsx",
}

ARCHIVE_SUFFIXES = {
    ".tar",
    ".tar.gz",
    ".tgz",
    ".zip",
}

TOOL_NAMES = (
    "aapt",
    "apktool",
    "bash",
    "cfr",
    "jadx",
    "node",
    "objdump",
    "procyon",
    "procyon-decompiler",
    "r2",
    "ruby",
    "sh",
    "strings",
)

# Root-level build / config file stems that signal a source directory.
_SOURCE_DIR_INDICATORS = frozenset({
    "Makefile", "CMakeLists.txt", "build.rs", "setup.py", "pyproject.toml",
    "Cargo.toml", "go.mod", "go.sum", "Package.swift", "Cargo.lock",
    "Pipfile", "requirements.txt", "setup.cfg", "tox.ini", "justfile",
    "meson.build", "build.gradle", "pom.xml", "build.xml", "composer.json",
    "package.json", "webpack.config", "vite.config", "Dockerfile",
})


def discover_tools() -> dict[str, str]:
    """Return a map of known tool names to executable paths."""
    discovered: dict[str, str] = {}
    for tool in TOOL_NAMES:
        path = shutil.which(tool)
        if path:
            discovered[tool] = path
    return discovered


TOOL_PATHS = discover_tools()


@dataclass
class HandlerResult:
    warnings: list[str] = field(default_factory=list)
    log_lines: list[str] = field(default_factory=list)
    used_tools: list[str] = field(default_factory=list)

    def merge(self, other: "HandlerResult", prefix: str | None = None) -> None:
        self.warnings.extend(other.warnings)
        self.used_tools.extend(other.used_tools)
        if prefix:
            self.log_lines.extend(f"{prefix}{line}" for line in other.log_lines)
        else:
            self.log_lines.extend(other.log_lines)


def run_tool(cmd: list[str], cwd: Path) -> tuple[int, str, str]:
    """Run a tool safely with capture and timeout.

    The target under analysis is never executed directly. Only analysis tools
    listed by the caller should be passed here.
    """
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=MAX_TOOL_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return 127, "", f"Tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
        return 124, stdout, f"Timed out after {MAX_TOOL_TIMEOUT_SECONDS}s. {stderr}".strip()
    except OSError as exc:
        return 1, "", str(exc)

    return completed.returncode, completed.stdout, completed.stderr


def detect_type(path: Path | str) -> str:
    """Detect target type using extension, archive contents, and magic bytes."""
    if isinstance(path, str):
        path = Path(path)
    if path.is_dir():
        return "directory"

    lowered_name = path.name.lower()
    suffixes = "".join(path.suffixes).lower()
    head = _read_prefix(path, 4096)

    if lowered_name.endswith(".tar.gz") or lowered_name.endswith(".tgz"):
        return "archive"
    if lowered_name.endswith(".apk"):
        return "apk"
    if lowered_name.endswith(".aab"):
        return "aab"
    if lowered_name.endswith(".jar"):
        return "jar"
    if lowered_name.endswith(".dmg"):
        return "dmg"
    if lowered_name.endswith(".zip") or lowered_name.endswith(".tar"):
        return "archive"
    if path.suffix.lower() == ".elf":
        return "elf"
    if path.suffix.lower() == ".exe":
        return "pe"
    if path.suffix.lower() in SCRIPT_SUFFIXES:
        return "script"

    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"MZ"):
        return "pe"
    if _looks_like_zip(path, head):
        zip_type = _classify_zip_container(path)
        if zip_type:
            return zip_type
        return "archive"
    if tarfile.is_tarfile(path):
        return "archive"
    if head.startswith(b"#!") or _is_probably_text(path):
        return "script"
    if suffixes in ARCHIVE_SUFFIXES:
        return "archive"

    return "unknown"


def decompile(target: str | Path, output_dir: Path | str | None = None) -> tuple[Path, list[str]]:
    """Normalize a target into a directory tree usable by zero-day agents."""
    if isinstance(target, str) and _is_url(target):
        dest: Path | str = output_dir or _default_output_dir_for_url(target)
        return download_and_decompile(target, dest if isinstance(dest, Path) else Path(dest))

    path = Path(target).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(path)

    if path.is_dir():
        return _handle_directory_target(path, output_dir if isinstance(output_dir, Path) else (Path(output_dir) if output_dir else None))

    detected_type = detect_type(path)
    destination: Path | str = output_dir or _default_output_dir_for_path(path)
    if isinstance(destination, str):
        destination = Path(destination)
    _ensure_output_tree(destination)

    result = HandlerResult()
    result.log_lines.extend(_tool_discovery_log_lines())
    result.log_lines.append(f"Started: {_utc_now()}")
    result.log_lines.append(f"Target: {path}")
    result.log_lines.append(f"Detected type: {detected_type}")

    _write_metadata(path, destination, detected_type)

    dispatch_result = _dispatch_target(path, destination, detected_type=detected_type, depth=0)
    result.merge(dispatch_result)

    _write_type_manifest(
        destination,
        target=path,
        detected_type=detected_type,
        used_tools=result.used_tools,
        warnings=result.warnings,
    )
    _write_tool_versions(destination, result.used_tools)
    result.log_lines.append(f"Finished: {_utc_now()}")
    _write_decompile_log(destination, result.log_lines, result.warnings)

    return destination, result.warnings


def decompile_apk(path: Path, out: Path) -> HandlerResult:
    """Decompile or extract an Android APK or AAB bundle."""
    result = HandlerResult()
    source_dir = out / "source"
    apktool_out = source_dir / "apktool"
    jadx_out = source_dir / "jadx"
    unzip_out = source_dir / "apk_unpacked"

    if "apktool" in TOOL_PATHS:
        cmd = [TOOL_PATHS["apktool"], "d", "-f", "-o", str(apktool_out), str(path)]
        rc, stdout, stderr = run_tool(cmd, out)
        result.log_lines.append(_format_tool_attempt("apktool", cmd, rc, stdout, stderr))
        if rc == 0:
            result.used_tools.append("apktool")
            manifest = apktool_out / "AndroidManifest.xml"
            if manifest.exists():
                shutil.copy2(manifest, source_dir / "AndroidManifest.xml")
        else:
            result.warnings.append(f"apktool failed for {path.name}; falling back to archive extraction.")
    else:
        result.warnings.append("apktool not installed; falling back to archive extraction for APK.")

    if "jadx" in TOOL_PATHS:
        cmd = [TOOL_PATHS["jadx"], "-d", str(jadx_out), str(path)]
        rc, stdout, stderr = run_tool(cmd, out)
        result.log_lines.append(_format_tool_attempt("jadx", cmd, rc, stdout, stderr))
        if rc == 0:
            result.used_tools.append("jadx")
        else:
            result.warnings.append(f"jadx failed for {path.name}; Smali/resources may be the best available output.")
    else:
        result.warnings.append("jadx not installed; Java-like source output for APKs may be unavailable.")

    if not apktool_out.exists():
        fallback = _extract_zip_archive(path, unzip_out)
        result.merge(fallback)

    manifest_plaintext = source_dir / "AndroidManifest.txt"
    if "aapt" in TOOL_PATHS:
        cmd = [TOOL_PATHS["aapt"], "dump", "xmltree", str(path), "AndroidManifest.xml"]
        rc, stdout, stderr = run_tool(cmd, out)
        result.log_lines.append(_format_tool_attempt("aapt", cmd, rc, stdout, stderr))
        if rc == 0 and stdout.strip():
            manifest_plaintext.write_text(stdout, encoding="utf-8")
            result.used_tools.append("aapt")
    elif not (source_dir / "AndroidManifest.xml").exists():
        result.warnings.append("Plaintext AndroidManifest extraction is limited without apktool or aapt.")

    for dex_path in _find_matching_files(source_dir, {".dex"}):
        strings_out = out / "strings" / dex_path.with_suffix(".strings.txt").name
        _write_strings_file(dex_path, strings_out, result)

    return result


def decompile_elf(path: Path, out: Path) -> HandlerResult:
    """Disassemble an ELF binary for static analysis."""
    result = HandlerResult()
    stem = _safe_name(path.name)
    disasm_dir = out / "disasm"

    if "objdump" in TOOL_PATHS:
        disasm_cmd = [TOOL_PATHS["objdump"], "-d", str(path)]
        rc, stdout, stderr = run_tool(disasm_cmd, out)
        (disasm_dir / f"{stem}.objdump.asm").write_text(stdout or stderr, encoding="utf-8")
        result.log_lines.append(_format_tool_attempt("objdump", disasm_cmd, rc, stdout, stderr))
        if rc == 0:
            if "objdump" not in result.used_tools:
                result.used_tools.append("objdump")
        else:
            result.warnings.append(f"objdump -d failed for {path.name}.")

        dynsym_cmd = [TOOL_PATHS["objdump"], "-T", str(path)]
        rc, stdout, stderr = run_tool(dynsym_cmd, out)
        dynsym_out = stdout if rc == 0 else stderr
        (disasm_dir / f"{stem}.dynamic_symbols.txt").write_text(dynsym_out, encoding="utf-8")
        result.log_lines.append(_format_tool_attempt("objdump", dynsym_cmd, rc, stdout, stderr))
        if rc == 0 and "objdump" not in result.used_tools:
            result.used_tools.append("objdump")

        sections_cmd = [TOOL_PATHS["objdump"], "-s", str(path)]
        rc, stdout, stderr = run_tool(sections_cmd, out)
        (disasm_dir / f"{stem}.section_dump.txt").write_text(stdout or stderr, encoding="utf-8")
        result.log_lines.append(_format_tool_attempt("objdump", sections_cmd, rc, stdout, stderr))
        if rc == 0 and "objdump" not in result.used_tools:
            result.used_tools.append("objdump")
    else:
        result.warnings.append("objdump not installed; ELF output will be limited to string extraction.")

    if "r2" in TOOL_PATHS:
        r2_cmd = [TOOL_PATHS["r2"], "-q", "-c", "aaa;afl;ii;iz;q", str(path)]
        rc, stdout, stderr = run_tool(r2_cmd, out)
        (disasm_dir / f"{stem}.radare2.txt").write_text(stdout or stderr, encoding="utf-8")
        result.log_lines.append(_format_tool_attempt("r2", r2_cmd, rc, stdout, stderr))
        if rc == 0:
            result.used_tools.append("r2")
        else:
            result.warnings.append(f"radare2 analysis failed for {path.name}.")
    else:
        result.warnings.append("radare2 not installed; deep binary analysis is unavailable.")

    extract_strings(path, out / "strings")
    return result


def decompile_pe(path: Path, out: Path) -> HandlerResult:
    """Disassemble a PE/Windows executable for static analysis."""
    result = HandlerResult()
    stem = _safe_name(path.name)
    disasm_dir = out / "disasm"

    if "objdump" in TOOL_PATHS:
        disasm_cmd = [TOOL_PATHS["objdump"], "-d", str(path)]
        rc, stdout, stderr = run_tool(disasm_cmd, out)
        (disasm_dir / f"{stem}.objdump.asm").write_text(stdout or stderr, encoding="utf-8")
        result.log_lines.append(_format_tool_attempt("objdump", disasm_cmd, rc, stdout, stderr))
        if rc == 0:
            if "objdump" not in result.used_tools:
                result.used_tools.append("objdump")
        else:
            result.warnings.append(f"objdump -d failed for {path.name}.")

        peinfo_cmd = [TOOL_PATHS["objdump"], "-x", str(path)]
        rc, stdout, stderr = run_tool(peinfo_cmd, out)
        (disasm_dir / f"{stem}.headers_and_symbols.txt").write_text(stdout or stderr, encoding="utf-8")
        result.log_lines.append(_format_tool_attempt("objdump", peinfo_cmd, rc, stdout, stderr))
        if rc == 0 and "objdump" not in result.used_tools:
            result.used_tools.append("objdump")

        sections_cmd = [TOOL_PATHS["objdump"], "-s", str(path)]
        rc, stdout, stderr = run_tool(sections_cmd, out)
        (disasm_dir / f"{stem}.section_dump.txt").write_text(stdout or stderr, encoding="utf-8")
        result.log_lines.append(_format_tool_attempt("objdump", sections_cmd, rc, stdout, stderr))
        if rc == 0 and "objdump" not in result.used_tools:
            result.used_tools.append("objdump")
    else:
        result.warnings.append("objdump not installed; PE output will be limited to string extraction.")

    if "r2" in TOOL_PATHS:
        r2_cmd = [TOOL_PATHS["r2"], "-q", "-c", "aaa;afl;ii;iz;q", str(path)]
        rc, stdout, stderr = run_tool(r2_cmd, out)
        (disasm_dir / f"{stem}.radare2.txt").write_text(stdout or stderr, encoding="utf-8")
        result.log_lines.append(_format_tool_attempt("r2", r2_cmd, rc, stdout, stderr))
        if rc == 0:
            result.used_tools.append("r2")
        else:
            result.warnings.append(f"radare2 analysis failed for {path.name}.")
    else:
        result.warnings.append("radare2 not installed; deep binary analysis is unavailable.")

    extract_strings(path, out / "strings")
    return result


def decompile_script(path: Path, out: Path) -> HandlerResult:
    """Copy a script into source/ and validate syntax when possible."""
    result = HandlerResult()
    source_dir = out / "source"
    destination = source_dir / path.name
    shutil.copy2(path, destination)
    result.log_lines.append(f"Copied script source to {destination}")

    validation_message = _validate_script(destination)
    result.log_lines.append(validation_message)
    if validation_message.startswith("Validation warning"):
        result.warnings.append(validation_message)

    return result


def extract_strings(path: Path, out: Path) -> Path:
    """Extract printable strings from a binary or packed file."""
    out.mkdir(parents=True, exist_ok=True)
    destination = out / f"{_safe_name(path.name)}.strings.txt"
    result = HandlerResult()
    _write_strings_file(path, destination, result)
    return destination


def download_and_decompile(url: str, out: Path) -> tuple[Path, list[str]]:
    """Download a remote artifact to a temp file and decompile it safely."""
    parsed = urlparse(url)
    original_url = url
    filename = Path(unquote(parsed.path)).name or "downloaded.bin"

    with tempfile.TemporaryDirectory(prefix="decompile_download_") as tmpdir:
        temp_path = Path(tmpdir) / filename
        request = Request(url, headers={"User-Agent": "bug-bounty-harness/decompiler"})
        try:
            with urlopen(request, timeout=60) as response:
                final_url = response.geturl()
                # Defend against redirect to file:// or an arbitrary host.
                final_parsed = urlparse(final_url)
                original_parsed = urlparse(original_url)
                if not final_url.startswith(original_parsed.scheme + "://"):
                    raise ValueError(
                        f"Download redirected from {original_url} to {final_url} — "
                        "refusing to follow off-origin redirect"
                    )
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > MAX_FILE_SIZE_BYTES:
                    raise ValueError(
                        f"Remote file size {content_length} exceeds limit "
                        f"{MAX_FILE_SIZE_BYTES}; aborting download"
                    )
                bytes_written = 0
                with temp_path.open("wb") as handle:
                    while True:
                        chunk = response.read(1024 * 1024)  # 1 MB at a time
                        if not chunk:
                            break
                        bytes_written += len(chunk)
                        if bytes_written > MAX_FILE_SIZE_BYTES:
                            raise ValueError(
                                f"Download exceeded {MAX_FILE_SIZE_BYTES} bytes; aborting"
                            )
                        handle.write(chunk)
        except Exception as exc:
            # Re-raise so decompile() never processes a partially-downloaded file.
            raise RuntimeError(f"download_and_decompile failed for {url}: {exc}") from exc

        return decompile(temp_path, output_dir=out)


def _dispatch_target(path: Path, out: Path, detected_type: str | None = None, depth: int = 0) -> HandlerResult:
    detected = detected_type or detect_type(path)
    result = HandlerResult()

    if depth > MAX_RECURSION_DEPTH:
        result.warnings.append(f"Maximum archive recursion depth reached at {path}.")
        result.log_lines.append(f"Skipped nested target beyond recursion limit: {path}")
        return result

    if detected in {"apk", "aab"}:
        return decompile_apk(path, out)
    if detected == "elf":
        return decompile_elf(path, out)
    if detected == "pe":
        return decompile_pe(path, out)
    if detected == "script":
        return decompile_script(path, out)
    if detected == "jar":
        return _decompile_jar(path, out)
    if detected == "dmg":
        return _decompile_dmg(path, out)
    if detected == "archive":
        return _decompile_archive(path, out, depth)

    copied_target = out / "source" / path.name
    shutil.copy2(path, copied_target)
    result.warnings.append(f"Unknown type for {path.name}; copied as-is for manual analysis.")
    result.log_lines.append(f"Copied unknown target to {copied_target}")
    return result


def _decompile_jar(path: Path, out: Path) -> HandlerResult:
    result = HandlerResult()
    source_dir = out / "source"
    jar_out = source_dir / "jar_unpacked"
    extract_result = _extract_zip_archive(path, jar_out)
    result.merge(extract_result)

    decompiled = False
    if "cfr" in TOOL_PATHS:
        cfr_out = source_dir / "cfr"
        cfr_out.mkdir(parents=True, exist_ok=True)
        cmd = [TOOL_PATHS["cfr"], str(path), "--outputdir", str(cfr_out)]
        rc, stdout, stderr = run_tool(cmd, out)
        result.log_lines.append(_format_tool_attempt("cfr", cmd, rc, stdout, stderr))
        if rc == 0:
            result.used_tools.append("cfr")
            decompiled = True

    if not decompiled:
        procyon_tool = TOOL_PATHS.get("procyon") or TOOL_PATHS.get("procyon-decompiler")
        if procyon_tool:
            procyon_out = source_dir / "procyon"
            procyon_out.mkdir(parents=True, exist_ok=True)
            attempts = [
                [procyon_tool, "-jar", str(path), "-o", str(procyon_out)],
                [procyon_tool, str(path), "-o", str(procyon_out)],
            ]
            for cmd in attempts:
                rc, stdout, stderr = run_tool(cmd, out)
                result.log_lines.append(_format_tool_attempt(Path(procyon_tool).name, cmd, rc, stdout, stderr))
                if rc == 0:
                    result.used_tools.append(Path(procyon_tool).name)
                    decompiled = True
                    break

    if not decompiled:
        result.warnings.append("No working Java decompiler found for JAR; using extracted classes/resources only.")

    for class_file in _find_matching_files(jar_out, {".class"}):
        strings_out = out / "strings" / f"{_safe_name(class_file.name)}.strings.txt"
        _write_strings_file(class_file, strings_out, result)

    return result


def _decompile_dmg(path: Path, out: Path) -> HandlerResult:
    result = HandlerResult()
    source_copy = out / "source" / path.name
    shutil.copy2(path, source_copy)
    result.warnings.append("DMG copied as-is. Mount or inspect manually on macOS-compatible tooling.")
    result.log_lines.append(f"Copied DMG for manual analysis: {source_copy}")
    return result


def _decompile_archive(path: Path, out: Path, depth: int) -> HandlerResult:
    result = HandlerResult()
    extract_root = out / "source" / "archive_contents"
    extract_root.mkdir(parents=True, exist_ok=True)

    if _looks_like_zip(path):
        extract_result = _extract_zip_archive(path, extract_root)
    elif tarfile.is_tarfile(path):
        extract_result = _extract_tar_archive(path, extract_root)
    else:
        result.warnings.append(f"Archive type for {path.name} is not supported by stdlib extractors.")
        result.log_lines.append(f"Archive extraction skipped for unsupported format: {path}")
        return result

    result.merge(extract_result)

    nested_root = out / "nested"
    for child in sorted(extract_root.rglob("*")):
        if not child.is_file():
            continue

        child_type = detect_type(child)
        if child_type in {"directory", "unknown", "script"}:
            if child_type == "script":
                rel = _safe_relative_path(child, extract_root)
                destination = out / "source" / "archive_scripts" / rel
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(child, destination)
            continue

        nested_out = nested_root / _safe_name(_safe_relative_path(child, extract_root).as_posix())
        _ensure_output_tree(nested_out)
        nested_result = _dispatch_target(child, nested_out, detected_type=child_type, depth=depth + 1)
        result.merge(nested_result, prefix=f"[nested {child.name}] ")

    return result


def _extract_zip_archive(path: Path, destination: Path) -> HandlerResult:
    result = HandlerResult()
    destination.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                safe = _safe_archive_member(member.filename, destination)
                if safe is None:
                    result.warnings.append(f"Blocked unsafe archive path: {member.filename}")
                    continue
                target_path = destination / safe
                if member.is_dir():
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue

                target_path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member, "r") as source, target_path.open("wb") as target:
                    shutil.copyfileobj(source, target)
    except (zipfile.BadZipFile, OSError) as exc:
        result.warnings.append(f"Failed to extract ZIP archive {path.name}: {exc}")
        result.log_lines.append(f"ZIP extraction failed for {path}: {exc}")
        return result

    result.log_lines.append(f"Extracted ZIP archive to {destination}")
    return result


def _extract_tar_archive(path: Path, destination: Path) -> HandlerResult:
    result = HandlerResult()
    destination.mkdir(parents=True, exist_ok=True)

    try:
        with tarfile.open(path) as archive:
            for member in archive.getmembers():
                safe = _safe_archive_member(member.name, destination)
                if safe is None:
                    result.warnings.append(f"Blocked unsafe tar member: {member.name}")
                    continue
                member_path = destination / safe
                if member.isdir():
                    member_path.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    result.log_lines.append(f"Skipped non-regular tar member: {member.name}")
                    continue

                member_path.parent.mkdir(parents=True, exist_ok=True)
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                with extracted, member_path.open("wb") as handle:
                    shutil.copyfileobj(extracted, handle)
    except (tarfile.TarError, OSError) as exc:
        result.warnings.append(f"Failed to extract TAR archive {path.name}: {exc}")
        result.log_lines.append(f"TAR extraction failed for {path}: {exc}")
        return result

    result.log_lines.append(f"Extracted TAR archive to {destination}")
    return result


def _handle_directory_target(path: Path, output_dir: Path | None) -> tuple[Path, list[str]]:
    warning = "Target is already a directory; skipping decompilation."
    if _looks_like_source_directory(path):
        warning = "Target already appears to be source code; skipping decompilation."

    if output_dir:
        _ensure_output_tree(output_dir)
        manifest_warning = [warning]
        _write_type_manifest(
            output_dir,
            target=path,
            detected_type="directory",
            used_tools=[],
            warnings=manifest_warning,
        )
        _write_decompile_log(output_dir, [f"Skipped directory target: {path}"], manifest_warning)
        return output_dir, manifest_warning

    return path, [warning]


def _write_metadata(path: Path, out: Path, detected_type: str) -> None:
    metadata_dir = out / "metadata"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    info_path = metadata_dir / "file_info.txt"
    info_path.write_text(
        "\n".join([
            f"target={path}",
            f"type={detected_type}",
            f"size_bytes={path.stat().st_size}",
            f"sha256={_hash_file(path, 'sha256')}",
            f"sha1={_hash_file(path, 'sha1')}",
            f"md5={_hash_file(path, 'md5')}",
            f"generated_utc={_utc_now()}",
        ])
        + "\n",
        encoding="utf-8",
    )


def _write_type_manifest(
    out: Path,
    target: Path,
    detected_type: str,
    used_tools: Iterable[str],
    warnings: Iterable[str],
) -> None:
    manifest = out / "type_manifest.txt"
    lines = [
        f"target={target}",
        f"detected_type={detected_type}",
        f"generated_utc={_utc_now()}",
        f"tools_used={', '.join(sorted(dict.fromkeys(used_tools))) or 'none'}",
    ]
    warning_list = list(warnings)
    if warning_list:
        lines.append("warnings=")
        lines.extend(f"- {warning}" for warning in warning_list)

    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_decompile_log(out: Path, log_lines: Iterable[str], warnings: Iterable[str]) -> None:
    lines = list(log_lines)
    warning_list = list(warnings)
    if warning_list:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in warning_list)
    (out / "decompile_log.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_tool_versions(out: Path, used_tools: Iterable[str]) -> None:
    tool_versions = out / "metadata" / "tool_versions.txt"
    lines: list[str] = []

    for tool_name in sorted(dict.fromkeys(used_tools)):
        executable = TOOL_PATHS.get(tool_name)
        if not executable:
            continue

        version = _get_tool_version(tool_name, executable)
        lines.append(f"{tool_name}={version}")

    if not lines:
        lines.append("No external tools recorded.")

    tool_versions.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_strings_file(path: Path, destination: Path, result: HandlerResult) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)

    if "strings" in TOOL_PATHS:
        cmd = [TOOL_PATHS["strings"], "-a", str(path)]
        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(destination.parent),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = proc.communicate(timeout=MAX_TOOL_TIMEOUT_SECONDS)
            rc = proc.returncode
        except subprocess.TimeoutExpired as exc:
            if proc:
                proc.kill()
                proc.wait()
            result.warnings.append(f"strings timed out for {path.name}; skipping")
            result.log_lines.append(f"strings timeout for {path}")
            return
        except OSError as exc:
            result.warnings.append(f"strings invocation failed for {path.name}: {exc}")
            result.log_lines.append(f"strings OSError for {path}: {exc}")
            return
        finally:
            # Ensure handles are fully closed even on unexpected errors.
            if proc is not None and proc.stdout is not None:
                proc.stdout.close()
            if proc is not None and proc.stderr is not None:
                proc.stderr.close()

        result.log_lines.append(_format_tool_attempt("strings", cmd, rc, stdout, stderr))
        if rc == 0 and stdout:
            destination.write_text(stdout, encoding="utf-8")
            result.used_tools.append("strings")
            return

    content = path.read_bytes()
    strings = _extract_printable_strings(content)
    destination.write_text("\n".join(strings) + ("\n" if strings else ""), encoding="utf-8")
    result.log_lines.append(f"Extracted strings with builtin fallback to {destination}")


def _extract_printable_strings(data: bytes) -> list[str]:
    seen: dict[str, None] = {}
    ascii_matches = re.findall(rb"[\x20-\x7e]{%d,}" % PRINTABLE_STRING_MIN_LENGTH, data)
    for match in ascii_matches:
        decoded = match.decode("utf-8", "replace")
        if decoded not in seen:
            seen[decoded] = None
            if len(seen) >= 20:  # Enough for source detection; stop scanning.
                return list(seen.keys())

    utf16_matches = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % PRINTABLE_STRING_MIN_LENGTH, data)
    for match in utf16_matches:
        decoded = match.decode("utf-16le", "replace")
        if decoded not in seen:
            seen[decoded] = None
            if len(seen) >= 20:
                return list(seen.keys())

    return list(seen.keys())


def _validate_script(path: Path) -> str:
    suffix = path.suffix.lower()

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(encoding="utf-8", errors="replace")

    if suffix == ".py":
        try:
            ast.parse(text, filename=str(path))
            return f"Validated Python syntax for {path.name}"
        except SyntaxError as exc:
            return f"Validation warning: Python syntax error in {path.name}: {exc}"

    if suffix in {".sh", ".bash"}:
        shell_name = "bash" if suffix == ".bash" and "bash" in TOOL_PATHS else "sh"
        executable = TOOL_PATHS.get(shell_name)
        if executable:
            rc, _stdout, stderr = run_tool([executable, "-n", str(path)], path.parent)
            if rc == 0:
                return f"Validated shell syntax for {path.name} with {shell_name}"
            return f"Validation warning: shell syntax check failed for {path.name}: {stderr.strip() or 'unknown error'}"
        return f"Validation warning: no shell syntax checker available for {path.name}"

    if suffix in {".js", ".cjs", ".mjs"} and "node" in TOOL_PATHS:
        rc, _stdout, stderr = run_tool([TOOL_PATHS["node"], "--check", str(path)], path.parent)
        if rc == 0:
            return f"Validated JavaScript syntax for {path.name} with node --check"
        return f"Validation warning: JavaScript syntax check failed for {path.name}: {stderr.strip() or 'unknown error'}"

    if suffix == ".rb" and "ruby" in TOOL_PATHS:
        rc, _stdout, stderr = run_tool([TOOL_PATHS["ruby"], "-c", str(path)], path.parent)
        if rc == 0:
            return f"Validated Ruby syntax for {path.name} with ruby -c"
        return f"Validation warning: Ruby syntax check failed for {path.name}: {stderr.strip() or 'unknown error'}"

    return f"Validation warning: no parser configured for {path.name}; copied as plaintext source."


def _tool_discovery_log_lines() -> list[str]:
    lines = ["Tool discovery:"]
    for tool_name in TOOL_NAMES:
        executable = TOOL_PATHS.get(tool_name)
        if executable:
            lines.append(f"- {tool_name}: {executable}")
        else:
            lines.append(f"- {tool_name}: missing")
    return lines


def _get_tool_version(tool_name: str, executable: str) -> str:
    version_commands = {
        "aapt": [executable, "version"],
        "apktool": [executable, "--version"],
        "bash": [executable, "--version"],
        "cfr": [executable, "--version"],
        "jadx": [executable, "--version"],
        "node": [executable, "--version"],
        "objdump": [executable, "--version"],
        "procyon": [executable, "--version"],
        "procyon-decompiler": [executable, "--version"],
        "r2": [executable, "-v"],
        "ruby": [executable, "--version"],
        "sh": [executable, "--version"],
        "strings": [executable, "--version"],
    }

    cmd = version_commands.get(tool_name)
    if not cmd:
        return executable

    rc, stdout, stderr = run_tool(cmd, Path.cwd())
    raw = stdout.strip() or stderr.strip()
    if rc == 0 and raw:
        return raw.splitlines()[0]
    return executable


def _format_tool_attempt(tool_name: str, cmd: list[str], rc: int, stdout: str, stderr: str) -> str:
    summary = stderr.strip() or stdout.strip()
    summary = summary.splitlines()[0] if summary else "no output"
    return f"{tool_name} rc={rc} cmd={' '.join(cmd)} summary={summary}"


def _hash_file(path: Path, algorithm: str) -> str:
    size = path.stat().st_size
    if size > MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"File {path} is {size} bytes (>{MAX_FILE_SIZE_BYTES}); "
            "hashing very large files is not supported"
        )
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _looks_like_zip(path: Path, head: bytes | None = None) -> bool:
    head = head if head is not None else _read_prefix(path, 4)
    return head.startswith(b"PK\x03\x04") or zipfile.is_zipfile(path)


def _classify_zip_container(path: Path) -> str | None:
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
    except (zipfile.BadZipFile, OSError):
        return None

    if "AndroidManifest.xml" in names and any(name.endswith(".dex") for name in names):
        return "apk"
    if "META-INF/MANIFEST.MF" in names and any(name.endswith(".class") for name in names):
        return "jar"
    return None


def _looks_like_source_directory(path: Path) -> bool:
    source_files = 0
    checked = 0
    try:
        for child, _ in _safe_scandir(path, depth=0):
            checked += 1
            if checked > MAX_GLOB_FILES:
                return False
            # Root-level build-file indicators.
            if child.is_file():
                stem = child.name
                if stem in _SOURCE_DIR_INDICATORS:
                    return True
                if child.suffix.lower() in SCRIPT_SUFFIXES:
                    source_files += 1
                    if source_files >= 3:
                        return True
    except OSError:
        return False
    return False


def _safe_scandir(
    root: Path, depth: int = 0
) -> Iterable[tuple[Path, "os.DirEntry[str]"]]:
    """Like scandir/tree but respects MAX_GLOB_DEPTH and MAX_GLOB_FILES, and
    skips directories that raise OSError (permissions, symlink loops, etc.)."""
    if depth > MAX_GLOB_DEPTH:
        return
    try:
        entries = list(os.scandir(root))
    except OSError:
        return

    for entry in entries:
        yield Path(entry.path), entry
        if entry.is_dir(follow_symlinks=False):
            yield from _safe_scandir(Path(entry.path), depth=depth + 1)


def _find_matching_files(root: Path, suffixes: set[str]) -> list[Path]:
    matches: list[Path] = []
    for child, _ in _safe_scandir(root):
        if child.is_file() and child.suffix.lower() in suffixes:
            matches.append(child)
            if len(matches) >= MAX_GLOB_FILES:
                break
    return matches


def _safe_archive_member(name: str, destination: Path) -> Path | None:
    """Return a safe relative path for an archive member, or None if unsafe.

    Blocks:
    - Absolute POSIX paths (/etc/passwd)
    - Windows absolute paths (C:\\Users\\evil, \\\\UNC\\share)
    - Traversal sequences (..) that would escape the destination
    - Paths that resolve outside `destination` after normalization
    """
    # Normalize both slash styles to forward slash for uniform handling.
    normalized = name.replace("\\", "/")

    # --- Windows absolute paths ---
    # e.g. C:/Users/evil, C:\Windows\System32, \\\\UNC\\share\\file
    if re.match(r"^[A-Za-z]:[/\\]|^[\\/]{2}", normalized):
        return None

    # --- Absolute POSIX path (starts with /) ---
    if normalized.startswith("/"):
        return None

    # --- Build candidate and check it doesn't escape destination ---
    # Join with destination to produce an absolute on-disk path, then
    # resolve any ".." segments and verify the result is still inside destination.
    dest_abs = destination.resolve()
    joined = (dest_abs / normalized).resolve()

    try:
        joined.relative_to(dest_abs)
    except ValueError:
        # Resolved path is outside destination — blocked.
        return None

    # Strip the destination prefix.
    try:
        relative = joined.relative_to(dest_abs)
    except ValueError:
        return Path("unnamed")

    # Remove residual "." and ".." parts.
    parts = [p for p in relative.parts if p not in {".", ".."}]
    if not parts:
        return Path("unnamed")
    return Path(*parts)


def _safe_relative_path(path: Path, base: Path) -> Path:
    safe = _safe_archive_member(path.relative_to(base).as_posix(), base)
    # _safe_archive_member returns None only for pathological cases;
    # in that event fall back to the name only.
    return safe if safe is not None else Path(path.name)


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "artifact"


def _read_prefix(path: Path, size: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


def _is_probably_text(path: Path) -> bool:
    try:
        sample = _read_prefix(path, TEXT_SAMPLE_BYTES)
    except OSError:
        return False

    if not sample:
        return True
    if b"\x00" in sample:
        return False

    text_chars = sum(1 for byte in sample if 32 <= byte <= 126 or byte in {9, 10, 13})
    return (text_chars / len(sample)) >= 0.85


def _default_output_dir_for_path(path: Path) -> Path:
    stem = _strip_known_suffixes(path.name)
    candidate = path.parent / f"{stem}_decompiled"
    return _dedupe_output_dir(candidate)


def _default_output_dir_for_url(url: str) -> Path:
    parsed = urlparse(url)
    name = Path(unquote(parsed.path)).name or "downloaded"
    candidate = Path.cwd() / f"{_strip_known_suffixes(name)}_decompiled"
    return _dedupe_output_dir(candidate)


def _dedupe_output_dir(path: Path) -> Path:
    if not path.exists():
        return path

    index = 2
    while True:
        candidate = path.with_name(f"{path.name}_{index}")
        if not candidate.exists():
            return candidate
        index += 1


def _strip_known_suffixes(name: str) -> str:
    lowered = name.lower()
    for suffix in sorted(ARCHIVE_SUFFIXES | {".apk", ".aab", ".jar", ".dmg", ".elf", ".exe"}, key=len, reverse=True):
        if lowered.endswith(suffix):
            return name[: -len(suffix)] or "artifact"
    return Path(name).stem or "artifact"


def _ensure_output_tree(out: Path | str) -> None:
    if isinstance(out, str):
        out = Path(out)
    for child in ("source", "disasm", "strings", "metadata"):
        (out / child).mkdir(parents=True, exist_ok=True)


def _is_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
