"""Lightweight progressive surface registry for APK hunts."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _dedupe_strings(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        ordered.append(text)
    return ordered


def _package_prefix(class_name: str) -> str:
    parts = [part for part in str(class_name or "").strip().split(".") if part]
    if len(parts) <= 1:
        return ""
    return ".".join(parts[:-1])


class ApkSurfaceRegistry:
    """JSON-backed store for APK attack-surface discovery."""

    CATEGORY_KEYS = (
        "components",
        "url_schemes",
        "permissions",
        "native_libs",
        "webview_classes",
        "content_providers",
        "smali_hints",
    )

    def __init__(self, registry_path: str | Path, payload: dict[str, Any] | None = None):
        self.registry_path = Path(registry_path).expanduser().resolve(strict=False)
        base_payload: dict[str, Any] = {
            "created_at": _now_iso(),
            "updated_at": _now_iso(),
            "apk_path": "",
            "extracted_root": "",
            "manifest_path": "",
            "package_name": "",
            "version_name": "",
            "version_code": "",
            "min_sdk": "",
            "target_sdk": "",
            "application_flags": {},
            "stats": {},
            "entries": [],
            "expansions": [],
            "progressive_findings": [],
        }
        for key in self.CATEGORY_KEYS:
            base_payload[key] = []
        if payload:
            for key, value in payload.items():
                base_payload[key] = value
        self.payload = base_payload

    @classmethod
    def create(
        cls,
        registry_path: str | Path,
        *,
        apk_path: str | Path,
        extracted_root: str | Path,
        manifest_path: str | Path = "",
        package_name: str = "",
        version_name: str = "",
        version_code: str = "",
        min_sdk: str = "",
        target_sdk: str = "",
        application_flags: dict[str, Any] | None = None,
        stats: dict[str, Any] | None = None,
    ) -> "ApkSurfaceRegistry":
        registry = cls(registry_path)
        registry.payload.update(
            {
                "apk_path": str(Path(apk_path).expanduser()),
                "extracted_root": str(Path(extracted_root).expanduser().resolve(strict=False)),
                "manifest_path": str(Path(manifest_path).expanduser().resolve(strict=False)) if manifest_path else "",
                "package_name": str(package_name or "").strip(),
                "version_name": str(version_name or "").strip(),
                "version_code": str(version_code or "").strip(),
                "min_sdk": str(min_sdk or "").strip(),
                "target_sdk": str(target_sdk or "").strip(),
                "application_flags": dict(application_flags or {}),
                "stats": dict(stats or {}),
                "created_at": _now_iso(),
                "updated_at": _now_iso(),
            }
        )
        return registry

    @classmethod
    def load(cls, registry_path: str | Path) -> "ApkSurfaceRegistry":
        path = Path(registry_path).expanduser().resolve(strict=False)
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"surface registry is not a JSON object: {path}")
        return cls(path, payload)

    @property
    def extracted_root(self) -> Path:
        return Path(str(self.payload.get("extracted_root") or "")).expanduser().resolve(strict=False)

    def to_dict(self) -> dict[str, Any]:
        self.payload["updated_at"] = _now_iso()
        return dict(self.payload)

    def save(self) -> Path:
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self.registry_path.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return self.registry_path

    def add_entry(self, category: str, entry: dict[str, Any]) -> None:
        if category not in self.CATEGORY_KEYS:
            raise ValueError(f"unknown registry category: {category}")
        normalized = dict(entry)
        normalized.setdefault("surface_type", category.rstrip("s").replace("_", "-"))
        normalized.setdefault("class_name", "")
        normalized.setdefault("file_path", "")
        normalized.setdefault("evidence", [])
        normalized.setdefault("severity_score", 0.0)
        normalized.setdefault("tags", [])
        normalized.setdefault("metadata", {})
        self.payload.setdefault(category, []).append(normalized)
        self.payload.setdefault("entries", []).append(normalized)

    def add_entries(self, category: str, entries: Iterable[dict[str, Any]]) -> None:
        for entry in entries:
            self.add_entry(category, entry)

    def iter_entries(self, include_expansions: bool = True) -> list[dict[str, Any]]:
        entries = list(self.payload.get("entries") or [])
        if not entries:
            for key in self.CATEGORY_KEYS:
                entries.extend(item for item in (self.payload.get(key) or []) if isinstance(item, dict))
        if include_expansions:
            for expansion in self.payload.get("expansions") or []:
                if not isinstance(expansion, dict):
                    continue
                for item in expansion.get("entries") or []:
                    if isinstance(item, dict):
                        entries.append(item)
        return entries

    def query(
        self,
        *,
        surface_types: Sequence[str] | None = None,
        tags: Sequence[str] | None = None,
        exported: bool | None = None,
        limit: int | None = None,
        include_expansions: bool = True,
    ) -> list[dict[str, Any]]:
        wanted_surfaces = {str(item).strip() for item in (surface_types or []) if str(item).strip()}
        wanted_tags = {str(item).strip() for item in (tags or []) if str(item).strip()}
        results: list[dict[str, Any]] = []
        seen: set[str] = set()
        for entry in self.iter_entries(include_expansions=include_expansions):
            surface_type = str(entry.get("surface_type") or "").strip()
            entry_tags = {str(item).strip() for item in (entry.get("tags") or []) if str(item).strip()}
            if wanted_surfaces and surface_type not in wanted_surfaces:
                continue
            if wanted_tags and not (wanted_tags & entry_tags):
                continue
            if exported is not None and bool(entry.get("exported")) is not exported:
                continue
            signature = json.dumps(
                {
                    "surface_type": surface_type,
                    "class_name": entry.get("class_name"),
                    "file_path": entry.get("file_path"),
                    "evidence": entry.get("evidence"),
                },
                sort_keys=True,
            )
            if signature in seen:
                continue
            seen.add(signature)
            results.append(dict(entry))
            if limit is not None and len(results) >= max(0, limit):
                break
        return results

    def file_paths_for_surfaces(
        self,
        surface_types: Sequence[str],
        *,
        limit: int | None = None,
        include_expansions: bool = True,
    ) -> list[str]:
        files = _dedupe_strings(
            str(entry.get("file_path") or "")
            for entry in self.query(
                surface_types=surface_types,
                include_expansions=include_expansions,
            )
        )
        if limit is None:
            return files
        return files[: max(0, limit)]

    def expand_class(
        self,
        class_name: str,
        *,
        requested_by: str,
        reason: str,
        limit: int = 40,
    ) -> list[str]:
        class_token = str(class_name or "").strip()
        if not class_token:
            return []
        relative_path = Path(*class_token.replace("$", ".").split(".")).with_suffix(".smali")
        matches: list[str] = []
        for smali_root in sorted(self.extracted_root.glob("smali*")):
            candidate = smali_root / relative_path
            if candidate.exists():
                matches.append(str(candidate.relative_to(self.extracted_root)))
        package = _package_prefix(class_token)
        package_matches = self.expand_packages(
            [package],
            requested_by=requested_by,
            reason=reason,
            limit=max(limit, len(matches)),
            save=False,
        )
        all_matches = _dedupe_strings([*matches, *package_matches])[: max(0, limit)]
        if all_matches:
            self._record_expansion(
                requested_by=requested_by,
                reason=reason,
                package_prefix=package,
                class_name=class_token,
                file_paths=all_matches,
                surface_type="class-expansion",
            )
            self.save()
        return all_matches

    def expand_packages(
        self,
        package_prefixes: Sequence[str],
        *,
        requested_by: str,
        reason: str,
        limit: int = 60,
        save: bool = True,
    ) -> list[str]:
        matches: list[str] = []
        for prefix in _dedupe_strings(package_prefixes):
            rel_dir = Path(*prefix.split(".")) if prefix else Path()
            for smali_root in sorted(self.extracted_root.glob("smali*")):
                candidate_dir = (smali_root / rel_dir).resolve(strict=False)
                if not candidate_dir.exists() or not candidate_dir.is_dir():
                    continue
                for file_path in sorted(candidate_dir.rglob("*.smali")):
                    try:
                        matches.append(str(file_path.relative_to(self.extracted_root)))
                    except ValueError:
                        matches.append(str(file_path))
                    if len(_dedupe_strings(matches)) >= max(0, limit):
                        break
                if len(_dedupe_strings(matches)) >= max(0, limit):
                    break
            if len(_dedupe_strings(matches)) >= max(0, limit):
                break
        deduped = _dedupe_strings(matches)[: max(0, limit)]
        if deduped and save:
            self._record_expansion(
                requested_by=requested_by,
                reason=reason,
                package_prefix=",".join(_dedupe_strings(package_prefixes)),
                class_name="",
                file_paths=deduped,
                surface_type="package-expansion",
            )
            self.save()
        return deduped

    def expand_for_surface_types(
        self,
        requested_by: str,
        surface_types: Sequence[str],
        *,
        limit: int = 60,
    ) -> list[str]:
        seed_entries = self.query(surface_types=surface_types, limit=24)
        if not seed_entries:
            return []
        direct_files = _dedupe_strings(str(item.get("file_path") or "") for item in seed_entries)
        package_prefixes = _dedupe_strings(
            _package_prefix(str(item.get("class_name") or ""))
            for item in seed_entries
        )
        expansion_limit = max(0, limit - len(direct_files))
        expanded = self.expand_packages(
            package_prefixes,
            requested_by=requested_by,
            reason=f"surface-type expansion for {','.join(surface_types)}",
            limit=expansion_limit or limit,
            save=False,
        )
        combined = _dedupe_strings([*direct_files, *expanded])[: max(0, limit)]
        if combined:
            self._record_expansion(
                requested_by=requested_by,
                reason=f"surface-type expansion for {','.join(surface_types)}",
                package_prefix=",".join(package_prefixes),
                class_name="",
                file_paths=combined,
                surface_type="surface-expansion",
            )
            self.save()
        return combined

    def prompt_context(
        self,
        surface_types: Sequence[str],
        *,
        max_entries: int = 18,
        max_files: int = 40,
        max_expansions: int = 6,
    ) -> dict[str, Any]:
        relevant_entries = self.query(surface_types=surface_types, limit=max_entries)
        relevant_files = self.file_paths_for_surfaces(surface_types, limit=max_files)
        expansions = [
            item
            for item in (self.payload.get("expansions") or [])
            if isinstance(item, dict)
        ][-max_expansions:]
        return {
            "package_name": self.payload.get("package_name"),
            "version_name": self.payload.get("version_name"),
            "version_code": self.payload.get("version_code"),
            "manifest_path": self.payload.get("manifest_path"),
            "application_flags": self.payload.get("application_flags") or {},
            "stats": self.payload.get("stats") or {},
            "surface_types": list(surface_types),
            "entries": relevant_entries,
            "relevant_files": relevant_files,
            "recent_expansions": expansions,
        }

    def record_progressive_finding(self, finding: dict[str, Any], requested_by: str) -> None:
        file_path = str(finding.get("file") or "").strip()
        entry = {
            "recorded_at": _now_iso(),
            "requested_by": requested_by,
            "type": str(finding.get("type") or "").strip(),
            "class_name": str(finding.get("class_name") or "").strip(),
            "file_path": file_path,
            "source": str(finding.get("source") or "").strip(),
            "sink": str(finding.get("sink") or "").strip(),
            "severity": str(finding.get("severity") or "").strip(),
        }
        self.payload.setdefault("progressive_findings", []).append(entry)
        self.save()

    def _record_expansion(
        self,
        *,
        requested_by: str,
        reason: str,
        package_prefix: str,
        class_name: str,
        file_paths: Sequence[str],
        surface_type: str,
    ) -> None:
        entries = [
            {
                "surface_type": surface_type,
                "class_name": class_name,
                "file_path": path,
                "evidence": [reason],
                "severity_score": 0.1,
                "tags": ["progressive-expansion"],
                "metadata": {"requested_by": requested_by, "package_prefix": package_prefix},
            }
            for path in _dedupe_strings(file_paths)
        ]
        self.payload.setdefault("expansions", []).append(
            {
                "created_at": _now_iso(),
                "requested_by": requested_by,
                "reason": reason,
                "package_prefix": package_prefix,
                "class_name": class_name,
                "entries": entries,
            }
        )

