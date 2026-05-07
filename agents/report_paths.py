"""Report path compatibility helpers for canonical and legacy layouts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from agents.storage_resolver import resolve_family_lane, resolve_storage

SEEDED_REPORT_STATES = {"raw", "confirmed", "dormant", "novel", "complete", "archive"}
STATUS_REPORT_SPECS = (
    ("active", "active.md"),
    ("confirmed", "confirmed.md"),
    ("dormant", "dormant.md"),
    ("novel", "novel_findings.md"),
    ("completed", "completed.md"),
)
LEGACY_STATUS_REPORT_SPECS = (
    ("confirmed", "confirmed.md"),
    ("dormant", "dormant.md"),
    ("novel", "novel_findings.md"),
)
DATE_SHAPED_DIR_RE = re.compile(r"^(?:\d{4}-\d{2}-\d{2}|\d{2}-\d{2}-\d{4})$")
DAILY_DATE_FORMAT = "%m-%d-%Y"
REPORT_NAV_GENERATED_MARKER = "<!-- generated: bounty-core-report-navigation -->"
CATEGORY_STUB_GENERATED_MARKER = "<!-- generated: bounty-core-category-link-stub -->"


@dataclass(frozen=True, slots=True)
class ReportSource:
    path: Path
    mode: str


def discover_report_files(source_dir: Path) -> list[Path]:
    """Return markdown report files under a selected source directory."""
    return sorted(
        path
        for path in source_dir.rglob("*.md")
        if path.is_file()
        and not is_generated_report_navigation(path)
        and not is_seeded_report_index(path)
    )


def has_report_markdown(source_dir: Path) -> bool:
    if not source_dir.is_dir():
        return False
    return bool(discover_report_files(source_dir))


def is_seeded_report_index(path: Path) -> bool:
    """Return True for generated canonical report index placeholders."""
    if path.name != "index.md" and path.parent.name != "index":
        return False
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    text = "\n".join(line for line in lines if not line.startswith("<!-- generated:")).strip()

    if path.name == "index.md" and path.parent.parent.name in SEEDED_REPORT_STATES:
        expected = f"# {path.parent.parent.name.title()} {path.parent.name.upper()}"
        return text == expected
    if path.parent.name == "index":
        expected = f"# {path.stem.replace('_', ' ').title()}"
        return text == expected
    return False


def is_generated_report_navigation(path: Path) -> bool:
    """Return True for bounty-core generated navigation and link-stub markdown."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return REPORT_NAV_GENERATED_MARKER in text or CATEGORY_STUB_GENERATED_MARKER in text


def is_seeded_raw_index(path: Path) -> bool:
    """Backward-compatible alias for callers filtering raw input reports."""
    expected = f"# Raw {path.parent.name.upper()}"
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return False
    if path.name != "index.md" or path.parent.parent.name != "raw":
        return False
    return text == expected


def is_date_shaped_status_dir(path: Path) -> bool:
    """Return True for canonical dated report index directories."""
    return path.is_dir() and DATE_SHAPED_DIR_RE.fullmatch(path.name) is not None


def _parse_report_date(path: Path) -> datetime:
    for fmt in (DAILY_DATE_FORMAT, "%Y-%m-%d", "%d-%m-%Y"):
        try:
            return datetime.strptime(path.parent.name, fmt)
        except ValueError:
            continue
    return datetime.fromtimestamp(path.stat().st_mtime)


def _latest_daily_status_report_path(reports_root: Path, bucket: str) -> Path | None:
    daily_root = reports_root / "daily"
    if not daily_root.is_dir():
        return None
    candidates = [
        path
        for path in daily_root.glob(f"*/{bucket}.md")
        if path.is_file() and DATE_SHAPED_DIR_RE.fullmatch(path.parent.name)
    ]
    if not candidates:
        return None
    return max(candidates, key=_parse_report_date)


def _global_status_report_path(reports_root: Path, bucket: str) -> Path | None:
    candidate = reports_root / f"{bucket}.md"
    if candidate.is_file():
        return candidate
    return None


def _latest_legacy_status_report_path(reports_root: Path, filename: str) -> Path | None:
    exact_candidate = reports_root / filename
    dated_candidates = [path for path in reports_root.glob(f"*/{filename}") if path.is_file()]
    legacy_candidates = [
        path
        for path in reports_root.glob(f"{filename[:-3]}_*.md")
        if path.is_file()
    ]
    candidates = dated_candidates + legacy_candidates
    if exact_candidate.is_file():
        candidates.append(exact_candidate)
    if not candidates:
        return None
    return max(candidates, key=lambda item: item.stat().st_mtime)


def status_report_path_for_read(reports_root: Path, bucket: str, legacy_filename: str) -> Path | None:
    """Return the status report path a report_checker-style reader can load."""
    global_candidate = _global_status_report_path(reports_root, bucket)
    if global_candidate is not None:
        return global_candidate

    daily_candidate = _latest_daily_status_report_path(reports_root, bucket)
    if daily_candidate is not None:
        return daily_candidate

    dated_bucket_root = reports_root / bucket
    canonical_flat = dated_bucket_root / "index.md"
    if canonical_flat.is_file() and not is_seeded_report_index(canonical_flat):
        return canonical_flat
    if dated_bucket_root.is_dir():
        dated_candidates = [
            path
            for path in dated_bucket_root.glob("*/index.md")
            if path.is_file() and not is_seeded_report_index(path)
        ]
        if dated_candidates:
            return max(dated_candidates, key=lambda item: item.stat().st_mtime)
    return _latest_legacy_status_report_path(reports_root, legacy_filename)


def status_index_paths_for_read(
    reports_root: Path,
    specs: Iterable[tuple[str, str]] = STATUS_REPORT_SPECS,
) -> list[Path]:
    if not reports_root.is_dir():
        return []
    return [
        path
        for bucket, legacy_filename in specs
        if (path := status_report_path_for_read(reports_root, bucket, legacy_filename)) is not None
    ]


def has_status_index_markdown(
    reports_root: Path,
    specs: Iterable[tuple[str, str]] = STATUS_REPORT_SPECS,
) -> bool:
    return bool(status_index_paths_for_read(reports_root, specs))


def canonical_reports_root(
    program: str,
    hunt_type: str = "source",
    *,
    family: str | None = None,
    lane: str | None = None,
    root_override: str | Path | None = None,
    create: bool = False,
) -> Path:
    resolved_family, resolved_lane = resolve_family_lane(family=family, lane=lane, hunt_type=hunt_type)
    storage = resolve_storage(
        program,
        family=resolved_family,
        lane=resolved_lane,
        root_override=root_override,
        create=create,
    )
    return storage.reports_root


def canonical_raw_reports_dir(
    program: str,
    hunt_type: str = "source",
    *,
    family: str | None = None,
    lane: str | None = None,
    root_override: str | Path | None = None,
    create: bool = False,
) -> Path:
    return canonical_reports_root(
        program,
        hunt_type,
        family=family,
        lane=lane,
        root_override=root_override,
        create=create,
    ) / "raw"


def _dedupe_sources(sources: Iterable[ReportSource]) -> list[ReportSource]:
    seen: set[Path] = set()
    deduped: list[ReportSource] = []
    for source in sources:
        key = source.path.expanduser().resolve(strict=False)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ReportSource(key, source.mode))
    return deduped


def canonical_report_sources(
    program: str,
    hunt_type: str = "source",
    *,
    family: str | None = None,
    lane: str | None = None,
    root_override: str | Path | None = None,
) -> list[ReportSource]:
    reports_root = canonical_reports_root(
        program,
        hunt_type,
        family=family,
        lane=lane,
        root_override=root_override,
        create=False,
    )
    return [
        ReportSource(reports_root / "raw", "canonical_raw"),
        ReportSource(reports_root, "canonical_reports"),
    ]


def home_source_report_sources(program: str) -> list[ReportSource]:
    program_root = Path.home() / "source" / program
    candidates = [
        ReportSource(program_root / "reports", "source_reports"),
        ReportSource(program_root / "report", "source_report"),
    ]
    if program_root.is_dir():
        candidates.extend(
            ReportSource(path, "source_wildcard")
            for path in sorted(program_root.glob("*reports*"))
            if path.is_dir()
        )
    return _dedupe_sources(candidates)


def legacy_ghost_report_sources(program: str, hunt_type: str = "source") -> list[ReportSource]:
    ghost_root = Path.home() / "Shared" / "bounty_recon" / program / "ghost"
    preferred = "web" if hunt_type == "web" else "source"
    other = "source" if preferred == "web" else "web"
    candidates = [
        ReportSource(ghost_root / f"reports_{preferred}", f"legacy_reports_{preferred}"),
        ReportSource(ghost_root / f"report_{preferred}", f"legacy_report_{preferred}"),
        ReportSource(ghost_root / "reports", "legacy_reports"),
        ReportSource(ghost_root / "report", "legacy_report"),
        ReportSource(ghost_root / f"reports_{other}", f"legacy_reports_{other}"),
        ReportSource(ghost_root / f"report_{other}", f"legacy_report_{other}"),
    ]
    return _dedupe_sources(candidates)


def select_report_source(
    program: str,
    *,
    hunt_type: str = "source",
    source_dir: str | Path | None = None,
    family: str | None = None,
    lane: str | None = None,
    root_override: str | Path | None = None,
) -> ReportSource:
    """Select the report source for imports.

    Explicit source directories are authoritative. Otherwise canonical bounty-core
    report directories win when they contain markdown. Legacy ghost directories
    are read only as fallback compatibility. If nothing exists, return the
    canonical raw directory so any generated reports are written canonically.
    """
    if source_dir is not None:
        return ReportSource(Path(source_dir).expanduser().resolve(strict=False), "override")

    for source in canonical_report_sources(
        program,
        hunt_type,
        family=family,
        lane=lane,
        root_override=root_override,
    ):
        if has_report_markdown(source.path):
            return source

    for source in home_source_report_sources(program):
        if has_report_markdown(source.path):
            return source

    for source in legacy_ghost_report_sources(program, hunt_type):
        if has_report_markdown(source.path):
            return source

    return ReportSource(
        canonical_raw_reports_dir(
            program,
            hunt_type,
            family=family,
            lane=lane,
            root_override=root_override,
            create=False,
        ).resolve(strict=False),
        "canonical_raw",
    )


def report_index_roots_for_read(
    program: str,
    hunt_type: str = "source",
    *,
    family: str | None = None,
    lane: str | None = None,
    root_override: str | Path | None = None,
) -> list[ReportSource]:
    """Return report roots for status-index readers, with legacy fallback."""
    canonical_root = canonical_reports_root(
        program,
        hunt_type,
        family=family,
        lane=lane,
        root_override=root_override,
        create=False,
    ).resolve(strict=False)
    if has_status_index_markdown(canonical_root, LEGACY_STATUS_REPORT_SPECS):
        return [ReportSource(canonical_root, "canonical_reports")]
    if root_override is not None:
        return []

    return [
        source
        for source in legacy_ghost_report_sources(program, hunt_type)
        if has_status_index_markdown(source.path, LEGACY_STATUS_REPORT_SPECS)
    ]
