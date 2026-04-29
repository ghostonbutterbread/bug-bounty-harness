"""Shared report-path and report-writing helpers for BaseTeam-backed teams."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Callable


def dated_report_index_paths(storage) -> tuple[Path, Path, Path]:
    report_date = datetime.now().strftime("%d-%m-%Y")
    confirmed_dir = storage.reports_root / "confirmed" / report_date
    dormant_dir = storage.reports_root / "dormant" / report_date
    novel_dir = storage.reports_root / "novel" / report_date
    for report_dir in (confirmed_dir, dormant_dir, novel_dir):
        report_dir.mkdir(parents=True, exist_ok=True)
    return (
        confirmed_dir / "index.md",
        dormant_dir / "index.md",
        novel_dir / "index.md",
    )


def write_report_indexes(
    storage,
    *,
    confirmed: list[dict],
    dormant: list[dict],
    novel: list[dict],
    render_confirmed: Callable[[list[dict]], str],
    render_dormant: Callable[[list[dict]], str],
    render_novel: Callable[[list[dict]], str],
) -> tuple[Path, Path, Path]:
    confirmed_path, dormant_path, novel_path = dated_report_index_paths(storage)
    confirmed_path.write_text(render_confirmed(confirmed), encoding="utf-8")
    dormant_path.write_text(render_dormant(dormant), encoding="utf-8")
    novel_path.write_text(render_novel(novel), encoding="utf-8")
    return confirmed_path, dormant_path, novel_path
