"""Offline AppMap research-librarian campaign wrapper."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable

_AGENT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _AGENT_DIR.parent
if _PROJECT_ROOT.as_posix() not in (p.as_posix() for p in map(Path, sys.path)):
    sys.path.insert(0, _PROJECT_ROOT.as_posix())

from agents.appmap_hypothesis import HypothesisOptions, generate_hypotheses, write_jsonl
from agents.appmap_research import generate_research_artifacts, normalize_research_query, sanitize_key


SCHEMA_VERSION = 1
DEFAULT_FOCUS = "rce"


@dataclass(frozen=True)
class CampaignPaths:
    root: Path
    manifest: Path
    scout_brief: Path
    validator_brief: Path
    sources_todo: Path
    validated_seed: Path
    readme: Path
    validation_report: Path
    plan: Path

    def as_manifest(self) -> dict[str, str]:
        return {
            "root": str(self.root),
            "manifest": str(self.manifest),
            "scout_brief": str(self.scout_brief),
            "validator_brief": str(self.validator_brief),
            "sources_todo": str(self.sources_todo),
            "validated_research_seed": str(self.validated_seed),
            "readme": str(self.readme),
            "validation_report": str(self.validation_report),
            "plan_appmap_command": str(self.plan),
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create and validate offline AppMap research-librarian campaign workspaces."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="Create a research-librarian campaign workspace.")
    init.add_argument("program", help="Program name used in campaign and later AppMap metadata.")
    init.add_argument("--category", action="append", default=[], help="Research category/class. Repeatable.")
    init.add_argument(
        "--research-query",
        action="append",
        nargs="+",
        default=[],
        metavar="WORD",
        help="Research query terms. Repeatable; terms are normalized into metadata.",
    )
    init.add_argument("--target-kind", default="auto", help="Optional AppMap target kind hint.")
    init.add_argument("--focus", default=DEFAULT_FOCUS, help="Research vulnerability focus. Defaults to rce.")
    init.add_argument("--output-root", help="Root directory for campaign workspace. Defaults to ~/Shared/appmap/<program>/research-librarian.")
    init.add_argument("--run-id", help="Deterministic run id override.")
    init.add_argument("--overwrite", action="store_true", help="Overwrite an existing campaign workspace.")
    init.set_defaults(func=cmd_init)

    validate = subparsers.add_parser("validate", help="Validate a local seed without network access.")
    validate.add_argument("campaign", help="Campaign workspace directory.")
    validate.add_argument(
        "--seed",
        help="Validated seed JSON/JSONL path. Defaults to <campaign>/validated_research_seed.json.",
    )
    validate.add_argument(
        "--report",
        help="Validation report path. Defaults to <campaign>/validation_report.json.",
    )
    validate.set_defaults(func=cmd_validate)

    plan = subparsers.add_parser("plan-appmap", help="Print and optionally capture an AppMap ingest command.")
    plan.add_argument("campaign", help="Campaign workspace directory.")
    plan.add_argument("target_path", help="Local target path for agents/app_mapper.py.")
    plan.add_argument("--seed", help="Seed path. Defaults to <campaign>/validated_research_seed.json.")
    plan.add_argument("--use-web-sources", action="store_true", help="Plan explicit URL web mode from validated seed sources.")
    plan.add_argument("--target-kind", help="Override target kind. Defaults to campaign manifest target_kind.")
    plan.add_argument("--focus", help="Override focus. Defaults to campaign manifest focus.")
    plan.add_argument("--run-id", help="Optional AppMap run id.")
    plan.add_argument("--write-specs", action="store_true", help="Include --write-specs in the planned command.")
    plan.add_argument("--output-mode", choices=("standalone", "canonical"), default="standalone")
    plan.add_argument("--output-root", help="Standalone AppMap output root.")
    plan.add_argument("--family", help="Canonical family.")
    plan.add_argument("--lane", help="Canonical lane.")
    plan.add_argument("--shared-root", help="Canonical Shared root override.")
    plan.add_argument("--promote-to-brainstorm", action="store_true", help="Include AppMap brainstorm promotion flag.")
    plan.add_argument("--brainstorm-root", help="Promotion brainstorm root.")
    plan.add_argument("--promote-spec-name", help="Promoted spec name.")
    plan.add_argument(
        "--capture",
        help="Write command to this file. Defaults to <campaign>/plan_appmap_command.txt when omitted.",
    )
    plan.set_defaults(func=cmd_plan_appmap)

    hypothesize = subparsers.add_parser("hypothesize", help="Generate generic research/AppMap chain hypotheses.")
    hypothesize.add_argument("campaign", help="Campaign workspace directory.")
    hypothesize.add_argument("--appmap-run", required=True, help="AppMap run root containing manifest/candidates/surfaces artifacts.")
    hypothesize.add_argument("--seed", help="Seed path. Defaults to <campaign>/validated_research_seed.json.")
    hypothesize.add_argument("--category", help="Vulnerability class/category override. Defaults to first campaign category, then focus.")
    hypothesize.add_argument("--output", help="JSONL output path. Defaults to <campaign>/hypotheses.jsonl.")
    hypothesize.add_argument("--markdown-output", help="Markdown report output path. Defaults to <campaign>/hypotheses.md.")
    hypothesize.add_argument("--brainstorm-spec-out", help="Optional brainstorm-style markdown spec output path.")
    hypothesize.add_argument("--max-hypotheses", type=int, help="Maximum hypotheses to emit.")
    hypothesize.add_argument("--surface-kind", action="append", default=[], metavar="KIND", help="Restrict to a mapped surface kind. Repeatable.")
    hypothesize.add_argument("--require-appmap-ref", action="store_true", help="Only emit hypotheses with AppMap candidate or surface refs.")
    hypothesize.add_argument("--include-low-confidence", action="store_true", help="Include weak surface-only hypotheses for manual review.")
    hypothesize.add_argument("--dry-run", action="store_true", help="Preview generation without writing output artifacts.")
    hypothesize.set_defaults(func=cmd_hypothesize)
    return parser


def cmd_init(args: argparse.Namespace) -> int:
    query_terms = _flatten_query(args.research_query)
    categories = tuple(str(item).strip() for item in args.category if str(item).strip())
    if not categories and not query_terms:
        raise SystemExit("init requires --category or --research-query")

    run_id = _campaign_run_id(args.run_id)
    campaign_root = _campaign_root(args.program, run_id=run_id, output_root=Path(args.output_root) if args.output_root else None)
    paths = _campaign_paths(campaign_root)
    if paths.root.exists() and any(paths.root.iterdir()) and not args.overwrite:
        raise SystemExit(f"campaign already exists and is not empty: {paths.root}; pass --overwrite to replace scaffolding")
    paths.root.mkdir(parents=True, exist_ok=True)

    created_at = _utc_now()
    query = normalize_research_query((*categories, *query_terms), focus=args.focus, target_kind=args.target_kind)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "program": args.program,
        "focus": args.focus,
        "target_kind": args.target_kind,
        "run_id": run_id,
        "created_at": created_at,
        "status": "initialized",
        "category": list(categories),
        "research_query_terms": list(query_terms),
        "research_query": query.as_manifest(),
        "network_policy": "wrapper performs no network calls, no browser automation, no search scraping, no target probing",
        "paths": paths.as_manifest(),
    }

    _write_json(paths.manifest, manifest)
    paths.scout_brief.write_text(_scout_brief(manifest), encoding="utf-8")
    paths.validator_brief.write_text(_validator_brief(manifest), encoding="utf-8")
    paths.sources_todo.write_text("", encoding="utf-8")
    _write_json(paths.validated_seed, {"sources": [], "technique_packs": []})
    paths.readme.write_text(_campaign_readme(manifest), encoding="utf-8")

    print(f"[appmap-research-librarian] campaign: {paths.root}")
    print(f"[appmap-research-librarian] manifest: {paths.manifest}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    campaign_root = Path(args.campaign).expanduser().resolve(strict=False)
    seed_path = Path(args.seed).expanduser() if args.seed else campaign_root / "validated_research_seed.json"
    report_path = Path(args.report).expanduser() if args.report else campaign_root / "validation_report.json"
    manifest = _read_campaign_manifest(campaign_root)
    report = validate_seed(seed_path, manifest=manifest, campaign_root=campaign_root)
    _write_json(report_path, report)

    print(
        "[appmap-research-librarian] "
        f"validation={report['status']} sources={report['counts']['sources']} "
        f"technique_packs={report['counts']['technique_packs']} errors={report['counts']['errors']}"
    )
    print(f"[appmap-research-librarian] report: {report_path}")
    return 0 if report["status"] == "ok" else 1


def cmd_plan_appmap(args: argparse.Namespace) -> int:
    campaign_root = Path(args.campaign).expanduser().resolve(strict=False)
    manifest = _read_campaign_manifest(campaign_root)
    seed_path = Path(args.seed).expanduser() if args.seed else campaign_root / "validated_research_seed.json"
    validation_report = validate_seed(seed_path, manifest=manifest, campaign_root=campaign_root)
    _write_json(campaign_root / "validation_report.json", validation_report)
    if validation_report["status"] != "ok":
        raise SystemExit(
            "validated seed failed local validation; fix validation_report.json before planning AppMap ingest"
        )
    if validation_report["counts"]["sources"] == 0 or validation_report["counts"]["technique_packs"] == 0:
        raise SystemExit("validated seed must contain at least one source and one technique_pack before planning AppMap ingest")
    try:
        command = plan_appmap_command(
            manifest,
            seed_path=seed_path,
            target_path=Path(args.target_path),
            use_web_sources=args.use_web_sources,
            target_kind=args.target_kind,
            focus=args.focus,
            run_id=args.run_id,
            write_specs=args.write_specs,
            output_mode=args.output_mode,
            output_root=Path(args.output_root).expanduser() if args.output_root else None,
            family=args.family,
            lane=args.lane,
            shared_root=Path(args.shared_root).expanduser() if args.shared_root else None,
            promote_to_brainstorm=args.promote_to_brainstorm,
            brainstorm_root=Path(args.brainstorm_root).expanduser() if args.brainstorm_root else None,
            promote_spec_name=args.promote_spec_name,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    capture_path = Path(args.capture).expanduser() if args.capture else campaign_root / "plan_appmap_command.txt"
    capture_path.write_text(command + "\n", encoding="utf-8")
    print(command)
    print(f"[appmap-research-librarian] plan: {capture_path}", file=sys.stderr)
    return 0


def cmd_hypothesize(args: argparse.Namespace) -> int:
    campaign_root = Path(args.campaign).expanduser().resolve(strict=False)
    manifest = _read_campaign_manifest(campaign_root)
    seed_path = Path(args.seed).expanduser() if args.seed else campaign_root / "validated_research_seed.json"
    validation_report = validate_seed(seed_path, manifest=manifest, campaign_root=campaign_root)
    if not args.dry_run:
        _write_json(campaign_root / "validation_report.json", validation_report)
    if validation_report["status"] != "ok":
        raise SystemExit(
            "validated seed failed local validation; fix validation_report.json before generating hypotheses"
        )
    if validation_report["counts"]["sources"] == 0 or validation_report["counts"]["technique_packs"] == 0:
        raise SystemExit("validated seed must contain at least one source and one technique_pack before generating hypotheses")
    options = HypothesisOptions(
        category=str(args.category or ""),
        max_hypotheses=args.max_hypotheses,
        surface_kinds=tuple(args.surface_kind or ()),
        require_appmap_ref=bool(args.require_appmap_ref),
        include_low_confidence=bool(args.include_low_confidence),
    )
    try:
        result = generate_hypotheses(
            campaign_root=campaign_root,
            appmap_run_root=Path(args.appmap_run).expanduser().resolve(strict=False),
            manifest=manifest,
            seed_path=seed_path,
            options=options,
            brainstorm_spec=bool(args.brainstorm_spec_out),
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    jsonl_path = Path(args.output).expanduser() if args.output else campaign_root / "hypotheses.jsonl"
    markdown_path = Path(args.markdown_output).expanduser() if args.markdown_output else campaign_root / "hypotheses.md"
    brainstorm_path = Path(args.brainstorm_spec_out).expanduser() if args.brainstorm_spec_out else None
    if brainstorm_path is not None and not result.hypotheses:
        raise SystemExit("--brainstorm-spec-out requires at least one generated hypothesis")
    if args.dry_run:
        print(
            "[appmap-research-librarian] "
            f"dry-run hypotheses={len(result.hypotheses)} candidates={result.summary['candidate_count']} "
            f"surfaces={result.summary['surface_count']} category={result.summary['category']}"
        )
        for hypothesis in result.hypotheses[:10]:
            print(f"{hypothesis['id']} {hypothesis['category']}: {hypothesis['title']}")
        return 0
    write_jsonl(jsonl_path, result.hypotheses)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text(result.report, encoding="utf-8")
    if brainstorm_path is not None and result.brainstorm_spec is not None:
        brainstorm_path.parent.mkdir(parents=True, exist_ok=True)
        brainstorm_path.write_text(result.brainstorm_spec, encoding="utf-8")
    print(
        "[appmap-research-librarian] "
        f"hypotheses={len(result.hypotheses)} jsonl={jsonl_path} markdown={markdown_path}"
    )
    if brainstorm_path is not None:
        print(f"[appmap-research-librarian] brainstorm_spec={brainstorm_path}")
    return 0


def validate_seed(seed_path: Path, *, manifest: dict[str, Any], campaign_root: Path | None = None) -> dict[str, Any]:
    fake_result = _fake_result(manifest)
    errors: list[str] = []
    try:
        research = generate_research_artifacts(
            fake_result,
            seed_paths=[seed_path],
            research_mode="local",
            research_query_terms=_manifest_query_terms(manifest),
        )
    except ValueError as exc:
        research = None
        errors.append(str(exc))

    if research is not None:
        errors.extend(str(item) for item in research["manifest"].get("errors", []))
        sources = research.get("sources", [])
        technique_packs = research.get("technique_packs", [])
        categories = sorted(set(research["manifest"].get("categories", [])))
    else:
        sources = []
        technique_packs = []
        categories = []

    errors.extend(_strict_seed_errors(seed_path))
    errors = list(dict.fromkeys(errors))
    status = "ok" if not errors else "failed"
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "generated_at": _utc_now(),
        "campaign_root": str(campaign_root) if campaign_root is not None else "",
        "seed_path": str(seed_path.expanduser().resolve(strict=False)),
        "network_access": False,
        "network_policy": "local seed validation only; no network I/O",
        "counts": {
            "sources": len(sources),
            "technique_packs": len(technique_packs),
            "errors": len(errors),
        },
        "categories": categories,
        "errors": errors,
        "manifest": research["manifest"] if research is not None else {},
    }


def plan_appmap_command(
    manifest: dict[str, Any],
    *,
    seed_path: Path,
    target_path: Path,
    use_web_sources: bool = False,
    target_kind: str | None = None,
    focus: str | None = None,
    run_id: str | None = None,
    write_specs: bool = False,
    output_mode: str = "standalone",
    output_root: Path | None = None,
    family: str | None = None,
    lane: str | None = None,
    shared_root: Path | None = None,
    promote_to_brainstorm: bool = False,
    brainstorm_root: Path | None = None,
    promote_spec_name: str | None = None,
) -> str:
    program = str(manifest.get("program") or "").strip()
    if not program:
        raise ValueError("campaign manifest is missing program")
    terms = _manifest_query_terms(manifest)
    argv = [
        "python3",
        "agents/app_mapper.py",
        program,
        str(target_path.expanduser()),
        "--target-kind",
        target_kind or str(manifest.get("target_kind") or "auto"),
        "--focus",
        focus or str(manifest.get("focus") or DEFAULT_FOCUS),
    ]
    if write_specs:
        argv.append("--write-specs")
    if run_id:
        argv.extend(["--run-id", run_id])
    if output_mode:
        argv.extend(["--output-mode", output_mode])
    if output_root is not None:
        argv.extend(["--output-root", str(output_root)])
    if family:
        argv.extend(["--family", family])
    if lane:
        argv.extend(["--lane", lane])
    if shared_root is not None:
        argv.extend(["--shared-root", str(shared_root)])
    if terms:
        argv.append("--research-query")
        argv.extend(terms)
    if use_web_sources:
        urls = _validated_source_urls(seed_path, manifest=manifest)
        if not urls:
            raise ValueError("validated seed contains no source URLs for --use-web-sources")
        argv.extend(["--research-mode", "web"])
        for url in urls:
            argv.extend(["--research-source-url", url])
    else:
        argv.extend(["--research-mode", "local", "--research-seed", str(seed_path.expanduser())])
    if promote_to_brainstorm:
        argv.append("--promote-to-brainstorm")
    if brainstorm_root is not None:
        argv.extend(["--brainstorm-root", str(brainstorm_root)])
    if promote_spec_name:
        argv.extend(["--promote-spec-name", promote_spec_name])
    return " ".join(shlex.quote(item) for item in argv)


def _campaign_root(program: str, *, run_id: str, output_root: Path | None) -> Path:
    if output_root is not None:
        base = output_root.expanduser()
    else:
        base = Path.home() / "Shared" / "appmap" / sanitize_key(program) / "research-librarian"
    return (base / sanitize_key(program) / run_id if output_root is not None else base / run_id).resolve(strict=False)


def _campaign_paths(root: Path) -> CampaignPaths:
    return CampaignPaths(
        root=root,
        manifest=root / "manifest.json",
        scout_brief=root / "scout_brief.md",
        validator_brief=root / "validator_brief.md",
        sources_todo=root / "sources.todo.jsonl",
        validated_seed=root / "validated_research_seed.json",
        readme=root / "README.md",
        validation_report=root / "validation_report.json",
        plan=root / "plan_appmap_command.txt",
    )


def _campaign_run_id(value: str | None) -> str:
    if value:
        run_id = sanitize_key(value, fallback="")
        if not run_id:
            raise SystemExit("run id must contain at least one letter or digit")
        return run_id[:120]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{timestamp}-{time.time_ns()}-{uuid.uuid4().hex[:8]}"


def _flatten_query(values: Iterable[Iterable[str]]) -> tuple[str, ...]:
    return tuple(str(term).strip() for group in values for term in group if str(term).strip())


def _manifest_query_terms(manifest: dict[str, Any]) -> tuple[str, ...]:
    terms = manifest.get("research_query_terms") or []
    categories = manifest.get("category") or []
    if not isinstance(terms, list):
        terms = []
    if not isinstance(categories, list):
        categories = []
    return tuple(str(item).strip() for item in [*categories, *terms] if str(item).strip())


def _fake_result(manifest: dict[str, Any]) -> SimpleNamespace:
    profile = SimpleNamespace(
        program=str(manifest.get("program") or ""),
        target_kind=str(manifest.get("target_kind") or "auto"),
    )
    return SimpleNamespace(profile=profile, focus=str(manifest.get("focus") or DEFAULT_FOCUS))


def _read_campaign_manifest(campaign_root: Path) -> dict[str, Any]:
    path = campaign_root / "manifest.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SystemExit(f"failed to read campaign manifest {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"failed to parse campaign manifest {path}: {exc.msg}") from exc


def _validated_source_urls(seed_path: Path, *, manifest: dict[str, Any]) -> list[str]:
    research = generate_research_artifacts(
        _fake_result(manifest),
        seed_paths=[seed_path],
        research_mode="local",
        research_query_terms=_manifest_query_terms(manifest),
    )
    if research is None:
        return []
    urls = [
        str(source.get("url") or "").strip()
        for source in research.get("sources", [])
        if str(source.get("url") or "").strip().startswith("https://")
    ]
    return list(dict.fromkeys(urls))


def _strict_seed_errors(seed_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        payload = _read_json_or_jsonl(seed_path)
    except OSError as exc:
        return [f"{seed_path}: failed to read seed: {exc}"]
    except json.JSONDecodeError as exc:
        return [f"{seed_path}: invalid JSON: {exc.msg}"]
    sources, techniques = _payload_sections(payload)
    if not sources and techniques:
        errors.append(f"{seed_path}: technique seed must include at least one source")
    source_ids: set[str] = set()
    for index, source in enumerate(sources, start=1):
        source_id = str(source.get("id") or source.get("source_id") or "").strip()
        normalized_source_id = sanitize_key(source_id, fallback="")
        if not source_id:
            errors.append(f"{seed_path}: source #{index} missing id")
        elif normalized_source_id in source_ids:
            errors.append(f"{seed_path}: duplicate source id {source_id!r}")
        else:
            source_ids.add(normalized_source_id)
        if not str(source.get("title") or source.get("name") or "").strip():
            errors.append(f"{seed_path}: source {source_id or index!r} missing title")
        if not str(source.get("url") or source.get("link") or source.get("local_path") or "").strip():
            errors.append(f"{seed_path}: source {source_id or index!r} missing url or local_path")
    technique_ids: set[str] = set()
    for index, technique in enumerate(techniques, start=1):
        technique_id = str(technique.get("id") or technique.get("key") or technique.get("technique_id") or index).strip()
        normalized_technique_id = sanitize_key(technique_id, fallback="")
        if normalized_technique_id in technique_ids:
            errors.append(f"{seed_path}: duplicate technique id {technique_id!r}")
        else:
            technique_ids.add(normalized_technique_id)
        if not str(technique.get("title") or technique.get("name") or "").strip():
            errors.append(f"{seed_path}: technique {technique_id!r} missing title")
        if not str(technique.get("summary") or technique.get("description") or "").strip():
            errors.append(f"{seed_path}: technique {technique_id!r} missing summary")
        if not str(technique.get("vulnerability_pack") or technique.get("focus") or "").strip():
            errors.append(f"{seed_path}: technique {technique_id!r} missing vulnerability_pack")
        declared_source_ids = _string_list(technique.get("source_ids") or technique.get("sources"))
        if not declared_source_ids:
            errors.append(f"{seed_path}: technique {technique_id!r} missing source_ids")
        for source_id in declared_source_ids:
            if sanitize_key(source_id, fallback="") not in source_ids:
                errors.append(f"{seed_path}: technique {technique_id!r} references unknown source id {source_id!r}")
        applies_to_all = str(technique.get("applies_to_all") or "").strip().lower() in {"1", "true", "yes", "on"}
        target_keys = _string_list(technique.get("target_pack_keys") or technique.get("target_packs"))
        surface_kinds = _string_list(technique.get("applicable_surface_kinds") or technique.get("surface_kinds"))
        if not applies_to_all and not target_keys:
            errors.append(f"{seed_path}: technique {technique_id!r} missing target_pack_keys")
        if not applies_to_all and not surface_kinds:
            errors.append(f"{seed_path}: technique {technique_id!r} missing applicable_surface_kinds")
    return errors


def _read_json_or_jsonl(path: Path) -> Any:
    text = path.expanduser().read_text(encoding="utf-8")
    if not text.strip():
        return {"sources": [], "technique_packs": []}
    if path.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    return json.loads(text)


def _payload_sections(payload: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    sources: list[dict[str, Any]] = []
    techniques: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        sources.extend(_dict_rows(payload.get("sources")))
        techniques.extend(_dict_rows(payload.get("technique_packs") or payload.get("techniques")))
        if payload.get("type") in {"source", "technique", "technique_pack"}:
            extra_sources, extra_techniques = _payload_sections([payload])
            sources.extend(extra_sources)
            techniques.extend(extra_techniques)
    elif isinstance(payload, list):
        for row in payload:
            if not isinstance(row, dict):
                continue
            row_type = str(row.get("type") or row.get("record_type") or "").strip()
            if row_type == "source":
                sources.append(row)
            elif row_type in {"technique", "technique_pack"}:
                techniques.append(row)
            elif "summary" in row and ("target_pack_keys" in row or "vulnerability_pack" in row):
                techniques.append(row)
            elif "url" in row or "title" in row:
                sources.append(row)
    return sources, techniques


def _dict_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list | tuple | set):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _scout_brief(manifest: dict[str, Any]) -> str:
    return f"""# AppMap Research Scout Brief

Program: {manifest["program"]}
Focus: {manifest["focus"]}
Target kind: {manifest["target_kind"]}
Categories: {", ".join(manifest["category"]) or "-"}
Research query: {" ".join(manifest["research_query_terms"]) or "-"}

Find and curate source URLs for this category/class. Write only cited candidate
sources to `sources.todo.jsonl`, one JSON object per line.

Rules:
- Do not probe the target program or target infrastructure.
- Do not ask AppMap to search, crawl, or browse.
- Prefer primary documentation, advisories, postmortems, framework docs, and
  high-signal writeups with stable URLs.
- Record why each source is relevant and which technique class it supports.

Suggested JSONL row:
```json
{{"url":"https://example.org/source","title":"Source title","publisher":"Publisher","category":"{manifest["research_query"]["query_key"]}","why_relevant":"Short cited reason"}}
```
"""


def _validator_brief(manifest: dict[str, Any]) -> str:
    return f"""# AppMap Research Validator Brief

Program: {manifest["program"]}
Focus: {manifest["focus"]}
Target kind: {manifest["target_kind"]}

Review `sources.todo.jsonl`, discard weak or duplicate sources, and write
`validated_research_seed.json` for AppMap local ingest.

Output schema:
```json
{{
  "sources": [
    {{"id": "S0001", "title": "Source title", "url": "https://example.org/source", "summary": "What this source supports."}}
  ],
  "technique_packs": [
    {{
      "id": "short-technique-id",
      "title": "Technique title",
      "summary": "Concrete technique and preconditions.",
      "vulnerability_pack": "{manifest["focus"]}",
      "target_pack_keys": ["node"],
      "applicable_surface_kinds": ["config"],
      "source_ids": ["S0001"],
      "guidance": ["What AppMap should look for in local code."]
    }}
  ]
}}
```

Validation requirements:
- Every source has `id`, `title`, and an explicit `url` or `local_path`.
- Every technique has source citations, vulnerability focus, and explicit
  applicability through `target_pack_keys` and `applicable_surface_kinds`, unless
  `applies_to_all` is deliberately set.
- Do not fetch URLs or probe any target from this wrapper.
"""


def _campaign_readme(manifest: dict[str, Any]) -> str:
    seed_path = manifest["paths"]["validated_research_seed"]
    return f"""# AppMap Research-Librarian Campaign

This workspace is an offline staging area for AppMap research seeds. The wrapper
does not perform network calls, browser automation, search scraping, crawling, or
target probing.

## Flow

1. Give `scout_brief.md` to a research scout agent.
2. Put curated URL candidates in `sources.todo.jsonl`.
3. Give `validator_brief.md` to a validator agent.
4. Write structured seed data to `validated_research_seed.json`.
5. Validate locally:

```bash
python3 agents/appmap_research_librarian.py validate {shlex.quote(manifest["paths"]["root"])}
```

## JSONL Candidate Example

```json
{{"url":"https://example.org/source","title":"Source title","publisher":"Publisher","category":"{manifest["research_query"]["query_key"]}","why_relevant":"Short cited reason"}}
```

## AppMap Ingest

Default local seed mode:

```bash
python3 agents/app_mapper.py {shlex.quote(manifest["program"])} <target_path> --target-kind {shlex.quote(manifest["target_kind"])} --focus {shlex.quote(manifest["focus"])} --research-mode local --research-seed {shlex.quote(seed_path)}
```

Explicit validated web-source mode:

```bash
python3 agents/appmap_research_librarian.py plan-appmap {shlex.quote(manifest["paths"]["root"])} <target_path> --use-web-sources
```
"""


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
