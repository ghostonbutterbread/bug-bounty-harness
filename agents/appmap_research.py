"""AppMap research collection, query normalization, and artifact shaping."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable


RESEARCH_MODES = ("local", "web", "hybrid")

_PLATFORM_ALIASES = {
    "electron": "electron",
    "electronjs": "electron",
    "node": "node",
    "nodejs": "node",
    "javascript": "javascript",
    "js": "javascript",
    "typescript": "typescript",
    "ts": "typescript",
    "python": "python",
    "py": "python",
    "django": "django",
    "flask": "flask",
    "react": "react",
    "nextjs": "nextjs",
    "next": "nextjs",
}
_VULNERABILITY_ALIASES = {
    "rce": "rce",
    "command-injection": "rce",
    "command": "rce",
    "xss": "xss",
    "cross-site-scripting": "xss",
    "ssrf": "ssrf",
    "sqli": "sqli",
    "sql-injection": "sqli",
    "idor": "idor",
    "csrf": "csrf",
    "lfi": "lfi",
    "open-redirect": "open-redirect",
    "redirect": "open-redirect",
    "race": "race",
}
_CATEGORY_TERMS = {
    "ipc": "ipc",
    "webview": "webview",
    "config": "config",
    "deserialization": "deserialization",
    "auth": "auth",
    "oauth": "oauth",
    "sandbox": "sandbox",
    "csp": "csp",
}


@dataclass(frozen=True)
class ResearchQuery:
    raw_terms: tuple[str, ...] = ()
    normalized_terms: tuple[str, ...] = ()
    platform_candidates: tuple[str, ...] = ()
    vulnerability_candidates: tuple[str, ...] = ()
    query_key: str = "general"
    categories: tuple[str, ...] = ()

    def as_manifest(self) -> dict[str, Any]:
        return {
            "raw_terms": list(self.raw_terms),
            "normalized_terms": list(self.normalized_terms),
            "platform_candidates": list(self.platform_candidates),
            "vulnerability_candidates": list(self.vulnerability_candidates),
            "query_key": self.query_key,
            "categories": list(self.categories),
        }


@dataclass(frozen=True)
class ResearchRequest:
    program: str
    focus: str
    target_kind: str
    provider_key: str = "local-seed"
    research_mode: str = "local"
    research_query: ResearchQuery = field(default_factory=ResearchQuery)
    research_online: bool = False
    seed_paths: tuple[Path, ...] = ()
    source_urls: tuple[str, ...] = ()


class ResearchProvider:
    """Opt-in research provider interface."""

    key = "base"
    network_capable = False

    def collect(self, request: ResearchRequest) -> dict[str, Any]:
        raise NotImplementedError


class LocalSeedResearchProvider(ResearchProvider):
    """Deterministic provider backed by local seed files only."""

    key = "local-seed"

    def collect(self, request: ResearchRequest) -> dict[str, Any]:
        sources, technique_packs, errors = _collect_seed_research(request)
        cache_key = _json_digest(
            {
                "provider": self.key,
                "research_mode": request.research_mode,
                "research_query": request.research_query.as_manifest(),
                "program": request.program,
                "focus": request.focus,
                "target_kind": request.target_kind,
                "seed_paths": [str(path.expanduser().resolve(strict=False)) for path in request.seed_paths],
                "sources": sources,
                "technique_packs": technique_packs,
            }
        )
        return {
            "manifest": _research_manifest(
                request,
                provider_key=self.key,
                cache_key=cache_key,
                network_access=False,
                network_policy="local seed provider only; no network I/O",
                sources=sources,
                technique_packs=technique_packs,
                errors=errors,
                fetched=[],
            ),
            "sources": sources,
            "technique_packs": technique_packs,
        }


class WebFetchResearchProvider(ResearchProvider):
    """Conservative HTTPS-only fetcher for operator-supplied source URLs."""

    key = "web-fetch"
    network_capable = True
    max_source_urls = 10
    max_bytes = 256 * 1024
    timeout_seconds = 5.0

    def __init__(
        self,
        *,
        opener: Callable[..., Any] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._opener = opener or _non_redirecting_urlopen
        self._now = now or (lambda: datetime.now(timezone.utc))

    def collect(self, request: ResearchRequest) -> dict[str, Any]:
        if not (request.research_online or request.research_mode == "web"):
            raise ValueError("web research requires --research-mode web or --research-online")
        if not request.source_urls:
            raise ValueError("web research requires at least one --research-source-url")
        if len(request.source_urls) > self.max_source_urls:
            raise ValueError(f"--research-source-url accepts at most {self.max_source_urls} URLs")
        return self._collect_web(request, seed_first=True)

    def _collect_web(self, request: ResearchRequest, *, seed_first: bool) -> dict[str, Any]:
        if seed_first:
            sources, technique_packs, errors = _collect_seed_research(request)
        else:
            sources, technique_packs, errors = [], [], []
        known_source_ids = {source["id"] for source in sources}
        known_technique_ids = {technique["id"] for technique in technique_packs}
        fetched: list[dict[str, Any]] = []

        for url in request.source_urls:
            fetch_record, source, metadata = self._fetch_source(url, len(sources) + 1, request)
            fetched.append(fetch_record)
            if source is None:
                if fetch_record.get("error"):
                    errors.append(f"{url}: {fetch_record['error']}")
                continue

            raw_source_id = str(source.get("id") or source.get("source_id") or "").strip()
            if source["id"] in known_source_ids:
                source["id"] = _stable_research_id(
                    "",
                    prefix="W",
                    index=len(sources) + 1,
                    payload=source,
                    known_ids=known_source_ids,
                )
                source["citation"] = f"[{source['id']}]"
            known_source_ids.add(source["id"])
            sources.append(source)

            if metadata is None:
                continue
            for metadata_error in metadata.get("errors", []):
                errors.append(str(metadata_error))

            aliases: dict[str, str] = {}
            if raw_source_id:
                aliases[raw_source_id] = source["id"]
            seed_source_ids = [source["id"]]
            for metadata_source in metadata.get("sources", []):
                normalized_source = _normalize_research_source(
                    metadata_source,
                    request=request,
                    seed_path=None,
                    index=len(sources) + 1,
                    known_ids=known_source_ids,
                    default_url=str(metadata_source.get("url") or url),
                    default_source_type="web-source-metadata",
                    metadata_origin=url,
                )
                metadata_raw_id = str(metadata_source.get("id") or metadata_source.get("source_id") or "").strip()
                if metadata_raw_id:
                    aliases[metadata_raw_id] = normalized_source["id"]
                known_source_ids.add(normalized_source["id"])
                seed_source_ids.append(normalized_source["id"])
                sources.append(normalized_source)

            for technique in metadata.get("technique_packs", []):
                normalized_technique = _normalize_technique_pack(
                    technique,
                    request=request,
                    seed_path=Path(url),
                    index=len(technique_packs) + 1,
                    source_aliases=aliases,
                    seed_source_ids=seed_source_ids,
                    known_source_ids=known_source_ids,
                    known_technique_ids=known_technique_ids,
                    errors=errors,
                )
                known_technique_ids.add(normalized_technique["id"])
                technique_packs.append(normalized_technique)

        sources.sort(key=lambda item: item["id"])
        technique_packs.sort(key=lambda item: item["id"])
        cache_key = _json_digest(
            {
                "provider": self.key,
                "research_mode": request.research_mode,
                "research_query": request.research_query.as_manifest(),
                "program": request.program,
                "focus": request.focus,
                "target_kind": request.target_kind,
                "seed_paths": [str(path.expanduser().resolve(strict=False)) for path in request.seed_paths],
                "source_urls": list(request.source_urls),
                "fetched": _stable_research_cache_value(fetched),
                "sources": _stable_research_cache_value(sources),
                "technique_packs": _stable_research_cache_value(technique_packs),
            }
        )
        return {
            "manifest": _research_manifest(
                request,
                provider_key=self.key,
                cache_key=cache_key,
                network_access=True,
                network_policy=(
                    "HTTPS-only fetch of explicit --research-source-url values; no search, crawling, "
                    f"or target probing; max_bytes={self.max_bytes}; timeout_seconds={self.timeout_seconds:g}"
                ),
                sources=sources,
                technique_packs=technique_packs,
                errors=errors,
                fetched=fetched,
            ),
            "sources": sources,
            "technique_packs": technique_packs,
        }

    def _fetch_source(
        self,
        raw_url: str,
        index: int,
        request_context: ResearchRequest,
    ) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
        url = raw_url.strip()
        fetched_at = self._now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        fetch_record: dict[str, Any] = {
            "url": url,
            "requested_at": fetched_at,
            "status": "not_fetched",
            "network_access": True,
            "max_bytes": self.max_bytes,
            "timeout_seconds": self.timeout_seconds,
        }
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() != "https" or not parsed.netloc:
            fetch_record["status"] = "rejected"
            fetch_record["error"] = "research-source-url must be an absolute https URL"
            return fetch_record, None, None

        request = urllib.request.Request(url, headers={"User-Agent": "AppMapResearch/1.0"})
        try:
            with self._opener(request, timeout=self.timeout_seconds) as response:
                final_url = str(getattr(response, "url", "") or getattr(response, "geturl", lambda: url)())
                status_code = int(getattr(response, "status", 0) or getattr(response, "code", 0) or response.getcode())
                headers = getattr(response, "headers", None)
                if 300 <= status_code < 400:
                    location = _header_value(headers, "Location")
                    fetch_record.update(
                        {
                            "status": "redirect_rejected",
                            "http_status": status_code,
                            "location": location,
                            "error": _redirect_rejected_error(location),
                        }
                    )
                    return fetch_record, None, None
                if final_url and final_url != url:
                    fetch_record["status"] = "redirect_rejected"
                    fetch_record["final_url"] = final_url
                    fetch_record["error"] = _redirect_rejected_error(final_url)
                    return fetch_record, None, None
                if urllib.parse.urlsplit(final_url or url).scheme.lower() != "https":
                    fetch_record["status"] = "rejected"
                    fetch_record["final_url"] = final_url
                    fetch_record["error"] = "redirected to non-https URL"
                    return fetch_record, None, None
                content_type = _header_value(headers, "Content-Type")
                data = response.read(self.max_bytes + 1)
        except urllib.error.HTTPError as exc:
            if 300 <= int(exc.code) < 400:
                location = _header_value(getattr(exc, "headers", None), "Location")
                fetch_record.update(
                    {
                        "status": "redirect_rejected",
                        "http_status": exc.code,
                        "location": location,
                        "error": _redirect_rejected_error(location),
                    }
                )
                return fetch_record, None, None
            fetch_record.update({"status": "http_error", "http_status": exc.code, "error": str(exc.reason or exc)})
            return fetch_record, None, None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            fetch_record.update({"status": "error", "error": str(exc)})
            return fetch_record, None, None

        truncated = len(data) > self.max_bytes
        if truncated:
            data = data[: self.max_bytes]
        digest = hashlib.sha256(data).hexdigest()
        text = _decode_web_bytes(data, content_type)
        title = _extract_web_title(text) or urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1] or url
        summary = _summarize_web_text(text, content_type)
        fetch_record.update(
            {
                "status": "ok_truncated" if truncated else "ok",
                "http_status": status_code,
                "final_url": final_url,
                "content_type": content_type,
                "bytes_read": len(data),
                "truncated": truncated,
                "content_sha256": digest,
            }
        )
        if truncated:
            fetch_record["error"] = f"response truncated after {self.max_bytes} bytes"

        source_id = _stable_research_id(
            "",
            prefix="W",
            index=index,
            payload={"url": url, "content_sha256": digest},
            known_ids=set(),
        )
        source = _with_db_ready_fields(
            {
                "id": source_id,
                "title": _compact_text(title, 180),
                "url": _compact_text(final_url or url, 500),
                "source_type": "web-fetch",
                "retrieved_at": fetched_at,
                "local_path": "",
                "summary": _compact_text(summary, 1200),
                "content_sha256": digest,
                "citation": f"[{source_id}]",
                "network_access": True,
                "http_status": status_code,
                "content_type": _compact_text(content_type, 120),
                "content_bytes": len(data),
            },
            request_context,
            default_trust_score=0.55,
        )
        metadata = _web_research_metadata(text, content_type, url)
        return fetch_record, source, metadata


class HybridResearchProvider(WebFetchResearchProvider):
    """Local seed first, then explicit web fetch only when online and URLs exist."""

    key = "hybrid"
    network_capable = True

    def collect(self, request: ResearchRequest) -> dict[str, Any]:
        if len(request.source_urls) > self.max_source_urls:
            raise ValueError(f"--research-source-url accepts at most {self.max_source_urls} URLs")
        if request.research_online and request.source_urls:
            result = self._collect_web(request, seed_first=True)
            result["manifest"]["provider"] = self.key
            result["manifest"]["research_mode"] = "hybrid"
            result["manifest"]["cache_key"] = _json_digest(
                {
                    "provider": self.key,
                    "research_mode": "hybrid",
                    "research_query": request.research_query.as_manifest(),
                    "program": request.program,
                    "focus": request.focus,
                    "target_kind": request.target_kind,
                    "seed_paths": [
                        str(path.expanduser().resolve(strict=False))
                        for path in request.seed_paths
                    ],
                    "source_urls": list(request.source_urls),
                    "fetched": _stable_research_cache_value(result["manifest"].get("fetched", [])),
                    "sources": _stable_research_cache_value(result.get("sources", [])),
                    "technique_packs": _stable_research_cache_value(result.get("technique_packs", [])),
                }
            )
            return result

        sources, technique_packs, errors = _collect_seed_research(request)
        if request.source_urls and not request.research_online:
            errors.append("hybrid web fetch skipped because --research-online was not set")
        cache_key = _json_digest(
            {
                "provider": self.key,
                "research_mode": request.research_mode,
                "research_query": request.research_query.as_manifest(),
                "program": request.program,
                "focus": request.focus,
                "target_kind": request.target_kind,
                "seed_paths": [str(path.expanduser().resolve(strict=False)) for path in request.seed_paths],
                "source_urls": list(request.source_urls),
                "sources": sources,
                "technique_packs": technique_packs,
                "errors": errors,
            }
        )
        return {
            "manifest": _research_manifest(
                request,
                provider_key=self.key,
                cache_key=cache_key,
                network_access=False,
                network_policy="hybrid local phase only; web fetch requires --research-online plus explicit URLs",
                sources=sources,
                technique_packs=technique_packs,
                errors=errors,
                fetched=[],
            ),
            "sources": sources,
            "technique_packs": technique_packs,
        }


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


_NON_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler)
_VOLATILE_RESEARCH_CACHE_FIELDS = {"requested_at", "retrieved_at", "fetched_at", "generated_at"}


RESEARCH_PROVIDERS: dict[str, type[ResearchProvider]] = {
    LocalSeedResearchProvider.key: LocalSeedResearchProvider,
    WebFetchResearchProvider.key: WebFetchResearchProvider,
    HybridResearchProvider.key: HybridResearchProvider,
}


def normalize_research_query(terms: Iterable[str] = (), *, focus: str = "", target_kind: str = "") -> ResearchQuery:
    raw_terms = tuple(str(term).strip() for term in terms if str(term).strip())
    normalized_terms = tuple(dict.fromkeys(_normalize_query_term(term) for term in raw_terms if _normalize_query_term(term)))
    platform_candidates = _candidate_values(normalized_terms, _PLATFORM_ALIASES)
    vulnerability_candidates = _candidate_values(normalized_terms, _VULNERABILITY_ALIASES)
    extra_categories = _candidate_values(normalized_terms, _CATEGORY_TERMS)

    target_hint = _normalize_query_term(target_kind)
    if target_hint and target_hint not in {"auto", "unknown"}:
        for piece in re.split(r"[-_/]+", target_hint):
            if piece in _PLATFORM_ALIASES:
                platform_candidates = tuple(dict.fromkeys((*platform_candidates, _PLATFORM_ALIASES[piece])))
    focus_hint = _normalize_query_term(focus)
    if focus_hint in _VULNERABILITY_ALIASES:
        vulnerability_candidates = tuple(dict.fromkeys((*vulnerability_candidates, _VULNERABILITY_ALIASES[focus_hint])))

    categories = tuple(
        dict.fromkeys(
            [
                *(f"platform:{item}" for item in platform_candidates),
                *(f"vulnerability:{item}" for item in vulnerability_candidates),
                *extra_categories,
            ]
        )
    )
    query_key = "-".join(normalized_terms) if normalized_terms else "general"
    return ResearchQuery(
        raw_terms=raw_terms,
        normalized_terms=normalized_terms,
        platform_candidates=platform_candidates,
        vulnerability_candidates=vulnerability_candidates,
        query_key=sanitize_key(query_key, fallback="general")[:120],
        categories=categories,
    )


def _candidate_values(terms: tuple[str, ...], aliases: dict[str, str]) -> tuple[str, ...]:
    values: list[str] = []
    for term in terms:
        if term in aliases:
            values.append(aliases[term])
        for piece in re.split(r"[-_/]+", term):
            if piece in aliases:
                values.append(aliases[piece])
    return tuple(dict.fromkeys(values))


def _normalize_query_term(term: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(term).strip().lower()).strip("-")


def provider_key_for_mode(research_mode: str) -> str:
    mode = normalize_research_mode(research_mode)
    return {"local": "local-seed", "web": "web-fetch", "hybrid": "hybrid"}[mode]


def normalize_research_mode(research_mode: str) -> str:
    mode = str(research_mode or "local").strip().lower()
    if mode not in RESEARCH_MODES:
        choices = ", ".join(RESEARCH_MODES)
        raise ValueError(f"unknown research mode {research_mode!r}; expected one of: {choices}")
    return mode


def build_research_provider(name: str) -> ResearchProvider:
    try:
        provider_cls = RESEARCH_PROVIDERS[name]
    except KeyError as exc:
        choices = ", ".join(sorted(RESEARCH_PROVIDERS))
        raise ValueError(f"unknown research provider {name!r}; expected one of: {choices}") from exc
    return provider_cls()


def normalized_research_source_urls(source_urls: Iterable[str]) -> tuple[str, ...]:
    return tuple(str(url).strip() for url in source_urls if str(url).strip())


def validate_research_options(
    *,
    research_online: bool,
    provider: ResearchProvider,
    source_urls: Iterable[str],
    research_mode: str = "local",
) -> tuple[str, ...]:
    mode = normalize_research_mode(research_mode)
    urls = normalized_research_source_urls(source_urls)
    max_source_urls = int(getattr(provider, "max_source_urls", WebFetchResearchProvider.max_source_urls))
    if len(urls) > max_source_urls:
        raise ValueError(f"--research-source-url accepts at most {max_source_urls} URLs")
    effective_research_online = bool(research_online or mode == "web")
    if mode == "web" and not urls:
        raise ValueError("--research-mode web requires at least one --research-source-url")
    if provider.key == WebFetchResearchProvider.key:
        if not effective_research_online:
            raise ValueError("web research requires --research-mode web or --research-online")
        if not urls:
            raise ValueError("web research requires at least one --research-source-url")
    if mode == "local" and urls and not provider.network_capable:
        raise ValueError("--research-source-url requires --research-mode web|hybrid or --research-provider web-fetch")
    return urls


def generate_research_artifacts(
    result: Any,
    *,
    research_online: bool = False,
    seed_paths: Iterable[Path] = (),
    source_urls: Iterable[str] = (),
    research_provider: str = "local-seed",
    research_mode: str | None = None,
    research_query_terms: Iterable[str] = (),
    provider: ResearchProvider | None = None,
) -> dict[str, Any] | None:
    seeds = tuple(path.expanduser() for path in seed_paths)
    provider_key = provider.key if provider is not None else research_provider
    if research_mode is None:
        mode = "web" if provider_key == "web-fetch" else "hybrid" if provider_key == "hybrid" else "local"
    else:
        mode = normalize_research_mode(research_mode)
    provider = provider or build_research_provider(provider_key_for_mode(mode) if research_provider == "local-seed" else research_provider)
    effective_research_online = bool(research_online or mode == "web")
    urls = validate_research_options(
        research_online=effective_research_online,
        provider=provider,
        source_urls=source_urls,
        research_mode=mode,
    )
    if not effective_research_online and not seeds and not urls and not tuple(research_query_terms):
        return None
    query = normalize_research_query(
        research_query_terms,
        focus=getattr(result, "focus", ""),
        target_kind=getattr(getattr(result, "profile", None), "target_kind", ""),
    )
    return provider.collect(
        ResearchRequest(
            program=getattr(getattr(result, "profile", None), "program", ""),
            focus=getattr(result, "focus", ""),
            target_kind=getattr(getattr(result, "profile", None), "target_kind", ""),
            provider_key=provider.key,
            research_mode=mode,
            research_query=query,
            research_online=effective_research_online,
            seed_paths=seeds,
            source_urls=urls,
        )
    )


def bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def sanitize_key(value: str, *, fallback: str = "target") -> str:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", str(value).strip().lower()).strip("-_")
    return slug or fallback


def _non_redirecting_urlopen(request: urllib.request.Request, *, timeout: float) -> Any:
    return _NON_REDIRECT_OPENER.open(request, timeout=timeout)


def _redirect_rejected_error(location: str) -> str:
    if location:
        return f"redirect rejected; Location: {location}"
    return "redirect rejected; Location header missing"


def _stable_research_cache_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _stable_research_cache_value(item)
            for key, item in value.items()
            if str(key) not in _VOLATILE_RESEARCH_CACHE_FIELDS
        }
    if isinstance(value, list):
        return [_stable_research_cache_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_stable_research_cache_value(item) for item in value)
    return value


def _collect_seed_research(request: ResearchRequest) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    sources: list[dict[str, Any]] = []
    technique_packs: list[dict[str, Any]] = []
    errors: list[str] = []
    known_source_ids: set[str] = set()
    known_technique_ids: set[str] = set()

    for seed_path in request.seed_paths:
        seed = _load_research_seed(seed_path, errors)
        aliases: dict[str, str] = {}
        seed_sources: list[str] = []
        for source in seed.get("sources", []):
            normalized = _normalize_research_source(
                source,
                request=request,
                seed_path=seed_path,
                index=len(sources) + 1,
                known_ids=known_source_ids,
            )
            raw_id = str(source.get("id") or source.get("source_id") or "").strip()
            if raw_id:
                aliases[raw_id] = normalized["id"]
            known_source_ids.add(normalized["id"])
            seed_sources.append(normalized["id"])
            sources.append(normalized)
        for technique in seed.get("technique_packs", []):
            technique_packs.append(
                _normalize_technique_pack(
                    technique,
                    request=request,
                    seed_path=seed_path,
                    index=len(technique_packs) + 1,
                    source_aliases=aliases,
                    seed_source_ids=seed_sources,
                    known_source_ids=known_source_ids,
                    known_technique_ids=known_technique_ids,
                    errors=errors,
                )
            )
            known_technique_ids.add(technique_packs[-1]["id"])

    sources.sort(key=lambda item: item["id"])
    technique_packs.sort(key=lambda item: item["id"])
    return sources, technique_packs, errors


def _research_manifest(
    request: ResearchRequest,
    *,
    provider_key: str,
    cache_key: str,
    network_access: bool,
    network_policy: str,
    sources: list[dict[str, Any]],
    technique_packs: list[dict[str, Any]],
    errors: list[str],
    fetched: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "enabled": bool(request.research_online or request.seed_paths or request.source_urls or request.research_query.raw_terms),
        "provider": provider_key,
        "research_mode": request.research_mode,
        "research_query": request.research_query.as_manifest(),
        "categories": list(request.research_query.categories),
        "validation_status": "unreviewed",
        "source_type": "research-manifest",
        "cache_key": cache_key,
        "cache_policy": "research artifacts are the offline cache for reproducible reuse",
        "online_requested": bool(request.research_online),
        "network_access": network_access,
        "network_policy": network_policy,
        "program": request.program,
        "focus": request.focus,
        "target_kind": request.target_kind,
        "seed_paths": [str(path.expanduser().resolve(strict=False)) for path in request.seed_paths],
        "source_urls": list(request.source_urls),
        "fetched": fetched,
        "counts": {"sources": len(sources), "technique_packs": len(technique_packs), "errors": len(errors)},
        "errors": errors,
    }


def _load_research_seed(seed_path: Path, errors: list[str]) -> dict[str, list[dict[str, Any]]]:
    path = seed_path.expanduser()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"{path}: failed to read seed: {exc}")
        return {"sources": [], "technique_packs": []}
    stripped = text.strip()
    if not stripped:
        return {"sources": [], "technique_packs": []}

    try:
        if path.suffix.lower() == ".jsonl":
            payload: Any = []
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    payload.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    errors.append(f"{path}: line {line_number}: invalid JSON: {exc.msg}")
        else:
            payload = json.loads(stripped)
    except json.JSONDecodeError:
        source = {
            "title": path.name,
            "source_type": "local-text-seed",
            "local_path": str(path.resolve(strict=False)),
            "summary": _compact_text(stripped, 900),
        }
        return {"sources": [source], "technique_packs": []}

    return _research_payload_sections(payload, origin=str(path), errors=errors)


def _load_research_payload_text(text: str, *, origin: str, errors: list[str], jsonl: bool) -> dict[str, list[dict[str, Any]]]:
    stripped = text.strip()
    if not stripped:
        return {"sources": [], "technique_packs": []}
    try:
        if jsonl:
            payload: Any = []
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    payload.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    errors.append(f"{origin}: line {line_number}: invalid JSON: {exc.msg}")
        else:
            payload = json.loads(stripped)
    except json.JSONDecodeError as exc:
        errors.append(f"{origin}: invalid JSON research metadata: {exc.msg}")
        return {"sources": [], "technique_packs": []}
    return _research_payload_sections(payload, origin=origin, errors=errors)


def _research_payload_sections(payload: Any, *, origin: str, errors: list[str]) -> dict[str, list[dict[str, Any]]]:
    sources: list[dict[str, Any]] = []
    technique_packs: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        sources.extend(_dict_rows(payload.get("sources")))
        technique_packs.extend(
            _dict_rows(
                payload.get("technique_packs")
                if payload.get("technique_packs") is not None
                else payload.get("techniques")
            )
        )
        if str(payload.get("type") or "").strip() in {"source", "technique", "technique_pack"}:
            rows = _research_payload_sections([payload], origin=origin, errors=errors)
            sources.extend(rows["sources"])
            technique_packs.extend(rows["technique_packs"])
    elif isinstance(payload, list):
        for row in payload:
            if not isinstance(row, dict):
                continue
            row_type = str(row.get("type") or row.get("record_type") or "").strip()
            if row_type == "source":
                sources.append(row)
            elif row_type in {"technique", "technique_pack"}:
                technique_packs.append(row)
            elif "summary" in row and ("target_pack_keys" in row or "vulnerability_pack" in row):
                technique_packs.append(row)
            elif "url" in row or "title" in row:
                sources.append(row)
    else:
        errors.append(f"{origin}: unsupported research seed JSON root")
    return {"sources": sources, "technique_packs": technique_packs}


def _dict_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _normalize_research_source(
    source: dict[str, Any],
    *,
    request: ResearchRequest,
    seed_path: Path | None,
    index: int,
    known_ids: set[str],
    default_url: str = "",
    default_source_type: str = "seed",
    metadata_origin: str = "",
) -> dict[str, Any]:
    raw_id = str(source.get("id") or source.get("source_id") or "").strip()
    source_id = _stable_research_id(raw_id, prefix="S", index=index, payload=source, known_ids=known_ids)
    fallback_title = seed_path.name if seed_path is not None else default_url or source_id
    local_path = str(source.get("local_path") or "")
    if not local_path and seed_path is not None:
        local_path = str(seed_path.resolve(strict=False))
    return _with_db_ready_fields(
        {
            "id": source_id,
            "title": _compact_text(str(source.get("title") or source.get("name") or fallback_title), 180),
            "url": _compact_text(str(source.get("url") or source.get("link") or default_url), 500),
            "source_type": _compact_text(str(source.get("source_type") or default_source_type), 80),
            "retrieved_at": _compact_text(str(source.get("retrieved_at") or source.get("published_at") or ""), 80),
            "local_path": _compact_text(local_path, 500),
            "summary": _compact_text(str(source.get("summary") or source.get("description") or ""), 1200),
            "content_sha256": _json_digest(source),
            "citation": f"[{source_id}]",
            "metadata_origin": _compact_text(metadata_origin, 500),
        },
        request,
        default_trust_score=0.65 if seed_path is not None else 0.5,
    )


def _normalize_technique_pack(
    technique: dict[str, Any],
    *,
    request: ResearchRequest,
    seed_path: Path,
    index: int,
    source_aliases: dict[str, str],
    seed_source_ids: list[str],
    known_source_ids: set[str],
    known_technique_ids: set[str],
    errors: list[str],
) -> dict[str, Any]:
    raw_id = str(technique.get("id") or technique.get("key") or technique.get("technique_id") or "").strip()
    technique_id = _stable_research_id(raw_id, prefix="T", index=index, payload=technique, known_ids=known_technique_ids)
    source_ids: list[str] = []
    requested_source_ids = _string_list(technique.get("source_ids") or technique.get("sources"))
    for item in requested_source_ids:
        raw_source_id = str(item).strip()
        if not raw_source_id:
            continue
        resolved_source_id = source_aliases.get(raw_source_id) or sanitize_key(raw_source_id, fallback="")
        if resolved_source_id in known_source_ids:
            source_ids.append(resolved_source_id)
        else:
            errors.append(f"{seed_path}: technique {technique_id} references unknown source id {raw_source_id!r}")
    if not requested_source_ids:
        source_ids = list(seed_source_ids)
    source_ids = sorted(dict.fromkeys(source_ids))
    return _with_db_ready_fields(
        {
            "id": technique_id,
            "title": _compact_text(str(technique.get("title") or technique.get("name") or technique_id), 180),
            "summary": _compact_text(str(technique.get("summary") or technique.get("description") or ""), 1400),
            "vulnerability_pack": _compact_text(str(technique.get("vulnerability_pack") or technique.get("focus") or request.focus), 80),
            "target_pack_keys": _string_list(technique.get("target_pack_keys") or technique.get("target_packs")),
            "applicable_surface_kinds": _string_list(technique.get("applicable_surface_kinds") or technique.get("surface_kinds")),
            "applies_to_all": bool_value(technique.get("applies_to_all")),
            "guidance": [_compact_text(item, 500) for item in _string_list(technique.get("guidance") or technique.get("steps"))],
            "source_ids": source_ids,
            "citations": [f"[{source_id}]" for source_id in source_ids],
            "seed_path": str(seed_path.resolve(strict=False)),
            "content_sha256": _json_digest(technique),
            "source_type": _compact_text(str(technique.get("source_type") or "technique-pack"), 80),
        },
        request,
        default_trust_score=0.55,
    )


def _with_db_ready_fields(record: dict[str, Any], request: ResearchRequest, *, default_trust_score: float) -> dict[str, Any]:
    query = request.research_query
    categories = list(dict.fromkeys([*_string_list(record.get("categories")), *query.categories]))
    trust_raw = record.get("trust_score", default_trust_score)
    try:
        trust_score = max(0.0, min(1.0, float(trust_raw)))
    except (TypeError, ValueError):
        trust_score = default_trust_score
    record.update(
        {
            "research_mode": request.research_mode,
            "research_query": query.query_key,
            "categories": categories,
            "validation_status": str(record.get("validation_status") or "unreviewed"),
            "trust_score": trust_score,
        }
    )
    return record


def _stable_research_id(value: str, *, prefix: str, index: int, payload: dict[str, Any], known_ids: set[str]) -> str:
    cleaned = sanitize_key(value, fallback="")
    if cleaned:
        candidate = cleaned[:80]
    else:
        digest = _json_digest(payload)[:10]
        candidate = f"{prefix}{index:04d}-{digest}"
    while candidate in known_ids:
        candidate = f"{candidate}-{_json_digest({'id': candidate, 'index': index})[:6]}"
    return candidate


def _json_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list | tuple | set):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


def _compact_text(value: str, limit: int) -> str:
    compacted = re.sub(r"\s+", " ", str(value or "")).strip()
    return compacted[:limit]


def _header_value(headers: Any, name: str) -> str:
    if headers is None:
        return ""
    getter = getattr(headers, "get", None)
    if callable(getter):
        value = getter(name) or getter(name.lower()) or getter(name.title())
        return str(value or "")
    return ""


def _decode_web_bytes(data: bytes, content_type: str) -> str:
    charset = ""
    match = re.search(r"charset=([\w.\-]+)", content_type or "", re.IGNORECASE)
    if match:
        charset = match.group(1)
    for encoding in (charset, "utf-8", "latin-1"):
        if not encoding:
            continue
        try:
            return data.decode(encoding, errors="replace")
        except LookupError:
            continue
    return data.decode("utf-8", errors="replace")


def _extract_web_title(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return _html_text(match.group(1))


def _summarize_web_text(text: str, content_type: str) -> str:
    if "html" in (content_type or "").lower() or re.search(r"<html\b|<body\b|<p\b", text, re.IGNORECASE):
        text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", text)
        text = _html_text(text)
    return _compact_text(text, 900)


def _html_text(text: str) -> str:
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = (
        text.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
    )
    return _compact_text(text, 1200)


def _web_research_metadata(text: str, content_type: str, url: str) -> dict[str, Any] | None:
    lower_type = (content_type or "").lower()
    path = urllib.parse.urlsplit(url).path.lower()
    if "json" not in lower_type and not path.endswith((".json", ".jsonl")):
        return None
    errors: list[str] = []
    metadata = _load_research_payload_text(text, origin=url, errors=errors, jsonl=path.endswith(".jsonl"))
    if errors:
        metadata["errors"] = errors
    return metadata
