"""Artifact helpers for Shared bounty output and indexes."""

__all__ = [
    "DEFAULT_SHARED",
    "load_json",
    "main",
    "map_path",
    "normalize_entry",
    "now_utc",
    "refresh_health",
    "upsert_entry",
]


def __getattr__(name: str):
    if name in __all__:
        from . import map as artifact_map

        return getattr(artifact_map, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
