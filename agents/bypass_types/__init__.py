"""
bypass_types — Lightweight bypass modules for the meta-harness orchestrator.

Each module exposes a class following the BypassModule interface:
    class FooBypass:
        name: str
        description: str
        requires_param: bool   # True if a --param is needed to operate

        async def detect(target, client, limiter) -> bool
        async def scan(target, client, sem, limiter, param=None) -> list[BypassResult]

Available modules:
  cors      — CORS misconfiguration
  xxe       — XML External Entity injection
  traversal — Path traversal (basic file read)
  ssti      — Server-Side Template Injection
  race      — Race condition / TOCTOU
  idor      — Insecure Direct Object Reference
"""

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Shared result type
# ---------------------------------------------------------------------------

@dataclass
class BypassResult:
    success: bool
    vuln_type: str
    technique: str
    category: str
    payload: str
    url: str
    status_code: int
    evidence: str
    note: str = ""

    def to_line(self) -> str:
        status = "HIT" if self.success else "miss"
        return (
            f"[{status}] [{self.vuln_type}] [{self.category}/{self.technique}] "
            f"{self.url} | {self.payload!r} | HTTP {self.status_code}"
        )


# ---------------------------------------------------------------------------
# Module registry (imported here for convenience)
# ---------------------------------------------------------------------------

from .cors import CORSBypass
from .xxe import XXEBypass
from .traversal import TraversalBypass
from .ssti import SSTIBypass
from .race import RaceBypass
from .idor import IDORBypass

# Ordered list used by the full sweep
ALL_MODULES = [
    CORSBypass,
    XXEBypass,
    TraversalBypass,
    SSTIBypass,
    RaceBypass,
    IDORBypass,
]

__all__ = [
    "BypassResult",
    "CORSBypass",
    "XXEBypass",
    "TraversalBypass",
    "SSTIBypass",
    "RaceBypass",
    "IDORBypass",
    "ALL_MODULES",
]
