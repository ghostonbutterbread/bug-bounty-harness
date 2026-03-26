"""
Program Config — Loads per-program settings from bounty_recon/{program}/.

Reads:
- rate_limit.conf    → requests per second limit
- scope/scope.md     → program metadata, notes, credentials path

Usage:
    from program_config import ProgramConfig
    cfg = ProgramConfig("superdrug")
    cfg.rate_limit_rps    # 5.0
    cfg.rate_limit_rpm    # 300
    cfg.credentials_path   # Path to credentials dir
    cfg.is_rate_limit_bypass_in_scope  # False (superdrug excludes it)
"""

import os
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

BASE_DIR = Path.home() / "Shared" / "bounty_recon"


@dataclass
class ProgramConfig:
    """Loaded configuration for a bug bounty program."""

    program: str
    rate_limit_rps: float = 5.0       # requests per second
    rate_limit_rpm: int = 300         # requests per minute (derived)
    timeout_per_request: float = 10.0  # seconds
    is_rate_limit_bypass_in_scope: bool = False
    is_csrf_in_scope: bool = True
    credentials_path: Optional[Path] = None
    scope_domains: list = None
    notes: str = ""

    def __post_init__(self):
        if self.scope_domains is None:
            self.scope_domains = []
        # Derive RPM from RPS
        if self.rate_limit_rps > 0:
            self.rate_limit_rpm = int(self.rate_limit_rps * 60)
        else:
            self.rate_limit_rpm = 30  # safe default

    @classmethod
    def load(cls, program: str) -> "ProgramConfig":
        """
        Load program config from ~/Shared/bounty_recon/{program}/.
        Falls back to safe defaults if files not found.
        """
        safe = re.sub(r"[^a-zA-Z0-9_\-]", "", program.lower().replace(" ", "_"))
        program_dir = BASE_DIR / safe
        conf_path = program_dir / "rate_limit.conf"
        scope_md_path = program_dir / "scope" / "scope.md"

        cfg = cls(program=safe)

        if program_dir.exists():
            cfg.credentials_path = program_dir / "credentials"

        # Load rate_limit.conf
        if conf_path.exists():
            cfg = _parse_rate_limit_conf(conf_path, cfg)

        # Load scope/scope.md for metadata
        if scope_md_path.exists():
            cfg = _parse_scope_md(scope_md_path, cfg)

        return cfg


def _parse_rate_limit_conf(path: Path, cfg: "ProgramConfig") -> "ProgramConfig":
    """Parse rate_limit.conf format: key=value, blank lines and # comments ignored."""
    rate_limit_rps = None
    timeout = None

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            if key == "default" and val:
                try:
                    rate_limit_rps = float(val)
                except ValueError:
                    pass
            elif key == "timeout" and val:
                try:
                    timeout = float(val)
                except ValueError:
                    pass

    if rate_limit_rps is not None:
        cfg.rate_limit_rps = max(0.1, rate_limit_rps)  # minimum 0.1 req/sec
        cfg.rate_limit_rpm = int(cfg.rate_limit_rps * 60)

    if timeout is not None:
        cfg.timeout_per_request = timeout

    return cfg


def _parse_scope_md(path: Path, cfg: "ProgramConfig") -> "ProgramConfig":
    """Extract key metadata from scope.md."""
    text = path.read_text()

    # Extract rate limit note (e.g. "Rate limit: Max 5 req/sec")
    rl_match = re.search(r"rate limit[:\s]+(\d+)\s*req", text, re.IGNORECASE)
    if rl_match and rl_match.group(1):
        rps = int(rl_match.group(1))
        if rps > 0:
            cfg.rate_limit_rps = float(rps)
            cfg.rate_limit_rpm = int(rps * 60)

    # Check if rate limit bypass is OOS
    for line in text.splitlines():
        if "out of scope" in line.lower() and "rate limit" in line.lower():
            cfg.is_rate_limit_bypass_in_scope = False
            break

    # Extract in-scope domains
    domains = re.findall(r"`?([\w\-\.]+\.(?:com|co\.uk|org|net|io))`?", text)
    if domains:
        # Deduplicate and clean
        seen = set()
        for d in domains:
            d = d.strip("`").lower().lstrip(".")
            if d not in seen and len(d) > 4:
                seen.add(d)
        cfg.scope_domains = sorted(seen)[:20]  # cap at 20

    # Extract notes (useful metadata)
    notes_lines = []
    for line in text.splitlines():
        if any(line.startswith(m) for m in ("**", "#", "##", "###")):
            notes_lines.append(line.strip("#* ").strip())

    cfg.notes = " | ".join(notes_lines[:5])

    return cfg


def rate_limit_for_program(program: str) -> tuple[int, int]:
    """
    Convenience: return (rpm, rps) for a program.
    Uses rate_limit.conf if present, else safe defaults.
    """
    cfg = ProgramConfig.load(program)
    return cfg.rate_limit_rpm, int(cfg.rate_limit_rps)
