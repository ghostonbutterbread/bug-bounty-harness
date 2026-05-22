#!/usr/bin/env python3
"""Scope manager for bug bounty programs."""

import argparse
import json
from pathlib import Path
from textwrap import dedent
from urllib.parse import urlparse


class ScopeManager:
    """Load and validate scope for a bug bounty program."""
    
    SCOPES_BASE = Path.home() / "Shared" / "scopes"
    LEGACY_RECON_BASE = Path.home() / "Shared" / "bounty_recon"
    
    def __init__(self, program: str):
        self.program = program
        self.scope_dir = self.SCOPES_BASE / program
        self.legacy_scope_dir = self.LEGACY_RECON_BASE / program / "scope"
        self.policy = self._load_policy()
        self.platform = self.policy.get("platform", "unknown")
        self.source_url = self.policy.get("source_url")
        self.source_brief_url = self.policy.get("source_brief_url")
        self.blocked_or_sensitive_classes = self.policy.get("blocked_or_sensitive_classes", [])
        self.domains = self._load_domains()
        self.urls = self._load_urls()

    def _candidate_files(self, names: list[str]) -> list[Path]:
        paths = [self.scope_dir / name for name in names]
        paths.extend(self.legacy_scope_dir / name for name in names)
        return paths

    def _load_policy(self) -> dict:
        """Load normalized rules/platform metadata when available."""
        path = self.scope_dir / "rules-of-engagement.json"
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return {}
    
    def _load_domains(self) -> set:
        """Load domains from scope files."""
        domains = set()
        for fpath in self._candidate_files(["in-scope.txt", "domains.txt", "scope.txt"]):
            if fpath.exists():
                for line in fpath.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("http"):
                        domains.add(line)
        return domains
    
    def _load_urls(self) -> set:
        """Load URLs from scope files."""
        urls = set()
        for fpath in self._candidate_files(["in-scope.txt", "scope.txt"]):
            if fpath.exists():
                for line in fpath.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and line.startswith("http"):
                        urls.add(line)
        return urls

    def _extract_host(self, target: str) -> str:
        """Extract a hostname from either a URL or a bare host input."""
        if not target:
            return ""

        parsed = urlparse(target)
        if parsed.hostname:
            return parsed.hostname.lower()

        host = parsed.path.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        return host.lower()
    
    def is_in_scope(self, target: str) -> bool:
        """Check if target is in scope."""
        parsed = urlparse(target)
        host = self._extract_host(target)
        
        # Check exact domain
        if host in self.domains:
            return True
        
        # Check wildcard (*.example.com)
        for domain in self.domains:
            if domain.startswith("*."):
                base = domain[2:]
                if host == base or host.endswith(f".{base}"):
                    return True
        
        # Check if URL is in scope
        if target.rstrip("/") in self.urls:
            return True
        
        # Check base URL
        base = f"{parsed.scheme}://{host}"
        if base.rstrip("/") in self.urls:
            return True
        
        return False
    
    def get_in_scope_domains(self) -> list:
        """Get list of in-scope domains."""
        return sorted(self.domains)
    
    def save_scope(self, domains: list, urls: list):
        """Save scope data to files."""
        self.scope_dir.mkdir(parents=True, exist_ok=True)
        
        with open(self.scope_dir / "in-scope.txt", "w") as f:
            f.write("# In-scope domains and URLs\n")
            for domain in sorted(domains):
                f.write(f"{domain}\n")
            for url in sorted(urls):
                f.write(f"{url}\n")
        
        print(f"[+] Saved {len(domains)} domains and {len(urls)} URLs to {self.scope_dir}")


def build_arg_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        description="Inspect saved in-scope domains and URLs for a program.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent(
            """\
            Example:
              python3 agents/scope_manager.py adobe

            Output:
              Reads from ~/Shared/scopes/<program>/ with legacy fallback.
            """
        ),
    )


def main() -> int:
    parser = build_arg_parser()
    parser.add_argument("program", help="Bug bounty program slug")
    args = parser.parse_args()

    mgr = ScopeManager(args.program)
    print(f"Program: {mgr.program}")
    print(f"Platform: {mgr.platform}")
    print(f"Domains: {len(mgr.domains)}")
    print(f"URLs: {len(mgr.urls)}")
    if mgr.domains:
        print("In-scope domains:")
        for d in mgr.get_in_scope_domains()[:10]:
            print(f"  - {d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
