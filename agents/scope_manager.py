#!/usr/bin/env python3
"""Scope manager for bug bounty programs."""

from pathlib import Path
from urllib.parse import urlparse
import re


class ScopeManager:
    """Load and validate scope for a bug bounty program."""
    
    RECON_BASE = Path.home() / "Shared" / "bounty_recon"
    
    def __init__(self, program: str):
        self.program = program
        self.scope_dir = self.RECON_BASE / program / "scope"
        self.domains = self._load_domains()
        self.urls = self._load_urls()
    
    def _load_domains(self) -> set:
        """Load domains from scope files."""
        domains = set()
        for fname in ["in-scope.txt", "domains.txt", "scope.txt"]:
            fpath = self.scope_dir / fname
            if fpath.exists():
                for line in fpath.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        domains.add(line)
        return domains
    
    def _load_urls(self) -> set:
        """Load URLs from scope files."""
        urls = set()
        for fname in ["in-scope.txt", "scope.txt"]:
            fpath = self.scope_dir / fname
            if fpath.exists():
                for line in fpath.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and line.startswith("http"):
                        urls.add(line)
        return urls
    
    def is_in_scope(self, target: str) -> bool:
        """Check if target is in scope."""
        parsed = urlparse(target)
        host = parsed.netloc.lower()
        
        # Check exact domain
        if host in self.domains:
            return True
        
        # Check wildcard (*.example.com)
        for domain in self.domains:
            if domain.startswith("*."):
                base = domain[2:]
                if host.endswith(base) or host == base:
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


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: scope_manager.py <program>")
        sys.exit(1)
    
    mgr = ScopeManager(sys.argv[1])
    print(f"Program: {mgr.program}")
    print(f"Domains: {len(mgr.domains)}")
    print(f"URLs: {len(mgr.urls)}")
    if mgr.domains:
        print("In-scope domains:")
        for d in mgr.get_in_scope_domains()[:10]:
            print(f"  - {d}")
