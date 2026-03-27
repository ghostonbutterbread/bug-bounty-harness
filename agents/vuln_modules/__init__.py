"""
vuln_modules — standalone vulnerability scanning modules for bug bounty recon.

Available modules:
  lfi           — Local File Inclusion (path traversal, PHP wrappers, proc)
  bypass403     — 403 Forbidden bypass (headers, path manipulation, methods)
  open_redirect — Open redirect detection (3xx, meta/JS redirect)
  ssrf          — Server-Side Request Forgery (internal/cloud metadata probing)

Each module exposes a class with a scan() method returning a dict finding or None.
"""

from .lfi import LFIModule
from .bypass403 import Bypass403
from .open_redirect import OpenRedirect
from .ssrf import SSRFModule

__all__ = ["LFIModule", "Bypass403", "OpenRedirect", "SSRFModule"]
