"""Offline import compatibility for direct users of the WAF module."""
import runpy
import sys
from pathlib import Path


def test_waf_import_from_agents_directory_without_repo_on_path(monkeypatch):
    root = Path(__file__).resolve().parents[1]
    agents = root / 'agents'
    with monkeypatch.context() as patch:
        patch.chdir(agents)
        patch.setattr(sys, 'path', [str(agents)] + [p for p in sys.path if p and Path(p).resolve() != root])
        for name in list(sys.modules):
            if name == 'agents' or name.startswith('agents.'):
                patch.delitem(sys.modules, name, raising=False)
        module = runpy.run_path(str(agents / 'waf_interceptor.py'), run_name='waf_interceptor')
        assert callable(module['WAFInterceptor'])
