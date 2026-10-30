import asyncio
import importlib.util
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from agents import bypass_harness as h
from agents.bypass_types.cors import CORSBypass
from agents.bypass_types.idor import IDORBypass

class Limiter:
    @asynccontextmanager
    async def http(self):
        yield
    def adapt_to_response(self, response):
        pass

def test_403_missing_baseline_not_a_miss():
    scanner = h.BypassOrchestrator()
    calls = 0
    async def get(*args, **kwargs):
        nonlocal calls
        calls += 1
        return None if calls == 1 else httpx.Response(200, text='ok')
    scanner._get = get
    async def run():
        return [r async for r in scanner._run_403('https://app.example.test/p', None, asyncio.Semaphore(1))]
    result = asyncio.run(run())[0]
    assert result.incomplete or '[unknown]' in result.to_line(), result.to_line()

def test_idor_missing_baseline_not_a_hit():
    module = IDORBypass()
    calls = 0
    async def get(*args, **kwargs):
        nonlocal calls
        calls += 1
        return None if calls == 1 else {'status': 200, 'len': 2, 'text': 'ok'}
    module._get = get
    async def run():
        return await module.scan('https://app.example.test/p/2', None, asyncio.Semaphore(1), None)
    result = asyncio.run(run())[0]
    assert not result.success and result.incomplete and '[unknown]' in result.to_line()
    assert 'baseline unavailable' in result.note

def test_idor_valid_baseline_preserves_positive():
    module = IDORBypass()
    calls = 0
    async def get(*args, **kwargs):
        nonlocal calls
        calls += 1
        return {'status': 403 if calls == 1 else 200, 'len': 2, 'text': 'ok'}
    module._get = get
    async def run():
        return await module.scan('https://app.example.test/p/2', None, asyncio.Semaphore(1), None)
    result = asyncio.run(run())[0]
    assert result.success and not result.incomplete

def test_403_valid_baseline_preserves_positive():
    scanner = h.BypassOrchestrator()
    calls = 0
    async def get(*args, **kwargs):
        nonlocal calls
        calls += 1
        return httpx.Response(403 if calls == 1 else 200, text='ok')
    scanner._get = get
    async def run():
        return [r async for r in scanner._run_403('https://app.example.test/p', None, asyncio.Semaphore(1))]
    result = asyncio.run(run())[0]
    assert result.success and not result.incomplete

def test_cors_wildcard_credentials_is_not_exploitable():
    class Client:
        async def get(self, url, headers):
            return httpx.Response(200, headers={'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true'})
    async def run():
        return await CORSBypass()._probe('https://app.example.test/p', 'evil_absolute', 'https://evil.example.test', Client(), asyncio.Semaphore(1), Limiter())
    result = asyncio.run(run())
    assert not result.success, result.to_line() + ' ' + result.evidence + ' ' + result.note
    assert result.evidence == 'ACAO: wildcard | credentials: true'

def test_cors_reflected_credentials_preserves_positive():
    class Client:
        async def get(self, url, headers):
            return httpx.Response(200, headers={'Access-Control-Allow-Origin': headers['Origin'], 'Access-Control-Allow-Credentials': 'true'})
    async def run():
        return await CORSBypass()._probe('https://app.example.test/p', 'evil_absolute', 'https://evil.example.test', Client(), asyncio.Semaphore(1), Limiter())
    result = asyncio.run(run())
    assert result.success and 'reflected' in result.evidence

def test_bypass_types_direct_top_level_import(monkeypatch):
    root = Path(h.__file__).resolve().parents[1]
    agents = root / 'agents'
    with monkeypatch.context() as patch:
        patch.chdir(agents)
        patch.setattr(sys, 'path', [str(agents)] + [p for p in sys.path if p and Path(p).resolve() != root])
        for name in list(sys.modules):
            if name == 'agents' or name.startswith('agents.') or name == 'bypass_types' or name.startswith('bypass_types.'):
                patch.delitem(sys.modules, name, raising=False)
        spec = importlib.util.spec_from_file_location('bypass_types', agents / 'bypass_types' / '__init__.py', submodule_search_locations=[str(agents / 'bypass_types')])
        module = importlib.util.module_from_spec(spec)
        patch.setitem(sys.modules, 'bypass_types', module)
        spec.loader.exec_module(module)
        assert module.CORSBypass
