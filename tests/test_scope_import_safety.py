"""Synthetic failure-path checks; no network or program data are used."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONSUMERS = ("fuzz_runner", "ai_recon", "autonomous_recon", "google_dorker",
             "secrets_finder", "subdomain_agent", "llm_harness")


@pytest.mark.parametrize("consumer", CONSUMERS)
@pytest.mark.parametrize("missing", ("validator", "idna", "broken_validator"))
@pytest.mark.parametrize("mode", ("package", "script"))
def test_validator_import_failure_never_becomes_optional(consumer, missing, mode, tmp_path):
    code = r'''
import builtins, importlib, os, sys
real_import = builtins.__import__
def guarded(name, globals=None, locals=None, fromlist=(), level=0):
    caller = (globals or {}).get('__name__', '')
    if os.environ['MISSING'] == 'broken_validator' and name in ('scope_validator', 'agents.scope_validator') and caller.endswith(os.environ['CONSUMER']):
        raise ImportError('synthetic broken validator dependency')
    if (os.environ['MISSING'] == 'validator' and name in ('scope_validator', 'agents.scope_validator') and caller.endswith(os.environ['CONSUMER'])) or (os.environ['MISSING'] == 'idna' and name == 'idna' and caller.endswith('scope_validator')):
        raise ModuleNotFoundError('synthetic missing ' + name, name=name)
    return real_import(name, globals, locals, fromlist, level)
builtins.__import__ = guarded
if os.environ['MODE'] == 'script':
    sys.path.insert(0, os.path.join(os.environ['ROOT'], 'agents'))
module = importlib.import_module(('agents.' if os.environ['MODE'] == 'package' else '') + os.environ['CONSUMER'])
from pathlib import Path
class State:
    CAMPAIGNS_DIR = Path(os.environ['HOME']) / 'campaigns'
if os.environ['CONSUMER'] == 'fuzz_runner':
    module.CampaignState = State
module.SubagentLogger = None
constructors = {
    'fuzz_runner': lambda: module.FuzzAgent('demo', 'synthetic'),
    'ai_recon': lambda: module.AIReconAgent('synthetic', ['example.test'], os.environ['HOME']),
    'autonomous_recon': lambda: module.run_recon('synthetic', 'https://example.test'),
    'google_dorker': lambda: module.GoogleDorker('synthetic', ['example.test'], os.environ['HOME']),
    'secrets_finder': lambda: module.SecretsFinder('synthetic').scan_wayback('example.test'),
    'subdomain_agent': lambda: module.SubdomainCollector('example.test', 'synthetic', [], None),
    'llm_harness': lambda: module.LLMHarness('https://example.test', program='synthetic'),
}
try:
    constructors[os.environ['CONSUMER']]()
except (ImportError, RuntimeError) as exc:
    assert 'scope' in str(exc).lower() and 'requirements.txt' in str(exc), str(exc)
    assert isinstance(exc.__cause__, ImportError), repr(exc.__cause__)
else:
    raise AssertionError('scope import failure was swallowed')
'''
    env = dict(os.environ, PYTHONPATH=str(ROOT), HOME=str(tmp_path),
               CONSUMER=consumer, MISSING=missing, MODE=mode, ROOT=str(ROOT),
               PYTHONDONTWRITEBYTECODE='1')
    result = subprocess.run([sys.executable, '-c', code], cwd=ROOT, env=env,
                            text=True, capture_output=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("consumer", CONSUMERS)
def test_scope_initialization_errors_stop_before_work(consumer, tmp_path, monkeypatch):
    import importlib
    module = importlib.import_module('agents.' + consumer)
    assert Path(module.__file__).resolve().is_relative_to(ROOT)
    failure = PermissionError('synthetic scope read failed')

    def fail_scope(program):
        raise failure

    class State:
        CAMPAIGNS_DIR = tmp_path / 'campaigns'

    monkeypatch.setattr(module, 'ScopeValidator', fail_scope)
    monkeypatch.setattr(module, 'SubagentLogger', None, raising=False)
    if consumer == 'fuzz_runner':
        monkeypatch.setattr(module, 'CampaignState', State)
    if consumer == 'autonomous_recon':
        monkeypatch.setattr(module, 'phase_discover', lambda *_: pytest.fail('started discovery'))
    constructors = {
        'fuzz_runner': lambda: module.FuzzAgent('demo', 'synthetic'),
        'ai_recon': lambda: module.AIReconAgent('synthetic', ['example.test'], str(tmp_path)),
        'autonomous_recon': lambda: module.run_recon('synthetic', 'https://example.test'),
        'google_dorker': lambda: module.GoogleDorker('synthetic', ['example.test'], str(tmp_path)),
        'secrets_finder': lambda: module.SecretsFinder('synthetic'),
        'subdomain_agent': lambda: module.SubdomainCollector('example.test', 'synthetic', [], None),
        'llm_harness': lambda: module.LLMHarness('https://example.test', program='synthetic'),
    }
    with pytest.raises(PermissionError) as exc:
        constructors[consumer]()
    assert exc.value is failure


def test_secrets_local_scan_survives_missing_validator_but_network_does_not(tmp_path, monkeypatch):
    from agents import secrets_finder
    cause = ModuleNotFoundError('synthetic idna')
    monkeypatch.setattr(secrets_finder, 'ScopeValidator', None)
    monkeypatch.setattr(secrets_finder, '_scope_import_error', cause, raising=False)
    finder = secrets_finder.SecretsFinder('synthetic')
    source = tmp_path / 'sample.js'
    source.write_text('const plain = 42;\n')
    assert finder.scan_file(source) == []
    for operation in (lambda: finder.is_in_scope('https://example.test'),
                      lambda: finder.scan_wayback('example.test'),
                      lambda: finder._wayback_cdx_records('example.test', 1),
                      lambda: finder.scan_nuclei_creds('https://example.test'),
                      lambda: finder.run_trufflehog('https://example.test/repo', 'git')):
        with pytest.raises(RuntimeError, match='Scope validator unavailable') as exc:
            operation()
        assert exc.value.__cause__ is cause


def test_fuzz_without_program_still_refuses_missing_validator(tmp_path, monkeypatch):
    from agents import fuzz_runner
    class State:
        CAMPAIGNS_DIR = tmp_path / 'campaigns'
    cause = ModuleNotFoundError('synthetic idna')
    monkeypatch.setattr(fuzz_runner, 'CampaignState', State)
    monkeypatch.setattr(fuzz_runner, 'ScopeValidator', None)
    monkeypatch.setattr(fuzz_runner, '_scope_import_error', cause)
    with pytest.raises(RuntimeError, match='Scope validator unavailable') as exc:
        fuzz_runner.FuzzAgent('demo')
    assert exc.value.__cause__ is cause


def test_fuzz_program_uses_real_child_validator(tmp_path, monkeypatch):
    from agents import fuzz_runner, scope_validator
    assert Path(scope_validator.__file__).resolve().is_relative_to(ROOT)
    monkeypatch.setattr(scope_validator.ScopeValidator, 'SCOPES_BASE', tmp_path / 'scopes')
    monkeypatch.setattr(scope_validator.ScopeValidator, 'LEGACY_RECON_BASE', tmp_path / 'legacy')
    scope = tmp_path / 'scopes' / 'synthetic'
    scope.mkdir(parents=True)
    (scope / 'in-scope.txt').write_text('example.test\n')
    class State:
        CAMPAIGNS_DIR = tmp_path / 'campaigns'
    monkeypatch.setattr(fuzz_runner, 'CampaignState', State)
    monkeypatch.setattr(fuzz_runner, 'SubagentLogger', None)
    agent = fuzz_runner.FuzzAgent('demo', 'synthetic')
    assert agent.is_in_scope('https://example.test/')
    assert not agent.is_in_scope('https://elsewhere.test/')
