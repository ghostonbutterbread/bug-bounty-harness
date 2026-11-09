"""The internal Chromium exec shim must work without profile HOME packages."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize('diagnostics', [False, True])
def test_pipe_exec_requires_only_stdlib_with_isolated_home(tmp_path, diagnostics):
    script = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/browser_control.py'
    read_fd, write_fd = os.pipe()
    try:
        env = {**os.environ, 'HOME': str(tmp_path), 'PYTHONNOUSERSITE': '1'}
        env.pop('BROWSER_STARTUP_RECEIPT_DIR', None)
        if diagnostics:
            env['BROWSER_STARTUP_RECEIPT_DIR'] = str(tmp_path)
        result = subprocess.run(
            [sys.executable, '-S', str(script), 'pipe-exec', str(read_fd), str(write_fd),
             sys.executable, '-S', '-c', 'import os; os.fstat(3); os.fstat(4); print("ready")'],
            env=env, pass_fds=(read_fd, write_fd), capture_output=True, text=True, timeout=10,
        )
    finally:
        os.close(read_fd)
        os.close(write_fd)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'ready'
    if diagnostics:
        events = json.loads((tmp_path / 'exec.json').read_text())['events']
        assert [(event['phase'], event['outcome']) for event in events] == [('exec', 'begin')]
