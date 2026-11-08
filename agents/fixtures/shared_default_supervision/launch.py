"""Run only the shared-default tests with fake services and kernel fences.

Linux Landlock ABI 4+ required. Never permits real systemd binaries or any TCP
port, including 8080. Filesystem writes are limited to an isolated scratch root.
"""
from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import shutil
import site
import socket
import subprocess
import sys
import tempfile

repo = Path(__file__).resolve().parents[3]
base = Path(os.environ['TMPDIR'])
signer_only = os.environ.get('SHARED_DEFAULT_SIGNER_TESTS') == '1'
openssl = shutil.which('openssl')
if not openssl:
    raise SystemExit('openssl required for signer fixture')
root = Path(tempfile.mkdtemp(prefix='shared-default-test-', dir=base))
for name in ('home', 'tmp', 'config', 'data', 'state', 'cache', 'runtime'):
    (root / name).mkdir(mode=0o700)
# Copy the small, explicitly named test dependencies into private scratch; never
# add the user's site-packages directory or its executable .pth files to tests.
candidates = [Path(site.getusersitepackages()), *(Path(p) for p in site.getsitepackages())]
source_site = next((p for p in candidates if (p / 'pytest').is_dir()
                    and (p / '_pytest').is_dir() and (p / 'py.py').is_file()), None)
if source_site is None:
    raise SystemExit('pytest fixture dependencies are not installed')
deps = root / 'pytest-deps'
deps.mkdir()
for name in ('pytest', '_pytest', 'pluggy', 'iniconfig', 'packaging'):
    source = source_site / name
    if not source.is_dir():
        raise SystemExit(f'missing fixture dependency: {source}')
    shutil.copytree(source, deps / name, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
shutil.copy2(source_site / 'py.py', deps / 'py.py')
for name in ('pytest', 'pluggy', 'iniconfig', 'packaging'):
    metadata = list(source_site.glob(name + '-*.dist-info'))
    if len(metadata) != 1:
        raise SystemExit(f'expected one {name} dist-info in {source_site}')
    shutil.copytree(metadata[0], deps / metadata[0].name)
old_script = root / 'old_mitm_lane.py'
# Sanitized historical CLI, checked in so a shallow clone needs no old object.
shutil.copyfile(Path(__file__).with_name('prior_mitm_lane.py.fixture'), old_script)
python = os.path.realpath(sys.executable)
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
if libc.syscall(444, 0, 0, 1) < 4:
    raise SystemExit('Landlock ABI 4 required')

class Ruleset(ctypes.Structure):
    _fields_ = [('fs', ctypes.c_uint64), ('net', ctypes.c_uint64)]

class PathRule(ctypes.Structure):
    _fields_ = [('access', ctypes.c_uint64), ('fd', ctypes.c_int32)]

rule = Ruleset(1 | 2 | sum(1 << i for i in range(4, 15)), 3)
fd = libc.syscall(444, ctypes.byref(rule), ctypes.sizeof(rule), 0)
if fd < 0:
    raise OSError(ctypes.get_errno(), 'landlock_create')

def allow(path, access):
    p = os.open(path, os.O_PATH | os.O_CLOEXEC)
    try:
        item = PathRule(access, p)
        if libc.syscall(445, fd, 1, ctypes.byref(item), 0):
            raise OSError(ctypes.get_errno(), 'landlock_add ' + str(path))
    finally:
        os.close(p)

allow(root, rule.fs)
allow('/dev/null', 2)
allow(python, 1)
allow('/usr/lib', 1)
if libc.prctl(38, 1, 0, 0, 0) or libc.syscall(446, fd, 0):
    raise OSError(ctypes.get_errno(), 'landlock_restrict')
os.close(fd)
for target in ('/usr/bin/systemctl', '/bin/systemctl', '/usr/bin/systemd-run', '/bin/systemd-run',
               '/usr/bin/journalctl', '/usr/bin/loginctl'):
    try:
        subprocess.run([target, '--version'], capture_output=True)
    except PermissionError:
        pass
    else:
        raise SystemExit('execution fence failed: ' + target)
if openssl:
    try:
        subprocess.run([openssl, 'version'], capture_output=True)
    except PermissionError:
        pass
    else:
        raise SystemExit('OpenSSL execution fence failed')
with socket.socket() as probe:
    if probe.connect_ex(('127.0.0.1', 1)) != errno.EACCES:
        raise SystemExit('TCP fence failed')
sec_probe = socket.socket()
# Also deny socket creation and connection, including Unix/datagram sockets,
# in every descendant. The fixture does not need any real network endpoint.
sec = ctypes.CDLL('libseccomp.so.2', use_errno=True)
sec.seccomp_init.argtypes = [ctypes.c_uint32]
sec.seccomp_init.restype = ctypes.c_void_p
sec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
sec.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
sec.seccomp_load.argtypes = [ctypes.c_void_p]
sec.seccomp_release.argtypes = [ctypes.c_void_p]
ctx = sec.seccomp_init(0x7fff0000)
if not ctx:
    raise SystemExit('seccomp_init failed')
for name in (b'socket', b'socketpair', b'connect'):
    nr = sec.seccomp_syscall_resolve_name(name)
    if nr < 0 or sec.seccomp_rule_add(ctx, 0x00050000 | errno.EPERM, nr, 0):
        raise SystemExit('seccomp rule failed: ' + repr(name))
if sec.seccomp_load(ctx):
    raise SystemExit('seccomp_load failed')
sec.seccomp_release(ctx)
try:
    socket.socket()
except PermissionError:
    pass
else:
    raise SystemExit('socket fence failed')
try:
    socket.socketpair()
except PermissionError:
    pass
else:
    raise SystemExit('socketpair fence failed')
if sec_probe.connect_ex(('127.0.0.1', 1)) != errno.EPERM:
    raise SystemExit('connect seccomp fence failed')
sec_probe.close()
env = {'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp'),
       'XDG_CONFIG_HOME': str(root / 'config'), 'XDG_DATA_HOME': str(root / 'data'),
       'XDG_STATE_HOME': str(root / 'state'), 'XDG_CACHE_HOME': str(root / 'cache'),
       'XDG_RUNTIME_DIR': str(root / 'runtime'), 'PATH': '/nonexistent',
       'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1',
       'SHARED_DEFAULT_KERNEL_FENCE': '1', 'OLD_MITM_LANE_FILE': str(old_script),
       'LANG': 'C.UTF-8'}
if openssl:
    env['TEST_OPENSSL'] = openssl
print(f'fixture={root}: systemd execution denied; all TCP denied', flush=True)
os.chdir(repo)
if signer_only and os.environ.get('SHARED_DEFAULT_DIRECT_TESTS') == '1':
    tests = ['agents/test_shared_default_direct_start.py']
elif signer_only and os.environ.get('SHARED_DEFAULT_ABSENCE_TESTS') == '1':
    tests = ['agents/test_shared_default_absence.py']
elif signer_only and os.environ.get('SHARED_DEFAULT_WRAPPER_ATTEST_TESTS') == '1':
    tests = ['agents/test_shared_default_wrapper_attestation.py']
elif signer_only and os.environ.get('SHARED_DEFAULT_ATTEST_TESTS') == '1':
    tests = ['agents/test_shared_default_attestation.py']
elif signer_only and os.environ.get('SHARED_DEFAULT_FRESH_TESTS') == '1':
    tests = ['agents/test_shared_default_fresh_observation.py']
elif signer_only and os.environ.get('SHARED_DEFAULT_REVIEW_TESTS') == '1':
    tests = ['agents/test_shared_default_review_checkpoint.py']
elif signer_only and os.environ.get('SHARED_DEFAULT_LEGACY_TESTS') == '1':
    tests = ['agents/test_shared_default_legacy_observation.py']
elif signer_only and os.environ.get('SHARED_DEFAULT_UNKNOWN_TESTS') == '1':
    tests = ['agents/test_shared_default_unknown_state.py']
elif signer_only and os.environ.get('SHARED_DEFAULT_IDENTITY_TESTS') == '1':
    tests = ['agents/test_shared_default_live_identity.py']
elif signer_only:
    tests = ['agents/test_shared_default_signer_dispatch.py',
             'agents/test_shared_default_ca_readiness.py::test_start_timeout_reports_unknown_without_retry_or_stop',
             'agents/test_shared_default_ca_readiness.py::test_timeout_main_emits_json_and_exits_nonzero',
             'agents/test_shared_default_ca_readiness.py::test_remote_loopback_rejected_before_dispatch',
             'agents/test_shared_default_ca_readiness.py::test_invalid_remote_advertisement_fails_before_dispatch',
             'agents/test_shared_default_ca_readiness.py::test_remote_advertisement_url_formats',
             'agents/test_shared_default_ca_readiness.py::test_failed_ssh_and_scp_stderr_are_not_exposed']
else:
    tests = ['agents/test_shared_default_signer_dispatch.py', 'agents/test_shared_default_ca_readiness.py', 'agents/test_shared_default_supervision.py', 'agents/test_shared_default_additional.py',
             'agents/test_shared_default_subprocess.py', 'agents/test_mitm_lane.py', 'agents/test_hoster_mitm_lane.py']
code = 'import sys; sys.path.append(sys.argv.pop(1)); import pytest; raise SystemExit(pytest.main(["-p", "no:cacheprovider", *sys.argv[1:]]))'
os.execve(python, [python, '-c', code, str(deps), *tests, '-q', '-r', 's',
                   '--junitxml', str(root / 'pytest-results.xml')], env)
