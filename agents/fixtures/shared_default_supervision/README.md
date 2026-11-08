# Fenced shared-default fixture

Run from this checkout with a Python that has pytest installed:

```sh
PYTHONNOUSERSITE=1 /usr/bin/python3 agents/fixtures/shared_default_supervision/launch.py
```

Requires Linux Landlock ABI 4+, libseccomp, pidfds, pytest and its dependencies,
and private `TMPDIR`. The launcher copies the named test dependencies into
private scratch without loading site `.pth` files. It isolates HOME and XDG state,
denies execution of real systemd binaries (including `/bin` aliases), denies all
TCP via Landlock and all socket/socketpair/connect syscalls via seccomp. Only the
fixture scratch directory and `/dev/null` are writable. The
subprocess test creates fake `loginctl`, `systemd-run` and `systemctl` commands
inside that directory; the fake service is a harmless Python sleep process
stopped via pidfd. It proves the fake service survives the dispatch subprocess
and that the recorded exact fake unit is stopped; it does **not** prove real
systemd cgroup, bus, linger, or socket behavior. Tests use mocked readiness and
never contact a real 8080 listener or Hoster. A real destination-host canary
and independent review remain deployment gates.

`prior_mitm_lane.py.fixture` is a sanitized historical CLI stored as test data
so the old-protocol rejection test does not require Git history. The test invokes
only its argument parser with `observe-default`; it must not launch or stop a
service. `a-test-key.pem.fixture` and `b-test-key.pem.fixture` are public,
synthetic test-only private keys: never use them for a real CA or service.
