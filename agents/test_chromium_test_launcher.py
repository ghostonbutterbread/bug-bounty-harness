from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path


def load_launcher_module():
    root = Path(__file__).resolve().parents[1]
    launcher = root / "skills" / "chromium-test" / "scripts" / "chromium_test.py"
    spec = importlib.util.spec_from_file_location("chromium_test_launcher", launcher)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_command_includes_remote_allow_origins(monkeypatch):
    module = load_launcher_module()
    monkeypatch.setattr(module, "find_chrome_binary", lambda explicit=None: "/usr/bin/chromium")
    args = argparse.Namespace(
        chrome_binary=None,
        proxy_server=None,
        remote_allow_origins="*",
        url="https://target.example/",
    )

    command = module.build_command(args, 9223, Path("/tmp/chromium-profile"))

    assert "--remote-debugging-address=127.0.0.1" in command
    assert "--remote-allow-origins=*" in command
    assert command[-1] == "https://target.example/"


def test_build_command_allows_custom_remote_allow_origins(monkeypatch):
    module = load_launcher_module()
    monkeypatch.setattr(module, "find_chrome_binary", lambda explicit=None: "/usr/bin/chromium")
    args = argparse.Namespace(
        chrome_binary=None,
        proxy_server=None,
        remote_allow_origins="http://127.0.0.1:9223",
        url=None,
    )

    command = module.build_command(args, 9223, Path("/tmp/chromium-profile"))

    assert "--remote-allow-origins=http://127.0.0.1:9223" in command
    assert command[-1] == "about:blank"
