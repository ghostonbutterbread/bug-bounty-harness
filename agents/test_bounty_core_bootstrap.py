from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agents import bounty_core_bootstrap, dependency_context


def _clear_bounty_core_modules() -> None:
    for name in list(sys.modules):
        if name == "bounty_core" or name.startswith("bounty_core."):
            sys.modules.pop(name, None)


def _checkout(root: Path, marker: str) -> str:
    package = root / "bounty_core"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(f"SOURCE = {marker!r}\n")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-qm", marker],
        check=True,
    )
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _configure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, root: Path, revision: str) -> None:
    receipt = tmp_path / "active-stack.json"
    receipt.write_text(json.dumps({"version": 1, "projects": {"core": {"root": str(root), "revision": revision}}}))
    config = tmp_path / "dependencies.json"
    config.write_text(json.dumps({"active_stack": str(receipt), "projects": {"bounty_core": "core"}}))
    monkeypatch.setattr(dependency_context, "CONFIG_PATH", config)


def test_receipt_selected_core_wins_over_foreign_sys_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    stable = tmp_path / "stable"
    beta = tmp_path / "beta"
    _checkout(stable, "stable")
    beta_revision = _checkout(beta, "beta")
    _configure(monkeypatch, tmp_path, beta, beta_revision)
    _clear_bounty_core_modules()
    monkeypatch.syspath_prepend(str(stable))

    bounty_core_bootstrap.ensure_bounty_core_importable()
    module = importlib.import_module("bounty_core")

    assert module.SOURCE == "beta"
    assert Path(module.__file__).resolve().is_relative_to(beta)
    _clear_bounty_core_modules()


def test_missing_configuration_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(dependency_context, "CONFIG_PATH", tmp_path / "missing.json")
    _clear_bounty_core_modules()
    with pytest.raises(dependency_context.DependencyResolutionError, match="Missing BBH dependency configuration"):
        bounty_core_bootstrap.ensure_bounty_core_importable()


def test_stale_receipt_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path / "core"
    revision = _checkout(root, "core")
    _configure(monkeypatch, tmp_path, root, "0" * len(revision))
    _clear_bounty_core_modules()
    with pytest.raises(dependency_context.DependencyResolutionError, match="Stale or invalid"):
        bounty_core_bootstrap.ensure_bounty_core_importable()
