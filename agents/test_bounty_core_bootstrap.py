from __future__ import annotations

import sys
from pathlib import Path

from agents import bounty_core_bootstrap


def _clear_bounty_core_modules() -> None:
    for name in list(sys.modules):
        if name == "bounty_core" or name.startswith("bounty_core."):
            del sys.modules[name]


def test_required_submodule_prefers_sibling_checkout_over_old_imported_package(
    tmp_path: Path,
    monkeypatch,
) -> None:
    old_checkout = tmp_path / "old"
    old_package = old_checkout / "bounty_core"
    old_package.mkdir(parents=True)
    (old_package / "__init__.py").write_text("SOURCE = 'old'\n", encoding="utf-8")

    sibling_checkout = tmp_path / "bounty-core"
    sibling_package = sibling_checkout / "bounty_core"
    sibling_package.mkdir(parents=True)
    (sibling_package / "__init__.py").write_text("SOURCE = 'sibling'\n", encoding="utf-8")
    (sibling_package / "brainstorm_spec.py").write_text(
        "SOURCE = 'sibling-brainstorm'\n",
        encoding="utf-8",
    )

    _clear_bounty_core_modules()
    monkeypatch.syspath_prepend(str(old_checkout))
    monkeypatch.setattr(
        bounty_core_bootstrap,
        "SIBLING_BOUNTY_CORE_CHECKOUT",
        sibling_checkout,
    )

    try:
        import bounty_core

        assert bounty_core.SOURCE == "old"

        bounty_core_bootstrap.ensure_bounty_core_importable(
            "bounty_core.brainstorm_spec"
        )

        import bounty_core.brainstorm_spec as brainstorm_spec

        assert sys.path[0] == str(sibling_checkout)
        assert list(bounty_core.__path__)[0] == str(sibling_package)
        assert brainstorm_spec.SOURCE == "sibling-brainstorm"
    finally:
        _clear_bounty_core_modules()
