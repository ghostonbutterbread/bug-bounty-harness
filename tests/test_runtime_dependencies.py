from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


PUBLISHED_VISIBILITY_MODES_CORE_SHA = "f3d02453f26a4e221632466c26742dfb55368f28"
SUPERSEDED_STALE_RECLAIM_CORE_SHA = "fc361eca86f9c86acb357e1b9ce6426bc44aef83"
OLD_CORE_SHA = "04b5149f617dafe7837726faec4d1bc5cf5471b6"


class RuntimeDependencyTests(unittest.TestCase):
    def test_checkout_runtime_manifest_pins_published_visibility_modes_core_revision(self) -> None:
        requirements = (ROOT / "requirements-bounty-core.txt").read_text(encoding="utf-8")
        self.assertRegex(
            requirements,
            rf"(?m)^bounty-core\s*@\s*git\+https://github\.com/ghostonbutterbread/bounty-core\.git@{PUBLISHED_VISIBILITY_MODES_CORE_SHA}$",
        )
        self.assertNotIn(SUPERSEDED_STALE_RECLAIM_CORE_SHA, requirements)
        self.assertNotIn(OLD_CORE_SHA, requirements)

    def test_checkout_runtime_manifest_includes_httpx_for_dispatcher_tools(self) -> None:
        requirements = (ROOT / "requirements-bounty-core.txt").read_text(encoding="utf-8")
        self.assertRegex(requirements, r"(?m)^httpx(?:[<>=!~]|\s|$)")


if __name__ == "__main__":
    unittest.main()
