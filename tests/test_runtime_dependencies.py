from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RuntimeDependencyTests(unittest.TestCase):
    def test_checkout_runtime_manifest_includes_httpx_for_dispatcher_tools(self) -> None:
        requirements = (ROOT / "requirements-bounty-core.txt").read_text(encoding="utf-8")
        self.assertRegex(requirements, r"(?m)^httpx(?:[<>=!~]|\s|$)")


if __name__ == "__main__":
    unittest.main()
