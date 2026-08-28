from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_PYTHON = [
    path
    for path in [*ROOT.glob("agents/**/*.py"), *ROOT.glob("*.py")]
    if "test" not in path.name
]
LEGACY_SOURCE_SELECTOR = re.compile(
    r"/home/ryushe/(?:projects|workspace)/(?:bug_bounty_harness|bounty-tools)|"
    r"Path\.home\(\) / \"projects\" / \"(?:bug_bounty_harness|bounty-tools)\"|"
    r"(?:BOUNTY_CORE_ROOT|BOUNTY_TOOLS_PATH)"
)


class ProductionPathSafetyTests(unittest.TestCase):
    def test_production_python_has_no_conventional_bbh_or_bounty_tools_source_selector(self) -> None:
        violations = [
            f"{path.relative_to(ROOT)}"
            for path in PRODUCTION_PYTHON
            if LEGACY_SOURCE_SELECTOR.search(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(violations, [], "\n".join(violations))

    def test_only_bounty_core_is_a_required_lane_bound_dependency(self) -> None:
        users = [
            str(path.relative_to(ROOT))
            for path in PRODUCTION_PYTHON
            if path.name != "dependency_context.py"
            and "ensure_bounty_tools_importable" in path.read_text(encoding="utf-8")
        ]
        self.assertEqual(users, [], "\n".join(users))


if __name__ == "__main__":
    unittest.main()
