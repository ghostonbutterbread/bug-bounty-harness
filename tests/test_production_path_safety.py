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
    r"/home/ryushe/(?:projects|workspace)/(?:bug_bounty_harness|bounty-tools|bounty-core)|"
    r"Path\.home\(\) / \"projects\" / \"(?:bug_bounty_harness|bounty-tools|bounty-core)\"|"
    r"(?:BOUNTY_CORE_ROOT|BOUNTY_TOOLS_PATH|active-stack\.json|dependencies\.json|"
    r"ensure_bounty_core_importable|resolve_dependency_root)"
)


class ProductionPathSafetyTests(unittest.TestCase):
    def test_production_python_has_no_legacy_source_selector_or_receipt_resolver(self) -> None:
        violations = [
            f"{path.relative_to(ROOT)}"
            for path in PRODUCTION_PYTHON
            if LEGACY_SOURCE_SELECTOR.search(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(violations, [], "\n".join(violations))

    def test_receipt_based_bounty_core_resolvers_are_removed(self) -> None:
        self.assertFalse((ROOT / "agents" / "dependency_context.py").exists())
        self.assertFalse((ROOT / "agents" / "bounty_core_bootstrap.py").exists())


if __name__ == "__main__":
    unittest.main()
