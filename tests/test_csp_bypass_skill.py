from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CspBypassSkillTests(unittest.TestCase):
    def test_skill_is_registered_and_router_points_to_it(self):
        registry = (ROOT / "SKILL_REGISTRY.md").read_text(encoding="utf-8")
        router = (ROOT / "skills/bypass/SKILL.md").read_text(encoding="utf-8")
        skill_path = ROOT / "skills/csp-bypass/SKILL.md"

        self.assertTrue(skill_path.is_file())
        self.assertIn("| **csp-bypass** |", registry)
        self.assertIn("skills/csp-bypass/SKILL.md", registry)
        self.assertIn("## CSP reference", router)
        self.assertIn("`csp-bypass` (`skills/csp-bypass/SKILL.md`)", router)

    def test_skill_covers_distinct_policy_bypass_mechanisms(self):
        skill = (ROOT / "skills/csp-bypass/SKILL.md").read_text(encoding="utf-8")
        frontmatter = re.match(r"---\n(.*?)\n---\n", skill, flags=re.DOTALL)
        if frontmatter is None:
            self.fail("skill frontmatter is missing")
        self.assertRegex(frontmatter.group(1), r"(?m)^name: csp-bypass$")
        for mechanism in (
            "JSONP",
            "script gadgets",
            "strict-dynamic",
            "Nonce reuse",
            "unsafe-eval",
            "base-uri",
            "Report-Only",
        ):
            with self.subTest(mechanism=mechanism):
                self.assertIn(mechanism, skill)
        self.assertIn("not the separate `script-src-elem` or `script-src-attr` lists", skill)
        self.assertIn("`wasm-unsafe-eval` permits WebAssembly compilation without enabling JavaScript string evaluation", skill)
        self.assertIn("`trusted-types-eval` can allow TrustedScript-valued eval sinks", skill)


if __name__ == "__main__":
    unittest.main()
