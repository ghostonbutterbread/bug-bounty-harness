"""Focused discovery and packaging guard for promoted BBH skills."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
PROMOTED = (
    "rce-exploration", "rce-surface-mapping", "rce-lifecycle",
    "rce-validation", "rce-technology-research", "account-registry",
    "blocker-first-analysis", "research-knowledge-management", "hunt-orchestration",
)


class SkillPromotionRoutesTest(unittest.TestCase):
    def test_all_named_skills_have_packaged_references_and_registry_rows(self):
        registry = (ROOT / "SKILL_REGISTRY.md").read_text(encoding="utf-8")
        for name in ("rce", *PROMOTED):
            with self.subTest(name=name):
                path = SKILLS / name / "SKILL.md"
                text = path.read_text(encoding="utf-8")
                self.assertTrue(text.startswith(f"---\nname: {name}\n"))
                self.assertIn(f"| **{name}** |", registry)
                for ref in re.findall(r"`(references/[^`]+\.md)`", text):
                    self.assertTrue((path.parent / ref).is_file(), f"{name}: {ref}")
                self.assertNotIn("/home/ryushe/", text)

    def test_rce_class_entry_and_overlapping_owners(self):
        entry = (SKILLS / "rce" / "SKILL.md").read_text(encoding="utf-8")
        for name in PROMOTED[:5]:
            self.assertIn(f"`{name}`", entry)
        self.assertIn("which controlled", entry)
        routes = (ROOT / "agents" / "index.md").read_text(encoding="utf-8")
        self.assertIn("load `/rce` as the class entry", routes)
        self.assertIn("`hunt-orchestration-policy` for admission", routes)
        self.assertIn("`/account-registry` with `/account-management`", routes)
        self.assertIn("`/blockers` only for an external prerequisite", routes)
        self.assertIn("`/research-knowledge-management` owns source admission", routes)
        self.assertIn("`blockers` owns the optional external-prerequisite store",
                      (SKILLS / "blocker-first-analysis" / "SKILL.md").read_text(encoding="utf-8"))

    def test_promoted_contracts_do_not_invent_auth_or_blocker_gates(self):
        registry = (SKILLS / "account-registry" / "SKILL.md").read_text(encoding="utf-8")
        recovery = (SKILLS / "account-registry" / "references" / "program-auth-recovery.md").read_text(encoding="utf-8")
        blocker = (SKILLS / "blocker-first-analysis" / "references" / "blocker-store-contract.md").read_text(encoding="utf-8")
        self.assertIn("`needs-browser-handoff`", registry)
        self.assertIn("not implemented by", registry)
        self.assertIn("not implemented by the resolver", recovery)
        self.assertNotIn("The resolver must load both", registry)
        self.assertNotIn("run the policy-declared owned browser login", registry)
        self.assertIn("not a testing or coverage gate", blocker)
        self.assertIn("freshly assess", blocker)
        self.assertNotIn("Open records block", blocker)

    def test_registry_migration_gates_match_current_consumers(self):
        registry = (SKILLS / "account-registry" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Chromium launcher currently accepts retired inventories", registry)
        self.assertIn("Shared-loader migration target (not yet implemented)", registry)
        self.assertIn("current lease helper also accepts legacy", registry)
        self.assertIn("`lifecycle: live`", registry)
        self.assertIn("do not retire on the basis of the account CLI alone", registry)
        self.assertIn("**not** verified authenticated or cleared", registry)
        self.assertIn("The helper does not perform a live health check on first acquisition", registry)

    def test_conditional_routes_agree_with_their_entry_skills(self):
        recovery = (SKILLS / "account-registry" / "references" / "program-auth-recovery.md").read_text(encoding="utf-8")
        mapping = (SKILLS / "rce-surface-mapping" / "SKILL.md").read_text(encoding="utf-8")
        research = (SKILLS / "research-knowledge-management" / "references" / "research-map-pattern.md").read_text(encoding="utf-8")
        self.assertIn("`proxy-replayable` or `hybrid`", recovery)
        self.assertIn("`browser-bound` and `unknown` remain browser-only", recovery)
        self.assertIn("Load from `rce` for broad mapped-surface coverage", mapping)
        self.assertIn("or from `rce-exploration`", mapping)
        self.assertIn("external context could distinguish", research)

    def test_transport_blocker_and_rce_validation_routes(self):
        hunt = (SKILLS / "hunt-orchestration" / "SKILL.md").read_text(encoding="utf-8")
        entry = (SKILLS / "rce" / "SKILL.md").read_text(encoding="utf-8")
        mapping = (SKILLS / "rce-surface-mapping" / "SKILL.md").read_text(encoding="utf-8")
        validation = (SKILLS / "rce-validation" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("through that affected transport path", hunt)
        self.assertIn("independently healthy transport lane", hunt)
        self.assertIn("handoff/blocker pointer in `bounty-notes`", hunt)
        self.assertIn("MapStore\nentry only for separately verified target behavior", hunt)
        for route in (entry, mapping, validation):
            self.assertIn("source-to-executor", route)
            self.assertIn("`rce-exploration`", route)

    def test_rce_ladders_distinguish_precursor_from_confirmation(self):
        validation = (SKILLS / "rce-validation" / "SKILL.md").read_text(encoding="utf-8")
        refs = SKILLS / "rce-exploration" / "references"
        ladder = (refs / "validation-ladder.md").read_text(encoding="utf-8")
        precursor = (refs / "precursor-ladder.md").read_text(encoding="utf-8")
        self.assertIn("before the sink is evidenced", ladder)
        self.assertIn("only\n   once the candidate sink is evidenced", ladder)
        for text in (validation, ladder, precursor):
            self.assertIn("blind/asynchronous observation gap", text)
            self.assertIn("lower-impact measurement is insufficient", text)
        self.assertIn("do not require a callback for a visible branch", validation)


if __name__ == "__main__":
    unittest.main()
