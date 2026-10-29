"""Account-management projects Auth Contract fields; it is not a second version."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class AuthContractProjectionTest(unittest.TestCase):
    def test_account_management_projects_one_contract(self) -> None:
        skill = (ROOT / "skills/account-management/SKILL.md").read_text(encoding="utf-8")
        playbook = (ROOT / "prompts/account-management-playbook.md").read_text(encoding="utf-8")
        recovery = (
            ROOT / "skills/account-registry/references/program-auth-recovery.md"
        ).read_text(encoding="utf-8")
        self.assertIn("auth-contract.md", skill)
        self.assertIn("Do not invent a second write-up", skill)
        self.assertIn("Children inherit", skill)
        self.assertIn("not a second narrative", playbook)
        self.assertIn("auth-contract.md", recovery)


if __name__ == "__main__":
    unittest.main()
