from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
ROUTER = SKILLS / "bunny" / "SKILL.md"
COLLABORATIVE = SKILLS / "bunny-collaborative" / "SKILL.md"
OFFHAND = SKILLS / "bunny-offhand" / "SKILL.md"
MULTI = SKILLS / "bunny-multi" / "SKILL.md"
GOALS = SKILLS / "bug-goals" / "SKILL.md"


class BunnySkillTests(unittest.TestCase):
    def test_default_route_and_explicit_offhand(self):
        router = ROUTER.read_text(encoding="utf-8")
        self.assertIn("name: bunny\n", router)
        self.assertIn("opt-in", router)
        self.assertIn("Keep `hunt-orchestration`", router)
        self.assertIn("Default: collaborative", router)
        self.assertIn("load `bunny-collaborative` before dispatch", router)
        self.assertIn("coordinator and each collaborative worker must load", router)
        self.assertIn("Explicit: offhand", router)
        self.assertIn("load `bunny-offhand` in the coordinator", router)
        self.assertIn("not** a Bunny mode skill", router)
        self.assertIn("Do not silently fall back", router)
        self.assertIn("mode change occurs at an evidence checkpoint", router)

    def test_shared_account_and_evidence_guards(self):
        router = ROUTER.read_text(encoding="utf-8")
        self.assertIn("not as a universal start gate", router)
        self.assertIn("A logout is a diagnostic event", router)
        self.assertIn("Independently verify credible candidates", router)
        self.assertIn("aggregate", router)
        self.assertIn("do not automatically submit externally", router)

    def test_mode_and_model_arguments_are_composable_and_worker_scoped(self):
        router = ROUTER.read_text(encoding="utf-8")
        collaborative = COLLABORATIVE.read_text(encoding="utf-8")
        for phrase in (
            "Bunny multi model <provider>:<model-id>",
            "Bunny model <model-id>",
            "mode words are not model IDs",
            "coordinator keeps its own model",
            "same authenticated provider as the parent",
            "verify the effective model and provider before live work",
            "never borrow the parent's credential or endpoint",
            "Do not change global configuration",
            "do not silently spawn on the wrong model",
        ):
            self.assertIn(phrase, router)
        self.assertIn("ordinary subagent tools", collaborative)
        self.assertIn("--model", router)
        self.assertIn("--provider", router)
        self.assertIn("interactive worker route in `bunny`", collaborative)
        self.assertIn("successive bounded segments", collaborative)
        self.assertIn("do not use approval-bypassing one-shot", collaborative)
        self.assertIn("real PTY", router)
        self.assertIn("Approvals: manual", router)
        self.assertIn("Approvals: smart", router)
        self.assertIn("without `YOLO bypass active`", router)
        self.assertIn("same owned PTY", collaborative)
        self.assertIn("not `delegate_task` steer/stop", collaborative)
        self.assertIn("pending approval", collaborative)
        self.assertIn("final-result-only", OFFHAND.read_text(encoding="utf-8"))

    def test_multi_program_is_depth_first_with_bounded_workers(self):
        router = ROUTER.read_text(encoding="utf-8")
        collaborative = COLLABORATIVE.read_text(encoding="utf-8")
        multi = MULTI.read_text(encoding="utf-8")
        goals = GOALS.read_text(encoding="utf-8")
        registry = (ROOT / "SKILL_REGISTRY.md").read_text(encoding="utf-8")
        self.assertIn("`multi` is a parameter", router)
        self.assertIn("coordinator loads `bunny-multi` before dispatch", collaborative)
        self.assertIn("Ordinary workers load this collaborative skill, not `bunny-multi`", collaborative)
        self.assertIn("Without `multi`, use the ordinary single-program contract", collaborative)
        self.assertIn("name: bunny-multi\n", multi)
        self.assertNotIn("/goal bunny multi", goals)
        self.assertNotIn("run-local coordinator key", router)
        for phrase in (
            "only in the coordinator",
            "not a new Bunny mode, a `/goal` requirement",
            "Several domains within one program are still one program",
            "run-local coordinator key",
            "not in any program's Shared data",
            "all active worker/run IDs",
            "not** a timer, deadline, or reason to move on",
            "close a program only on evidence-backed grounds",
            "three active subagents total",
            "interactive CLI workers count",
            "including multiple workers in one program",
            "free a slot only after confirming that worker has stopped",
            "reporters all count",
            "Verify each candidate independently in its own program",
            "call it separately for each named program",
            "does not validate a comma-separated list",
            "Bunny remains the sole coordinator",
            "without `/goal`, this goal helper is not a prerequisite",
        ):
            self.assertIn(phrase, multi)
        self.assertIn("| **bunny-multi** |", registry)

    def test_collaborative_worker_roles_and_load(self):
        text = COLLABORATIVE.read_text(encoding="utf-8")
        self.assertIn("name: bunny-collaborative\n", text)
        self.assertIn("Both the coordinator and every collaborative worker load", text)
        self.assertIn("Load bunny-collaborative before acting", text)
        self.assertIn("ordinary subagent tools", text)
        for role in ("hunter", "recon", "verifier", "reporter"):
            name = f"bunny-{role}"
            self.assertIn(f"`{name}`", text)
            body = (SKILLS / "bunny" / "agents" / f"{name}.md").read_text(encoding="utf-8")
            self.assertTrue(body.startswith(f"---\nname: {name}\n"))
            self.assertIn("load `bunny-collaborative`", body)

    def test_checkpoint_and_negative_challenge(self):
        text = COLLABORATIVE.read_text(encoding="utf-8")
        hunter = (SKILLS / "bunny" / "agents" / "bunny-hunter.md").read_text(encoding="utf-8")
        for phrase in (
            "send the coordinator a bounded checkpoint",
            "observed result **versus** interpretation",
            "successive bounded segments",
            "periodic stall check is a backstop",
            "3–5 coordinator feedback turns",
            "Hey, there’s a vulnerability here. Find it.",
            "Research the observed technology",
            "creative in-scope tricks",
            "Stop the challenge early on direct disproof",
            "never a factual finding",
        ):
            self.assertIn(phrase, text)
        self.assertIn("requested checkpoints, not only at final completion", hunter)
        self.assertIn("motivational search stance, not evidence", hunter)

    def test_workers_own_scoped_store_writes_and_parent_reconciles(self):
        text = COLLABORATIVE.read_text(encoding="utf-8")
        for phrase in (
            "resolved program, family, and lane", "exact Attempt stream ID",
            "Worker-owned writes", "attempt:<attempt-run-id>:<attempt_id>",
            "read-back", "no Coverage assessment was justified",
            "do not transcribe", "parent", "open sibling",
        ):
            self.assertIn(phrase, text)
        self.assertIn("worker writes", GOALS.read_text(encoding="utf-8"))

    def test_offhand_requires_no_worker_mode(self):
        text = OFFHAND.read_text(encoding="utf-8")
        self.assertIn("name: bunny-offhand\n", text)
        self.assertIn("Only the coordinator loads this mode skill", text)
        self.assertIn("Do not instruct workers to load a Bunny mode skill", text)
        self.assertIn("final bounded result", text)
        self.assertIn("never choose it as the default", text)

    def test_grok_coordinator_preset_is_explicit_and_keeps_worker_alias(self):
        router = ROUTER.read_text(encoding="utf-8")
        for phrase in (
            "bunny grok w/ glm <objective>",
            "Grok 4.6 high as coordinator",
            "GLM-5.3-Flash max as workers",
            "bunny model grok <objective>",
            "retains the worker-model meaning",
            "Outside the explicit Grok coordinator preset",
            "does not resolve the `multi` + offhand conflict",
        ):
            self.assertIn(phrase, router)
        reference = SKILLS / "bunny" / "references" / "grok-coordinator.md"
        self.assertIn("(references/grok-coordinator.md)", router)
        self.assertTrue(reference.is_file())

    def test_grok_transport_and_mixed_worker_route_contract(self):
        text = (SKILLS / "bunny" / "references" / "grok-coordinator.md").read_text(
            encoding="utf-8"
        )
        for phrase in (
            "bunny grok with glm <objective>",
            "bunny multi grok w/ glm <objective>",
            "grok-4.6` / high",
            "glm-5.3-flash` / max",
            "not an invented model ID",
            "hermes auth status xai-oauth",
            "hermes auth status xai",
            "Hermes xAI auth is not Grok",
            "try the other eligible",
            "read-only model call",
            "not a second\ncampaign coordinator",
            "--provider xai-oauth --model grok-4.6 --reasoning high",
            "--provider zai --model glm-5.3-flash --reasoning max",
            "model/provider/**effort** override",
            "cannot enforce this mixed route",
            "do not mutate global delegation settings",
            "Do not silently reduce max",
            "No headless approval bypass",
            "confirmed process exit",
        ):
            self.assertIn(phrase, text)

    def assert_grok_route_resolves(self, skill_dir):
        router = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("(references/grok-coordinator.md)", router)
        self.assertTrue(
            (skill_dir / "references" / "grok-coordinator.md").is_file(),
            "Grok routing reference missing",
        )

    def test_grok_reference_link_guard_rejects_a_broken_projection(self):
        import tempfile
        import shutil

        self.assert_grok_route_resolves(SKILLS / "bunny")
        with tempfile.TemporaryDirectory() as directory:
            projection = Path(directory) / "bunny"
            shutil.copytree(SKILLS / "bunny", projection)
            self.assert_grok_route_resolves(projection)
            router = projection / "SKILL.md"
            original = router.read_text(encoding="utf-8")
            router.write_text(original.replace("(references/grok-coordinator.md)", ""))
            with self.assertRaises(AssertionError):
                self.assert_grok_route_resolves(projection)
            router.write_text(original, encoding="utf-8")
            (projection / "references" / "grok-coordinator.md").unlink()
            with self.assertRaises(AssertionError):
                self.assert_grok_route_resolves(projection)

    def test_registered(self):
        registry = (ROOT / "SKILL_REGISTRY.md").read_text(encoding="utf-8")
        for name in ("bunny", "bunny-collaborative", "bunny-multi", "bunny-offhand"):
            self.assertIn(f"| **{name}** |", registry)
            self.assertIn(f"`skills/{name}/SKILL.md`", registry)


if __name__ == "__main__":
    unittest.main()
