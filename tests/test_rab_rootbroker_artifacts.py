"""Provider-free installation contract for the benchmark's existing rootbroker."""
from __future__ import annotations
import unittest

from tests.test_rootbroker_cutover import cutover


class RABRootbrokerInstalledArtifactsTests(unittest.TestCase):
    def test_controller_and_root_verification_core_have_exact_install_targets(self) -> None:
        artifacts = {item.target: item for item in cutover.ARTIFACTS}
        self.assertEqual(
            artifacts[cutover.RAB_ARM_CONTROLLER_TARGET].source_relative,
            "tools/grabowski_rab_root_arm_controller.py",
        )
        self.assertEqual(artifacts[cutover.RAB_ARM_CONTROLLER_TARGET].mode, 0o755)
        self.assertTrue(artifacts[cutover.RAB_ARM_CONTROLLER_TARGET].python_source)
        self.assertEqual(
            artifacts[cutover.RAB_ARM_CORE_TARGET].source_relative,
            "tools/grabowski_rab_provider_one_shot.py",
        )
        self.assertEqual(artifacts[cutover.RAB_ARM_CORE_TARGET].mode, 0o644)
        self.assertTrue(artifacts[cutover.RAB_ARM_CORE_TARGET].python_source)
        self.assertEqual(
            artifacts[cutover.RAB_ARM_EXEC_TARGET].source_relative,
            "tools/grabowski_rab_arm_exec.py",
        )
        self.assertEqual(artifacts[cutover.RAB_ARM_EXEC_TARGET].mode, 0o755)
        self.assertTrue(artifacts[cutover.RAB_ARM_EXEC_TARGET].python_source)
        closure = (
            (cutover.RAB_CODEX_RUNNER_TARGET, "tools/repobrief_agent_benchmark_codex_runner.py", 0o755),
            (cutover.RAB_BASE_RUNNER_TARGET, "tools/repobrief_agent_benchmark_runner.py", 0o644),
            (cutover.RAB_BOOTSTRAP_TARGET, "tools/repobrief_agent_benchmark_source_bootstrap.py", 0o644),
            (cutover.RAB_CODEX_PREFLIGHT_TARGET, "tools/repobrief_agent_benchmark_codex_preflight.py", 0o755),
            (cutover.RAB_PREFLIGHT_CORE_TARGET, "tools/repobrief_agent_benchmark_preflight_core.py", 0o644),
        )
        for target, source, mode in closure:
            self.assertEqual(artifacts[target].source_relative, source)
            self.assertEqual(artifacts[target].mode, mode)
            self.assertTrue(artifacts[target].python_source)

    def test_controller_is_installed_only_by_existing_commit_bound_cutover(self) -> None:
        sources = [item.source_relative for item in cutover.ARTIFACTS]
        self.assertEqual(sources.count("tools/grabowski_rab_root_arm_controller.py"), 1)
        self.assertEqual(sources.count("tools/grabowski_rab_provider_one_shot.py"), 1)
        self.assertEqual(sources.count("tools/grabowski_rab_arm_exec.py"), 1)
        self.assertEqual(len(sources), len(set(sources)))


if __name__ == "__main__":
    unittest.main()