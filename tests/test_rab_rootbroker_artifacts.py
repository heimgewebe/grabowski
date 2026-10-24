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

    def test_controller_is_installed_only_by_existing_commit_bound_cutover(self) -> None:
        sources = [item.source_relative for item in cutover.ARTIFACTS]
        self.assertEqual(sources.count("tools/grabowski_rab_root_arm_controller.py"), 1)
        self.assertEqual(sources.count("tools/grabowski_rab_provider_one_shot.py"), 1)
        self.assertEqual(len(sources), len(set(sources)))


if __name__ == "__main__":
    unittest.main()
