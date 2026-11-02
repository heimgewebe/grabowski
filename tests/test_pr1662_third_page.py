"""PR #1662: full deploy-index census must include the third 2,000-name page.

The production host had 3,316 durable jobs when the fixed source passed a
read-only full-census smoke; this suite tests further registry growth, including
a late recovery candidate and a late unreadable record.  It uses the same
self-deploy test seam, without accessing or mutating the real job store.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_self_deploy import SELF_DEPLOY


class ThirdPageDeployIndexCensusTests(unittest.TestCase):
    """No 2,000-name or 4,000-name boundary can hide an outstanding job."""

    ORDINARY_COUNT = 4_107

    @staticmethod
    def _ordinary() -> dict[str, object]:
        return {
            "argv": ["/usr/bin/python3", "/tmp/ordinary-nonruntime.py"],
            "final_status": "completed",
        }

    @staticmethod
    def _runner(relative: Path) -> dict[str, object]:
        return {
            "argv": ["/usr/bin/python3", f"/home/alex/repos/grabowski/{relative}"],
            "final_status": "running",
        }

    def _fixture(self, rows: dict[str, dict[str, object]]):
        entries = [Path("/jobs") / name for name in rows]
        root = mock.Mock()
        root.iterdir.side_effect = lambda: iter(entries)
        seen: list[str] = []

        def metadata(unit: str) -> dict[str, object]:
            seen.append(unit)
            return rows[unit]

        return root, seen, metadata

    def test_third_page_late_deploy_and_resume_are_retained_read_only(self) -> None:
        rows = {
            f"grabowski-job-{index:012x}": self._ordinary()
            for index in range(self.ORDINARY_COUNT)
        }
        deploy = "grabowski-job-fffffffffff0"
        resume = "grabowski-job-fffffffffff1"
        rows[deploy] = self._runner(SELF_DEPLOY.RUNNER_RELATIVE_PATH)
        rows[resume] = self._runner(SELF_DEPLOY.MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH)
        root, seen, metadata = self._fixture(rows)

        with (
            mock.patch.object(
                SELF_DEPLOY, "_iter_bootstrap_job_entries",
                side_effect=lambda directory: iter(directory.iterdir()),
            ),
            mock.patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", side_effect=metadata
            ),
            mock.patch.object(
                SELF_DEPLOY, "_deploy_finalization_retry_block", return_value=False
            ),
            mock.patch.object(
                SELF_DEPLOY, "_write_deploy_index"
            ) as write,
            mock.patch.object(Path, "is_symlink", return_value=False),
            mock.patch.object(Path, "is_dir", return_value=True),
        ):
            result = SELF_DEPLOY._bootstrap_deploy_index(root, read_only=True)

        self.assertEqual(len(seen), self.ORDINARY_COUNT + 2)
        self.assertEqual(set(seen), set(rows))
        self.assertEqual(result["units"], [deploy, resume])
        self.assertIsNone(result["pending_unit"])
        self.assertEqual(root.iterdir.call_count, 2)
        write.assert_not_called()

    def test_unreadable_record_in_third_page_prevents_partial_persistence(self) -> None:
        rows = {
            f"grabowski-job-{index:012x}": self._ordinary()
            for index in range(self.ORDINARY_COUNT)
        }
        late = "grabowski-job-fffffffffffe"
        rows[late] = self._runner(SELF_DEPLOY.RUNNER_RELATIVE_PATH)
        root, seen, metadata = self._fixture(rows)

        def fails_at_late_unit(unit: str) -> dict[str, object]:
            if unit == late:
                raise OSError("late runtime job metadata unavailable")
            return metadata(unit)

        with (
            mock.patch.object(
                SELF_DEPLOY, "_iter_bootstrap_job_entries",
                side_effect=lambda directory: iter(directory.iterdir()),
            ),
            mock.patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata",
                side_effect=fails_at_late_unit,
            ),
            mock.patch.object(
                SELF_DEPLOY, "_deploy_finalization_retry_block", return_value=False
            ),
            mock.patch.object(SELF_DEPLOY, "_write_deploy_index") as write,
            mock.patch.object(Path, "is_symlink", return_value=False),
            mock.patch.object(Path, "is_dir", return_value=True),
        ):
            with self.assertRaisesRegex(RuntimeError, "metadata is unreadable"):
                SELF_DEPLOY._bootstrap_deploy_index(root)

        self.assertEqual(len(seen), self.ORDINARY_COUNT)
        write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
