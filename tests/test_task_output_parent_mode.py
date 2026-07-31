from __future__ import annotations

import os
import stat
import unittest
from unittest.mock import patch

from tests.test_tasks import LOCAL_HOST, TaskTests, tasks


class TaskOutputParentModeTests(unittest.TestCase):
    def test_task_logs_reads_files_under_traversable_parent(self) -> None:
        fixture = TaskTests(methodName="test_task_output_paths_are_attempt_bound")
        fixture.setUp()
        try:
            task = fixture._start()["task"]
            os.chmod(fixture.output_root, 0o755)
            paths = fixture._write_task_output(
                task,
                stdout="out-one\nout-two\n",
                stderr="err-one\n",
            )

            with patch.object(
                tasks.fleet, "fleet_host", return_value=LOCAL_HOST
            ), patch.object(tasks, "_dispatch") as dispatch:
                output = tasks.grabowski_task_logs(
                    str(task["task_id"]),
                    max_lines=20,
                )

            dispatch.assert_not_called()
            self.assertEqual(
                stat.S_IMODE(fixture.output_root.stat().st_mode),
                0o755,
            )
            self.assertEqual(
                stat.S_IMODE(paths["directory"].stat().st_mode),
                0o700,
            )
            self.assertEqual(output["output_source"], "private-task-files-v1")
            self.assertEqual(output["result"]["output_reader"], "local-descriptor-v1")
            self.assertEqual(output["result"]["stdout"], "out-one\nout-two\n")
            self.assertEqual(output["result"]["stderr"], "err-one\n")
        finally:
            fixture.tearDown()
