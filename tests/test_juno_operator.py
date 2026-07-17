from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
JUNO_ROOT = ROOT / "tools" / "juno"
sys.path.insert(0, str(JUNO_ROOT))

from juno_operator import collectors, models, paths  # noqa: E402
from juno_operator.app import create_incident, refresh  # noqa: E402


class ModelTests(unittest.TestCase):
    def test_overall_status_is_fail_closed(self) -> None:
        healthy = models.CollectorResult("a", "healthy", models.utc_now())
        unknown = models.CollectorResult("b", "unknown", models.utc_now())
        self.assertEqual(models.Snapshot(1, models.utc_now(), (healthy,)).overall_status, "healthy")
        self.assertEqual(models.Snapshot(1, models.utc_now(), (healthy, unknown)).overall_status, "unknown")


class PathTests(unittest.TestCase):
    def test_document_ancestor_uses_name_not_container_uuid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "random-container" / "Documents" / "Juno Operator"
            project.mkdir(parents=True)
            with mock.patch.object(paths.glob, "glob", return_value=[]):
                roots = paths.discover_storage_roots(project)
            self.assertEqual(roots, [("Juno-Dokumente", project.parent.resolve())])


class CollectorTests(unittest.TestCase):
    def test_target_config_rejects_unknown_kind(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "targets.json"
            config.write_text(json.dumps({"schema_version": 1, "targets": [{"id": "x", "kind": "shell"}]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid target"):
                collectors.load_targets(config)

    def test_target_config_rejects_endpoint_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "targets.json"
            config.write_text(
                json.dumps({
                    "schema_version": 1,
                    "targets": [{
                        "id": "heim-pc-ssh",
                        "kind": "tcp",
                        "host": "example.invalid",
                        "port": 22,
                    }],
                }),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "fixed endpoint"):
                collectors.load_targets(config)

    def test_storage_listing_is_immediate_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "Documents"
            project = root / "Juno Operator"
            project.mkdir(parents=True)
            for index in range(105):
                (root / f"f-{index:03d}.txt").write_text("x", encoding="utf-8")
            with mock.patch.object(paths.glob, "glob", return_value=[]):
                result = collectors.collect_storage(project)
            self.assertEqual(result.status, "healthy")
            observed = result.data["roots"][0]
            self.assertEqual(observed["entry_count_observed"], 100)
            self.assertTrue(observed["entries_truncated"])


class AppTests(unittest.TestCase):
    def _project(self, root: Path) -> Path:
        project = root / "Documents" / "Juno Operator"
        (project / "config").mkdir(parents=True)
        (project / "config" / "targets.json").write_text('{"schema_version":1,"targets":[]}\n', encoding="utf-8")
        return project

    def test_refresh_writes_cache_and_dashboard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = self._project(Path(temporary))
            with mock.patch.object(paths.glob, "glob", return_value=[]):
                snapshot, dashboard = refresh(project)
            self.assertTrue(dashboard.is_file())
            self.assertTrue((project / "state" / "latest.json").is_file())
            self.assertIn("Juno Operator", dashboard.read_text(encoding="utf-8"))
            self.assertEqual(snapshot.schema_version, 1)

    def test_incident_is_non_overwriting_and_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = self._project(Path(temporary))
            with mock.patch.object(paths.glob, "glob", return_value=[]):
                incident = create_incident(project)
            self.assertTrue((incident / "manifest.json").is_file())
            checksums = json.loads((incident / "checksums.json").read_text(encoding="utf-8"))
            self.assertEqual(set(checksums), {"dashboard.html", "snapshot.json", "summary.md"})


if __name__ == "__main__":
    unittest.main()
