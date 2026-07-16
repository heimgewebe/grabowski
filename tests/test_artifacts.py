from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass
    def tool(self, *args, **kwargs):
        return lambda function: function

class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs

if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types

import grabowski_artifacts as artifacts

REMOTE_HOST = {
    "transport": "ssh",
    "target": "example",
    "enabled": True,
    "roles": ["worker"],
    "command_allowlist": ["*"],
    "connect_timeout_seconds": 10,
}
LOCAL_HOST = {**REMOTE_HOST, "transport": "local", "target": "local"}

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

class ArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.resource_database = self.root / "state" / "resources.sqlite3"
        self.resource_patch = patch.object(
            artifacts.resources, "RESOURCE_DB", self.resource_database
        )
        self.resource_patch.start()

    def tearDown(self) -> None:
        self.resource_patch.stop()
        self.temporary.cleanup()

    def test_local_publish_create_and_replace_preconditions(self) -> None:
        destination = self.root / "artifact.bin"
        temporary = self.root / ".artifact.tmp"
        temporary.write_bytes(b"first")
        result = artifacts._publish_local(
            temporary,
            destination,
            mode="create",
            expected_destination_sha256="",
            expected_source_sha256=sha(b"first"),
        )
        self.assertEqual(result["sha256"], sha(b"first"))
        self.assertEqual(destination.read_bytes(), b"first")

        temporary.write_bytes(b"second")
        with self.assertRaisesRegex(RuntimeError, "precondition"):
            artifacts._publish_local(
                temporary,
                destination,
                mode="replace",
                expected_destination_sha256=sha(b"wrong"),
                expected_source_sha256=sha(b"second"),
            )
        self.assertEqual(destination.read_bytes(), b"first")
        self.assertEqual(temporary.read_bytes(), b"second")

        result = artifacts._publish_local(
            temporary,
            destination,
            mode="replace",
            expected_destination_sha256=sha(b"first"),
            expected_source_sha256=sha(b"second"),
        )
        self.assertEqual(result["mode"], "replace")
        self.assertEqual(destination.read_bytes(), b"second")

    def test_regular_file_contract_rejects_symlink_and_allows_hardlink(self) -> None:
        source = self.root / "source"
        source.write_bytes(b"x")
        symlink = self.root / "link"
        symlink.symlink_to(source)
        with self.assertRaises(ValueError):
            artifacts._hash_file(symlink)
        hardlink = self.root / "hard"
        hardlink.hardlink_to(source)
        digest, size = artifacts._hash_file(source)
        self.assertEqual(digest, sha(b"x"))
        self.assertEqual(size, 1)

    def test_remote_path_is_canonical_and_merges_is_immutable(self) -> None:
        self.assertEqual(artifacts._remote_path("/home/alex/out.bin"), "/home/alex/out.bin")
        for path in ("relative", "/home/alex/a/../b", "/home/alex/repos/merges/x"):
            with self.assertRaises((ValueError, PermissionError)):
                artifacts._remote_path(path)

    def test_remote_resource_keys_are_host_scoped(self) -> None:
        first = artifacts._remote_resource_key("heimserver", "/home/alex/file")
        second = artifacts._remote_resource_key("heimberry", "/home/alex/file")
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("service:artifact-path-"))

    def test_pull_verifies_remote_and_publishes_atomically(self) -> None:
        payload = b"payload"
        expected = sha(payload)
        destination = self.root / "result.bin"

        def fake_scp(host: str, source: str, destination_path: str, *, upload: bool):
            self.assertFalse(upload)
            Path(destination_path).write_bytes(payload)
            return {"returncode": 0, "stdout": "", "stderr": ""}

        with patch.object(artifacts.fleet, "fleet_host", return_value=REMOTE_HOST), patch.object(
            artifacts, "_remote_stat",
            return_value={"exists": True, "path": "/remote/file", "host": "remote", "size": len(payload), "sha256": expected},
        ), patch.object(artifacts, "_local_destination", return_value=(destination, False)), patch.object(
            artifacts, "_scp", side_effect=fake_scp
        ):
            result = artifacts.artifact_pull(
                "remote", "/remote/file", str(destination), expected, create_only=True
            )
        self.assertEqual(destination.read_bytes(), payload)
        self.assertEqual(result["sha256"], expected)
        self.assertEqual(artifacts.resources.list_resources(), [])

    def test_push_cleans_remote_temporary_on_publish_failure(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"payload")
        expected = sha(b"payload")
        old = sha(b"old")
        cleaned: list[str] = []
        pre_state = {"exists": True, "size": 3, "sha256": old}
        with patch.object(artifacts, "_local_source", return_value=source), patch.object(
            artifacts.fleet, "fleet_host", return_value=REMOTE_HOST
        ), patch.object(
            artifacts, "_remote_stat", side_effect=[pre_state, dict(pre_state)]
        ), patch.object(
            artifacts, "_scp", return_value={"returncode": 0, "stdout": "", "stderr": ""}
        ), patch.object(
            artifacts, "_remote_run", side_effect=RuntimeError("destination hash precondition failed")
        ), patch.object(
            artifacts, "_remote_cleanup", side_effect=lambda host, path: cleaned.append(path)
        ):
            with self.assertRaisesRegex(RuntimeError, "without changing"):
                artifacts.artifact_push(
                    "remote", str(source), "/remote/file", expected,
                    create_only=False, expected_destination_sha256=old,
                )
        self.assertEqual(len(cleaned), 1)
        self.assertTrue(cleaned[0].startswith("/remote/file.grabowski-"))
        self.assertEqual(artifacts.resources.list_resources(), [])

    def test_push_returns_only_provenance_not_contents(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"secret-like-content")
        expected = sha(source.read_bytes())
        publish = {"returncode": 0, "stdout": json.dumps({"size": source.stat().st_size, "sha256": expected, "mode": "create"}), "stderr": ""}
        with patch.object(artifacts, "_local_source", return_value=source), patch.object(
            artifacts.fleet, "fleet_host", return_value=REMOTE_HOST
        ), patch.object(
            artifacts, "_remote_stat", side_effect=[
                {"exists": False},
                {"exists": True, "size": source.stat().st_size, "sha256": expected},
            ]
        ), patch.object(
            artifacts, "_scp", return_value={"returncode": 0, "stdout": "", "stderr": ""}
        ), patch.object(artifacts, "_remote_run", return_value=publish):
            result = artifacts.artifact_push(
                "remote", str(source), "/remote/file", expected, create_only=True
            )
        self.assertNotIn("secret-like-content", json.dumps(result))
        self.assertTrue(result["success"])
        self.assertEqual(result["sha256"], expected)
        self.assertEqual(
            result["mutation_outcome"],
            "confirmed_by_publish_receipt_and_post_state_readback",
        )
        self.assertEqual(result["post_state_readback"]["sha256"], expected)
        self.assertTrue(result["publish_response_valid"])

    def test_push_recovers_success_from_post_state_after_invalid_response(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"payload")
        expected = sha(source.read_bytes())
        cleaned: list[str] = []
        with patch.object(artifacts, "_local_source", return_value=source), patch.object(
            artifacts.fleet, "fleet_host", return_value=REMOTE_HOST
        ), patch.object(
            artifacts, "_remote_stat", side_effect=[
                {"exists": False},
                {"exists": True, "size": source.stat().st_size, "sha256": expected},
            ]
        ), patch.object(
            artifacts, "_scp", return_value={"returncode": 0, "stdout": "", "stderr": ""}
        ), patch.object(
            artifacts, "_remote_run", return_value={"returncode": 0, "stdout": "", "stderr": ""}
        ), patch.object(
            artifacts, "_remote_cleanup", side_effect=lambda host, path: cleaned.append(path)
        ):
            result = artifacts.artifact_push(
                "remote", str(source), "/remote/file", expected, create_only=True
            )
        self.assertTrue(result["success"])
        self.assertFalse(result["publish_response_valid"])
        self.assertEqual(
            result["mutation_outcome"],
            "confirmed_by_post_state_readback_after_publish_error",
        )
        self.assertEqual(result["post_state_readback"]["sha256"], expected)
        self.assertEqual(cleaned, [])
        self.assertEqual(artifacts.resources.list_resources(), [])

    def test_push_cleans_partial_temporary_after_scp_failure(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"payload")
        expected = sha(source.read_bytes())
        cleaned: list[str] = []
        with patch.object(artifacts, "_local_source", return_value=source), patch.object(
            artifacts.fleet, "fleet_host", return_value=REMOTE_HOST
        ), patch.object(
            artifacts, "_remote_stat", return_value={"exists": False}
        ), patch.object(
            artifacts, "_scp", return_value={"returncode": 1, "stdout": "", "stderr": "copy failed"}
        ), patch.object(
            artifacts, "_remote_cleanup", side_effect=lambda host, path: cleaned.append(path)
        ):
            with self.assertRaisesRegex(RuntimeError, "copy failed"):
                artifacts.artifact_push(
                    "remote", str(source), "/remote/file", expected, create_only=True
                )
        self.assertEqual(len(cleaned), 1)
        self.assertTrue(cleaned[0].startswith("/remote/file.grabowski-"))
        self.assertEqual(artifacts.resources.list_resources(), [])

    def test_push_marks_valid_receipt_with_contradictory_post_state_ambiguous(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"payload")
        expected = sha(source.read_bytes())
        other = sha(b"other")
        publish = {
            "returncode": 0,
            "stdout": json.dumps(
                {"size": source.stat().st_size, "sha256": expected, "mode": "create"}
            ),
            "stderr": "",
        }
        with patch.object(artifacts, "_local_source", return_value=source), patch.object(
            artifacts.fleet, "fleet_host", return_value=REMOTE_HOST
        ), patch.object(
            artifacts, "_remote_stat", side_effect=[
                {"exists": False},
                {"exists": True, "size": 5, "sha256": other},
            ]
        ), patch.object(
            artifacts, "_scp", return_value={"returncode": 0, "stdout": "", "stderr": ""}
        ), patch.object(artifacts, "_remote_run", return_value=publish), patch.object(
            artifacts, "_remote_cleanup"
        ):
            result = artifacts.artifact_push(
                "remote", str(source), "/remote/file", expected, create_only=True
            )
        self.assertFalse(result["success"])
        self.assertTrue(result["publish_response_valid"])
        ambiguity = result["ambiguous_mutation_outcome"]
        self.assertTrue(ambiguity["publish_response_valid"])
        self.assertIn("contradicted", ambiguity["publish_error"])
        self.assertEqual(ambiguity["observed_post_state"]["sha256"], other)
        self.assertEqual(artifacts.resources.list_resources(), [])

    def test_push_returns_ambiguous_receipt_when_post_state_readback_fails(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"payload")
        expected = sha(source.read_bytes())
        cleaned: list[str] = []
        with patch.object(artifacts, "_local_source", return_value=source), patch.object(
            artifacts.fleet, "fleet_host", return_value=REMOTE_HOST
        ), patch.object(
            artifacts, "_remote_stat", side_effect=[
                {"exists": False},
                RuntimeError("readback offline"),
            ]
        ), patch.object(
            artifacts, "_scp", return_value={"returncode": 0, "stdout": "", "stderr": ""}
        ), patch.object(
            artifacts, "_remote_run", side_effect=RuntimeError("transport response lost")
        ), patch.object(
            artifacts, "_remote_cleanup", side_effect=lambda host, path: cleaned.append(path)
        ):
            result = artifacts.artifact_push(
                "remote", str(source), "/remote/file", expected, create_only=True
            )
        self.assertFalse(result["success"])
        self.assertEqual(result["mutation_outcome"], "ambiguous")
        ambiguity = result["ambiguous_mutation_outcome"]
        self.assertEqual(ambiguity["reason"], "post_state_readback_failed")
        self.assertFalse(result["publish_response_valid"])
        self.assertFalse(ambiguity["publish_response_valid"])
        self.assertEqual(ambiguity["verification"]["method"], "grabowski_artifact_stat")
        self.assertIn("readback offline", ambiguity["readback_error"])
        self.assertEqual(len(cleaned), 1)
        self.assertEqual(artifacts.resources.list_resources(), [])

    def test_push_requires_readback_after_valid_publish_receipt(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"payload")
        expected = sha(source.read_bytes())
        publish = {
            "returncode": 0,
            "stdout": json.dumps(
                {"size": source.stat().st_size, "sha256": expected, "mode": "create"}
            ),
            "stderr": "",
        }
        with patch.object(artifacts, "_local_source", return_value=source), patch.object(
            artifacts.fleet, "fleet_host", return_value=REMOTE_HOST
        ), patch.object(
            artifacts, "_remote_stat", side_effect=[
                {"exists": False},
                RuntimeError("verification unavailable"),
            ]
        ), patch.object(
            artifacts, "_scp", return_value={"returncode": 0, "stdout": "", "stderr": ""}
        ), patch.object(artifacts, "_remote_run", return_value=publish), patch.object(
            artifacts, "_remote_cleanup"
        ):
            result = artifacts.artifact_push(
                "remote", str(source), "/remote/file", expected, create_only=True
            )
        self.assertFalse(result["success"])
        self.assertTrue(result["publish_response_valid"])
        ambiguity = result["ambiguous_mutation_outcome"]
        self.assertTrue(ambiguity["publish_response_valid"])
        self.assertEqual(ambiguity["reason"], "post_state_readback_failed")
        self.assertIn("verification unavailable", ambiguity["readback_error"])
        self.assertEqual(artifacts.resources.list_resources(), [])

    def test_push_returns_ambiguous_receipt_for_unexpected_post_state(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"payload")
        expected = sha(source.read_bytes())
        other = sha(b"other")
        with patch.object(artifacts, "_local_source", return_value=source), patch.object(
            artifacts.fleet, "fleet_host", return_value=REMOTE_HOST
        ), patch.object(
            artifacts, "_remote_stat", side_effect=[
                {"exists": False},
                {"exists": True, "size": 5, "sha256": other},
            ]
        ), patch.object(
            artifacts, "_scp", return_value={"returncode": 0, "stdout": "", "stderr": ""}
        ), patch.object(
            artifacts, "_remote_run", side_effect=RuntimeError("publish response lost")
        ), patch.object(artifacts, "_remote_cleanup"):
            result = artifacts.artifact_push(
                "remote", str(source), "/remote/file", expected, create_only=True
            )
        self.assertFalse(result["success"])
        ambiguity = result["ambiguous_mutation_outcome"]
        self.assertEqual(
            ambiguity["reason"],
            "post_state_did_not_match_precondition_or_expected_artifact",
        )
        self.assertEqual(ambiguity["observed_post_state"]["sha256"], other)
        self.assertEqual(artifacts.resources.list_resources(), [])

if __name__ == "__main__":
    unittest.main()
