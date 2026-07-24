from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import subprocess
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
        self.root_patch = patch.object(
            artifacts.base, "_roots", return_value=(self.root,)
        )
        self.resource_patch.start()
        self.root_patch.start()

    def tearDown(self) -> None:
        self.root_patch.stop()
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
        cleaned: list[str] = []
        with patch.object(artifacts, "_local_source", return_value=source), patch.object(
            artifacts.fleet, "fleet_host", return_value=REMOTE_HOST
        ), patch.object(
            artifacts, "_scp", return_value={"returncode": 0, "stdout": "", "stderr": ""}
        ), patch.object(
            artifacts, "_remote_run", side_effect=RuntimeError("destination hash precondition failed")
        ), patch.object(
            artifacts, "_remote_cleanup", side_effect=lambda host, path: cleaned.append(path)
        ):
            with self.assertRaisesRegex(RuntimeError, "precondition"):
                artifacts.artifact_push(
                    "remote", str(source), "/remote/file", expected,
                    create_only=False, expected_destination_sha256=sha(b"old"),
                )
        self.assertEqual(len(cleaned), 1)
        self.assertTrue(cleaned[0].startswith("/remote/file.grabowski-"))
        self.assertEqual(artifacts.resources.list_resources(), [])

    def test_remote_create_publish_accepts_nonempty_no_hash_sentinel(self) -> None:
        payload = b"payload"
        source = self.root / "temporary.bin"
        destination = self.root / "published.bin"
        source.write_bytes(payload)
        expected = sha(payload)

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                artifacts._REMOTE_PUBLISH_SCRIPT,
                str(source),
                str(destination),
                expected,
                "create",
                artifacts._NO_DESTINATION_HASH,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(source.exists())
        self.assertEqual(destination.read_bytes(), payload)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["sha256"], expected)
        self.assertEqual(receipt["mode"], "create")

    def test_create_only_push_never_dispatches_empty_argv(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"payload")
        expected = sha(source.read_bytes())
        observed_argv: list[str] = []

        def fake_remote_run(host: str, argv: list[str], timeout_seconds: int = 60):
            self.assertEqual(host, "remote")
            observed_argv.extend(argv)
            return {
                "returncode": 0,
                "stdout": json.dumps(
                    {"size": source.stat().st_size, "sha256": expected, "mode": "create"}
                ),
                "stderr": "",
            }

        with patch.object(artifacts, "_local_source", return_value=source), patch.object(
            artifacts.fleet, "fleet_host", return_value=REMOTE_HOST
        ), patch.object(
            artifacts, "_scp", return_value={"returncode": 0, "stdout": "", "stderr": ""}
        ), patch.object(artifacts, "_remote_run", side_effect=fake_remote_run):
            result = artifacts.artifact_push(
                "remote", str(source), "/remote/file", expected, create_only=True
            )

        self.assertEqual(result["sha256"], expected)
        self.assertTrue(observed_argv)
        self.assertTrue(all(isinstance(item, str) and item for item in observed_argv))
        self.assertEqual(observed_argv[-1], artifacts._NO_DESTINATION_HASH)

    def test_push_returns_only_provenance_not_contents(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"secret-like-content")
        expected = sha(source.read_bytes())
        publish = {"returncode": 0, "stdout": json.dumps({"size": source.stat().st_size, "sha256": expected, "mode": "create"}), "stderr": ""}
        with patch.object(artifacts, "_local_source", return_value=source), patch.object(
            artifacts.fleet, "fleet_host", return_value=REMOTE_HOST
        ), patch.object(
            artifacts, "_scp", return_value={"returncode": 0, "stdout": "", "stderr": ""}
        ), patch.object(artifacts, "_remote_run", return_value=publish):
            result = artifacts.artifact_push(
                "remote", str(source), "/remote/file", expected, create_only=True
            )
        self.assertNotIn("secret-like-content", json.dumps(result))
        self.assertEqual(result["sha256"], expected)

    def test_redaction_is_bounded_and_independent_of_operator_private_helpers(self) -> None:
        secret = "super-secret-value"
        diagnostic = (
            f"Authorization: Bearer {secret} password={secret} "
            f"https://user:{secret}@example.invalid/ "
            + "x" * (artifacts.MAX_ERROR_INPUT_CHARS + 100)
        )
        with patch.object(
            artifacts.operator,
            "_redact_text",
            side_effect=AssertionError("private helper must not be called"),
            create=True,
        ):
            redacted = artifacts._redact_transfer_detail(diagnostic)
        self.assertNotIn(secret, redacted)
        self.assertIn("[REDACTED]", redacted)
        self.assertLessEqual(len(redacted), artifacts.MAX_ERROR_DETAIL_CHARS)

        injected = artifacts._redact_transfer_detail(
            "token=still-secret", redactor=lambda value: value.replace("still-secret", "clean")
        )
        self.assertNotIn("still-secret", injected)

        json_redacted = artifacts._redact_transfer_detail(
            '{"access_token": "json-secret", "status": "failed"}'
        )
        self.assertNotIn("json-secret", json_redacted)
        self.assertIn("[REDACTED]", json_redacted)

    def test_traceback_redaction_emits_only_the_controlled_final_diagnostic(self) -> None:
        secret = "traceback-secret-value"
        diagnostic = (
            "Traceback (most recent call last):\n"
            "  File \"<string>\", line 34, in <module>\n"
            "    raise RuntimeError(\"destination already exists\")\n"
            "RuntimeError: destination already exists token=" + secret
        )

        redacted = artifacts._redact_transfer_detail(diagnostic)

        self.assertNotIn("Traceback", redacted)
        self.assertNotIn("<string>", redacted)
        self.assertNotIn("RuntimeError", redacted)
        self.assertNotIn(secret, redacted)
        self.assertEqual(redacted, "destination already exists token=[REDACTED]")

    def test_remote_failure_is_total_and_redacts_secret_output(self) -> None:
        secret = "remote-secret-value"
        failure = {
            "result": {
                "returncode": 255,
                "stdout": "",
                "stderr": f"Authorization: Bearer {secret} password={secret}",
            }
        }
        with patch.object(artifacts.fleet, "run_fleet_host", return_value=failure):
            with self.assertRaises(artifacts.ArtifactTransferError) as context:
                artifacts._remote_run("remote", ["true"])
        message = str(context.exception)
        self.assertNotIn(secret, message)
        self.assertIn("[REDACTED]", message)
        self.assertLessEqual(len(message), artifacts.MAX_ERROR_DETAIL_CHARS + 64)

    def test_push_scp_failure_redacts_and_releases_exact_lease(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"payload")
        expected = sha(b"payload")
        secret = "scp-upload-secret"
        cleaned: list[str] = []
        with patch.object(artifacts, "_local_source", return_value=source), patch.object(
            artifacts.fleet, "fleet_host", return_value=REMOTE_HOST
        ), patch.object(
            artifacts,
            "_scp",
            return_value={"returncode": 1, "stdout": "", "stderr": f"token={secret}"},
        ), patch.object(
            artifacts, "_remote_cleanup", side_effect=lambda host, path: cleaned.append(path)
        ):
            with self.assertRaises(artifacts.ArtifactTransferError) as context:
                artifacts.artifact_push(
                    "remote", str(source), "/remote/file", expected, create_only=True
                )
        self.assertNotIn(secret, str(context.exception))
        self.assertEqual(len(cleaned), 1)
        self.assertEqual(artifacts.resources.list_resources(), [])

    def test_pull_scp_failure_redacts_and_preserves_destination(self) -> None:
        payload = b"payload"
        expected = sha(payload)
        destination = self.root / "result.bin"
        secret = "scp-download-secret"
        with patch.object(artifacts.fleet, "fleet_host", return_value=REMOTE_HOST), patch.object(
            artifacts,
            "_remote_stat",
            return_value={
                "exists": True,
                "path": "/remote/file",
                "host": "remote",
                "size": len(payload),
                "sha256": expected,
            },
        ), patch.object(
            artifacts, "_local_destination", return_value=(destination, False)
        ), patch.object(
            artifacts,
            "_scp",
            return_value={"returncode": 1, "stdout": "", "stderr": f"password={secret}"},
        ):
            with self.assertRaises(artifacts.ArtifactTransferError) as context:
                artifacts.artifact_pull(
                    "remote", "/remote/file", str(destination), expected, create_only=True
                )
        self.assertNotIn(secret, str(context.exception))
        self.assertFalse(destination.exists())
        self.assertEqual(artifacts.resources.list_resources(), [])

    def test_public_push_boundary_redacts_missing_host_and_source_drift(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"payload")
        expected = sha(b"payload")
        secret = "host-secret-value"
        with patch.object(
            artifacts.operator, "_require_operator_mutation", return_value=None
        ), patch.object(artifacts, "_local_source", return_value=source), patch.object(
            artifacts.fleet, "fleet_host", side_effect=ValueError(f"missing token={secret}")
        ):
            with self.assertRaises(artifacts.ArtifactTransferError) as context:
                artifacts.grabowski_artifact_push(
                    "missing", str(source), "/remote/file", expected
                )
        self.assertNotIn(secret, str(context.exception))

        with patch.object(
            artifacts.operator, "_require_operator_mutation", return_value=None
        ), patch.object(artifacts, "_local_source", return_value=source), patch.object(
            artifacts, "_hash_file", side_effect=RuntimeError(f"source drift token={secret}")
        ):
            with self.assertRaises(artifacts.ArtifactTransferError) as context:
                artifacts.grabowski_artifact_push(
                    "remote", str(source), "/remote/file", expected
                )
        self.assertNotIn(secret, str(context.exception))
        self.assertIn("source drift", str(context.exception))

    def test_public_pull_collision_and_destination_hash_mismatch_are_bounded(self) -> None:
        payload = b"new-payload"
        expected_source = sha(payload)
        destination = self.root / "result.bin"
        destination.write_bytes(b"old-payload")

        def fake_scp(host: str, source: str, destination_path: str, *, upload: bool):
            self.assertFalse(upload)
            Path(destination_path).write_bytes(payload)
            return {"returncode": 0, "stdout": "", "stderr": ""}

        common = (
            patch.object(artifacts.operator, "_require_operator_mutation", return_value=None),
            patch.object(artifacts.fleet, "fleet_host", return_value=REMOTE_HOST),
            patch.object(
                artifacts,
                "_remote_stat",
                return_value={
                    "exists": True,
                    "path": "/remote/file",
                    "host": "remote",
                    "size": len(payload),
                    "sha256": expected_source,
                },
            ),
            patch.object(artifacts, "_local_destination", return_value=(destination, True)),
            patch.object(artifacts, "_scp", side_effect=fake_scp),
        )
        for context in common:
            context.start()
        try:
            with self.assertRaises(artifacts.ArtifactTransferError) as collision:
                artifacts.grabowski_artifact_pull(
                    "remote",
                    "/remote/file",
                    str(destination),
                    expected_source,
                    create_only=True,
                )
            self.assertIn("destination already exists", str(collision.exception))
            self.assertLessEqual(
                len(str(collision.exception)), artifacts.MAX_ERROR_DETAIL_CHARS
            )
            self.assertEqual(destination.read_bytes(), b"old-payload")
            self.assertEqual(artifacts.resources.list_resources(), [])

            with self.assertRaises(artifacts.ArtifactTransferError) as mismatch:
                artifacts.grabowski_artifact_pull(
                    "remote",
                    "/remote/file",
                    str(destination),
                    expected_source,
                    create_only=False,
                    expected_destination_sha256=sha(b"different-old-payload"),
                )
            self.assertIn("Destination hash precondition failed", str(mismatch.exception))
            self.assertLessEqual(
                len(str(mismatch.exception)), artifacts.MAX_ERROR_DETAIL_CHARS
            )
            self.assertEqual(destination.read_bytes(), b"old-payload")
            self.assertEqual(artifacts.resources.list_resources(), [])
        finally:
            for context in reversed(common):
                context.stop()

    def test_public_boundary_resanitizes_artifact_transfer_errors(self) -> None:
        secret = "nested-secret-value"
        error = artifacts.ArtifactTransferError(f'token={secret} ' + "x" * 5000)
        redacted = artifacts._transfer_error("push", error)
        self.assertNotIn(secret, str(redacted))
        self.assertLessEqual(len(str(redacted)), artifacts.MAX_ERROR_DETAIL_CHARS)

    def test_push_rejects_invalid_remote_integrity_receipt(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"payload")
        expected = sha(b"payload")
        publish = {
            "returncode": 0,
            "stdout": json.dumps(
                {"size": source.stat().st_size, "sha256": sha(b"wrong"), "mode": "create"}
            ),
            "stderr": "",
        }
        with patch.object(artifacts, "_local_source", return_value=source), patch.object(
            artifacts.fleet, "fleet_host", return_value=REMOTE_HOST
        ), patch.object(
            artifacts, "_scp", return_value={"returncode": 0, "stdout": "", "stderr": ""}
        ), patch.object(artifacts, "_remote_run", return_value=publish):
            with self.assertRaisesRegex(
                artifacts.ArtifactTransferError, "integrity receipt"
            ):
                artifacts.artifact_push(
                    "remote", str(source), "/remote/file", expected, create_only=True
                )
        self.assertEqual(artifacts.resources.list_resources(), [])


    def _git(self, repository: Path, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return completed.stdout.strip()

    def _repository_with_two_commits(self) -> tuple[Path, str, str]:
        repository = self.root / "repository"
        repository.mkdir()
        self._git(repository, "init")
        self._git(repository, "config", "user.name", "Artifact Test")
        self._git(repository, "config", "user.email", "artifact@example.test")
        (repository / "value.txt").write_text("first\n")
        self._git(repository, "add", "value.txt")
        self._git(repository, "commit", "-m", "first")
        base_commit = self._git(repository, "rev-parse", "HEAD")
        (repository / "value.txt").write_text("second\n")
        self._git(repository, "commit", "-am", "second")
        head_commit = self._git(repository, "rev-parse", "HEAD")
        return repository, base_commit, head_commit

    def test_text_artifact_publish_and_chunked_read_are_hash_bound(self) -> None:
        repository, base_commit, head_commit = self._repository_with_two_commits()
        artifact_root = self.root / "text-artifacts"
        with patch.object(artifacts, "TEXT_ARTIFACT_ROOT", artifact_root):
            result = artifacts.publish_text_artifact(
                "git-diff.v1",
                str(repository),
                base_commit,
                head_commit,
                pull_request_number=17,
            )
            self.assertEqual(result["schema"], "git-diff-artifact.v1")
            self.assertTrue(result["filename"].endswith("-diff.txt"))
            chunks = []
            offset = 0
            while True:
                chunk = artifacts.read_text_artifact(
                    result["artifact_id"],
                    result["diff_sha256"],
                    result["receipt_sha256"],
                    offset=offset,
                    max_bytes=11,
                )
                payload = __import__("base64").b64decode(chunk["payload_b64"])
                self.assertEqual(chunk["chunk_sha256"], sha(payload))
                chunks.append(payload)
                if chunk["next_offset"] is None:
                    break
                offset = chunk["next_offset"]
            data = b"".join(chunks)
            self.assertEqual(len(data), result["byte_size"])
            self.assertEqual(sha(data), result["diff_sha256"])
            self.assertIn(b"-first", data)
            self.assertIn(b"+second", data)

    def test_text_artifact_requires_exact_full_commit_sha(self) -> None:
        repository, base_commit, head_commit = self._repository_with_two_commits()
        with patch.object(
            artifacts, "TEXT_ARTIFACT_ROOT", self.root / "text-artifacts"
        ):
            with self.assertRaisesRegex(ValueError, "full lowercase"):
                artifacts.publish_text_artifact(
                    "git-diff.v1", str(repository), "HEAD~1", head_commit
                )
            with self.assertRaisesRegex(ValueError, "full lowercase"):
                artifacts.publish_text_artifact(
                    "git-diff.v1", str(repository), base_commit, "HEAD"
                )

    def test_text_artifact_read_rejects_tampering(self) -> None:
        repository, base_commit, head_commit = self._repository_with_two_commits()
        artifact_root = self.root / "text-artifacts"
        with patch.object(artifacts, "TEXT_ARTIFACT_ROOT", artifact_root):
            result = artifacts.publish_text_artifact(
                "git-diff.v1", str(repository), base_commit, head_commit
            )
            path = artifact_root / result["artifact_id"] / result["filename"]
            path.write_bytes(path.read_bytes() + b"tampered")
            with self.assertRaisesRegex(
                artifacts.ArtifactTransferError, "integrity verification"
            ):
                artifacts.read_text_artifact(
                    result["artifact_id"],
                    result["diff_sha256"],
                    result["receipt_sha256"],
                )


    def test_text_artifact_read_requires_pinned_receipt_hash(self) -> None:
        repository, base_commit, head_commit = self._repository_with_two_commits()
        artifact_root = self.root / "text-artifacts"
        with patch.object(artifacts, "TEXT_ARTIFACT_ROOT", artifact_root):
            result = artifacts.publish_text_artifact(
                "git-diff.v1", str(repository), base_commit, head_commit
            )
            with self.assertRaisesRegex(
                artifacts.ArtifactTransferError, "receipt hash precondition"
            ):
                artifacts.read_text_artifact(
                    result["artifact_id"], result["diff_sha256"], "0" * 64
                )

    def test_text_artifact_ignores_git_replace_refs(self) -> None:
        repository, base_commit, head_commit = self._repository_with_two_commits()
        self._git(repository, "checkout", "--detach", base_commit)
        (repository / "value.txt").write_text("replacement\n")
        self._git(repository, "commit", "-am", "replacement")
        replacement_commit = self._git(repository, "rev-parse", "HEAD")
        self._git(repository, "replace", head_commit, replacement_commit)
        artifact_root = self.root / "text-artifacts"
        with patch.object(artifacts, "TEXT_ARTIFACT_ROOT", artifact_root):
            result = artifacts.publish_text_artifact(
                "git-diff.v1", str(repository), base_commit, head_commit
            )
            data = (
                artifact_root / result["artifact_id"] / result["filename"]
            ).read_bytes()
        self.assertIn(b"+second", data)
        self.assertNotIn(b"+replacement", data)

    def test_text_artifact_read_rejects_symlinked_receipt(self) -> None:
        repository, base_commit, head_commit = self._repository_with_two_commits()
        artifact_root = self.root / "text-artifacts"
        with patch.object(artifacts, "TEXT_ARTIFACT_ROOT", artifact_root):
            result = artifacts.publish_text_artifact(
                "git-diff.v1", str(repository), base_commit, head_commit
            )
            directory = artifact_root / result["artifact_id"]
            receipt = directory / "receipt.json"
            external = self.root / "external-receipt.json"
            external.write_bytes(receipt.read_bytes())
            external.chmod(0o600)
            receipt.unlink()
            receipt.symlink_to(external)
            with self.assertRaisesRegex(
                artifacts.ArtifactTransferError, "file open failed"
            ):
                artifacts.read_text_artifact(
                    result["artifact_id"],
                    result["diff_sha256"],
                    result["receipt_sha256"],
                )

    def test_text_artifact_read_rejects_hardlinked_diff(self) -> None:
        repository, base_commit, head_commit = self._repository_with_two_commits()
        artifact_root = self.root / "text-artifacts"
        with patch.object(artifacts, "TEXT_ARTIFACT_ROOT", artifact_root):
            result = artifacts.publish_text_artifact(
                "git-diff.v1", str(repository), base_commit, head_commit
            )
            path = artifact_root / result["artifact_id"] / result["filename"]
            (self.root / "external-diff.txt").hardlink_to(path)
            with self.assertRaisesRegex(
                artifacts.ArtifactTransferError,
                "not one private owner-controlled regular file",
            ):
                artifacts.read_text_artifact(
                    result["artifact_id"],
                    result["diff_sha256"],
                    result["receipt_sha256"],
                )

    def test_text_artifact_blocks_private_key_markers(self) -> None:
        repository, base_commit, _ = self._repository_with_two_commits()
        private_key_marker = (
            "-----" + "BEGIN OPENSSH " + "PRIVATE " + "KEY-----"
        )
        (repository / "value.txt").write_text(
            private_key_marker + "\nnot-a-real-key\n"
        )
        self._git(repository, "commit", "-am", "secret marker")
        head_commit = self._git(repository, "rev-parse", "HEAD")
        with patch.object(
            artifacts, "TEXT_ARTIFACT_ROOT", self.root / "text-artifacts"
        ):
            with self.assertRaisesRegex(PermissionError, "private-key marker"):
                artifacts.publish_text_artifact(
                    "git-diff.v1", str(repository), base_commit, head_commit
                )

if __name__ == "__main__":
    unittest.main()
