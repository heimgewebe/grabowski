from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_systemkatalog as surface


HEAD = "a" * 40
SCRIPT_SHA256 = "b" * 64
ORIGIN_SHA256 = "c" * 64


class SystemkatalogSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.script = self.root / surface.QUERY_SCRIPT
        self.script.parent.mkdir(parents=True)
        self.script.write_text("print('test')\n", encoding="utf-8")
        self.repository_identity = {
            "repository": surface.CATALOG_REPOSITORY,
            "head": HEAD,
            "origin_sha256": ORIGIN_SHA256,
            "clean": True,
        }
        self.script_identity = {
            "path": str(self.script),
            "sha256": SCRIPT_SHA256,
            "bytes": self.script.stat().st_size,
        }

    def payload(
        self,
        *,
        operation: str = "system",
        value: str | None = "grabowski",
        status: str = "ok",
        commit: str = HEAD,
    ) -> dict[str, object]:
        kind = (
            "system_catalog_query_result"
            if status == "ok"
            else "system_catalog_query_error"
        )
        payload: dict[str, object] = {
            "schemaVersion": 2,
            "kind": kind,
            "status": status,
            "command": operation,
            "query": {"value": value},
            "catalogRepository": surface.CATALOG_REPOSITORY,
            "catalogCommit": commit,
            "doesNotEstablish": [
                "runtime_health",
                "task_status",
                "merge_readiness",
            ],
        }
        if status == "ok":
            payload.update(
                {
                    "catalogIdentity": {
                        "repository": surface.CATALOG_REPOSITORY,
                        "commit": commit,
                        "artifactManifest": {
                            "path": "rendered/ecosystem-map-artifact-manifest.json",
                            "sha256": "d" * 64,
                            "bytes": 100,
                        },
                    },
                    "sourcePaths": ["registry/ecosystem/nodes.json"],
                    "sourceEvidence": [
                        {
                            "path": "registry/ecosystem/nodes.json",
                            "sha256": "e" * 64,
                            "bytes": 200,
                        }
                    ],
                    "result": {"system": {"id": "repo:grabowski"}},
                }
            )
        else:
            payload["error"] = {
                "code": "query_not_unique",
                "message": "not found",
                "path": None,
                "details": {"matchCount": 0},
            }
        return payload

    @staticmethod
    def completed(payload: object, *, returncode: int = 0) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=["systemkatalog_query.py"],
            returncode=returncode,
            stdout=json.dumps(payload).encode("utf-8"),
            stderr=b"",
        )

    def query_patches(self, completed: subprocess.CompletedProcess[bytes]):
        return (
            mock.patch.object(surface, "_configured_root", return_value=self.root),
            mock.patch.object(
                surface,
                "_repository_identity",
                return_value=self.repository_identity,
            ),
            mock.patch.object(
                surface,
                "_regular_file_identity",
                return_value=self.script_identity,
            ),
            mock.patch.object(surface, "_run", return_value=completed),
        )

    def test_success_preserves_revision_bound_systemkatalog_envelope(self) -> None:
        payload = self.payload()
        patches = self.query_patches(self.completed(payload))
        with patches[0], patches[1], patches[2], patches[3] as run:
            result = surface.query_systemkatalog("system", " grabowski ")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["systemkatalog"], payload)
        self.assertEqual(result["adapter_identity"]["repository"]["head"], HEAD)
        self.assertEqual(
            result["adapter_identity"]["query_script"]["sha256"],
            SCRIPT_SHA256,
        )
        argv = run.call_args.args[0]
        self.assertEqual(
            argv,
            [
                os.sys.executable,
                str(self.script),
                "--root",
                str(self.root),
                "system",
                "grabowski",
            ],
        )
        self.assertIn("execution_permission", result["does_not_establish"])
        self.assertIn("catalog_semantic_completeness", result["does_not_establish"])

    def test_manifest_operation_has_no_value_argument(self) -> None:
        payload = self.payload(operation="manifest", value=None)
        patches = self.query_patches(self.completed(payload))
        with patches[0], patches[1], patches[2], patches[3] as run:
            result = surface.query_systemkatalog("manifest")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(run.call_args.args[0][-1], "manifest")
        self.assertNotIn(None, run.call_args.args[0])

    def test_degraded_systemkatalog_result_is_preserved(self) -> None:
        payload = self.payload(status="degraded")
        patches = self.query_patches(self.completed(payload, returncode=3))
        with patches[0], patches[1], patches[2], patches[3]:
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(result["status"], "degraded")
        self.assertIsNone(result.get("adapter_error"))
        self.assertEqual(
            result["systemkatalog"]["error"]["code"],
            "query_not_unique",
        )

    def test_value_is_required_for_targeted_operations(self) -> None:
        with mock.patch.object(surface, "_run") as run:
            result = surface.query_systemkatalog("relations")
        self.assertEqual(result["adapter_error"]["code"], "value_required")
        run.assert_not_called()

    def test_value_is_forbidden_for_manifest(self) -> None:
        result = surface.query_systemkatalog("manifest", "unexpected")
        self.assertEqual(result["adapter_error"]["code"], "value_forbidden")

    def test_unknown_operation_fails_closed(self) -> None:
        result = surface.query_systemkatalog("unknown", "value")
        self.assertEqual(result["adapter_error"]["code"], "operation_unsupported")

    def test_control_character_in_value_is_rejected(self) -> None:
        result = surface.query_systemkatalog("system", "grabowski\nother")
        self.assertEqual(result["adapter_error"]["code"], "value_invalid")

    def test_missing_root_returns_typed_adapter_error(self) -> None:
        missing = self.root / "missing"
        with mock.patch.dict(
            os.environ,
            {surface.ROOT_ENVIRONMENT: str(missing)},
            clear=False,
        ):
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(result["adapter_error"]["code"], "root_unavailable")

    def test_missing_query_script_returns_typed_adapter_error(self) -> None:
        self.script.unlink()
        with mock.patch.object(surface, "_configured_root", return_value=self.root), mock.patch.object(
            surface,
            "_repository_identity",
            return_value=self.repository_identity,
        ):
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(result["adapter_error"]["code"], "query_script_missing")

    def test_dirty_repository_failure_is_preserved(self) -> None:
        failure = surface.SystemkatalogAdapterError(
            "repository_dirty",
            "dirty",
        )
        with mock.patch.object(surface, "_configured_root", return_value=self.root), mock.patch.object(
            surface,
            "_repository_identity",
            side_effect=failure,
        ):
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(result["adapter_error"]["code"], "repository_dirty")

    def test_timeout_failure_is_preserved(self) -> None:
        failure = surface.SystemkatalogAdapterError(
            "subprocess_timeout",
            "timeout",
            details={"timeout_seconds": 15},
        )
        with mock.patch.object(surface, "_configured_root", return_value=self.root), mock.patch.object(
            surface,
            "_repository_identity",
            return_value=self.repository_identity,
        ), mock.patch.object(
            surface,
            "_regular_file_identity",
            return_value=self.script_identity,
        ), mock.patch.object(surface, "_run", side_effect=failure):
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(result["adapter_error"]["code"], "subprocess_timeout")

    def test_repository_change_during_query_fails_closed(self) -> None:
        payload = self.payload()
        changed = {**self.repository_identity, "head": "f" * 40}
        with mock.patch.object(surface, "_configured_root", return_value=self.root), mock.patch.object(
            surface,
            "_repository_identity",
            side_effect=[self.repository_identity, changed],
        ), mock.patch.object(
            surface,
            "_regular_file_identity",
            return_value=self.script_identity,
        ), mock.patch.object(
            surface,
            "_run",
            return_value=self.completed(payload),
        ):
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(result["adapter_error"]["code"], "repository_changed")

    def test_query_script_change_during_query_fails_closed(self) -> None:
        payload = self.payload()
        changed = {**self.script_identity, "sha256": "f" * 64}
        with mock.patch.object(surface, "_configured_root", return_value=self.root), mock.patch.object(
            surface,
            "_repository_identity",
            return_value=self.repository_identity,
        ), mock.patch.object(
            surface,
            "_regular_file_identity",
            side_effect=[self.script_identity, changed],
        ), mock.patch.object(
            surface,
            "_run",
            return_value=self.completed(payload),
        ):
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(result["adapter_error"]["code"], "query_script_changed")

    def test_noncontract_exit_code_fails_closed(self) -> None:
        patches = self.query_patches(self.completed({}, returncode=1))
        with patches[0], patches[1], patches[2], patches[3]:
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(result["adapter_error"]["code"], "query_failed")

    def test_malformed_json_fails_closed(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"{", stderr=b""
        )
        patches = self.query_patches(completed)
        with patches[0], patches[1], patches[2], patches[3]:
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(result["adapter_error"]["code"], "query_json_invalid")

    def test_wrong_schema_fails_closed(self) -> None:
        payload = self.payload()
        payload["schemaVersion"] = 1
        patches = self.query_patches(self.completed(payload))
        with patches[0], patches[1], patches[2], patches[3]:
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(
            result["adapter_error"]["code"],
            "payload_contract_mismatch",
        )

    def test_operation_mismatch_fails_closed(self) -> None:
        payload = self.payload(operation="repository")
        patches = self.query_patches(self.completed(payload))
        with patches[0], patches[1], patches[2], patches[3]:
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(
            result["adapter_error"]["code"],
            "payload_operation_mismatch",
        )

    def test_commit_mismatch_fails_closed(self) -> None:
        payload = self.payload(commit="f" * 40)
        patches = self.query_patches(self.completed(payload))
        with patches[0], patches[1], patches[2], patches[3]:
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(
            result["adapter_error"]["code"],
            "payload_commit_mismatch",
        )

    def test_exit_status_mismatch_fails_closed(self) -> None:
        payload = self.payload(status="degraded")
        patches = self.query_patches(self.completed(payload, returncode=0))
        with patches[0], patches[1], patches[2], patches[3]:
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(
            result["adapter_error"]["code"],
            "payload_exit_mismatch",
        )

    def test_missing_source_evidence_fails_closed(self) -> None:
        payload = self.payload()
        payload.pop("sourceEvidence")
        patches = self.query_patches(self.completed(payload))
        with patches[0], patches[1], patches[2], patches[3]:
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(
            result["adapter_error"]["code"],
            "payload_evidence_invalid",
        )

    def test_invalid_manifest_identity_fails_closed(self) -> None:
        payload = self.payload()
        payload["catalogIdentity"]["artifactManifest"]["sha256"] = "z" * 64
        patches = self.query_patches(self.completed(payload))
        with patches[0], patches[1], patches[2], patches[3]:
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(
            result["adapter_error"]["code"],
            "payload_identity_invalid",
        )

    def test_invalid_degraded_error_fails_closed(self) -> None:
        payload = self.payload(status="degraded")
        payload["error"] = {"code": "", "message": ""}
        patches = self.query_patches(self.completed(payload, returncode=3))
        with patches[0], patches[1], patches[2], patches[3]:
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(
            result["adapter_error"]["code"],
            "payload_error_invalid",
        )

    def test_invalid_nonclaims_fail_closed(self) -> None:
        payload = self.payload()
        payload["doesNotEstablish"] = "runtime_health"
        patches = self.query_patches(self.completed(payload))
        with patches[0], patches[1], patches[2], patches[3]:
            result = surface.query_systemkatalog("system", "grabowski")
        self.assertEqual(
            result["adapter_error"]["code"],
            "payload_nonclaims_invalid",
        )

    def test_run_enforces_stdout_bound_without_memory_capture(self) -> None:
        command = [
            os.sys.executable,
            "-c",
            (
                "import os; "
                f"os.write(1, b'x' * {surface.MAX_STDOUT_BYTES + 1})"
            ),
        ]
        with self.assertRaisesRegex(
            surface.SystemkatalogAdapterError,
            "output exceeds",
        ) as raised:
            surface._run(command, cwd=self.root, timeout_seconds=2)
        self.assertEqual(raised.exception.code, "stdout_too_large")

    def test_run_timeout_terminates_the_process_group(self) -> None:
        command = [os.sys.executable, "-c", "import time; time.sleep(30)"]
        with self.assertRaisesRegex(
            surface.SystemkatalogAdapterError,
            "timed out",
        ) as raised:
            surface._run(command, cwd=self.root, timeout_seconds=0.05)
        self.assertEqual(raised.exception.code, "subprocess_timeout")

    def test_run_rejects_invalid_timeout_before_process_start(self) -> None:
        with mock.patch.object(subprocess, "Popen") as popen:
            with self.assertRaises(surface.SystemkatalogAdapterError) as raised:
                surface._run(["true"], cwd=self.root, timeout_seconds=0)
        self.assertEqual(raised.exception.code, "timeout_invalid")
        popen.assert_not_called()

    def test_repository_identity_rejects_dirty_state(self) -> None:
        with mock.patch.object(
            surface,
            "_git_text",
            side_effect=[HEAD, " M registry/ecosystem/nodes.json", next(iter(surface.ALLOWED_ORIGINS))],
        ):
            with self.assertRaises(surface.SystemkatalogAdapterError) as raised:
                surface._repository_identity(self.root)
        self.assertEqual(raised.exception.code, "repository_dirty")

    def test_repository_identity_rejects_wrong_origin(self) -> None:
        with mock.patch.object(
            surface,
            "_git_text",
            side_effect=[HEAD, "", "git@example.invalid:other/catalog.git"],
        ):
            with self.assertRaises(surface.SystemkatalogAdapterError) as raised:
                surface._repository_identity(self.root)
        self.assertEqual(raised.exception.code, "origin_unexpected")


if __name__ == "__main__":
    unittest.main()
