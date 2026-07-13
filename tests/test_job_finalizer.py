from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_job_finalizer as finalizer  # noqa: E402


class JobFinalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "jobs"
        self.root.mkdir(mode=0o700)
        self.job_id = "0123456789ab"
        self.unit = f"grabowski-job-{self.job_id}"
        self.directory = self.root / self.unit
        self.directory.mkdir(mode=0o700)
        self.metadata = {
            "schema_version": 1,
            "job_id": self.job_id,
            "unit": self.unit,
            "owner": "uid:1000",
            "scope": {"cwd": "/tmp", "runtime_seconds": 60},
            "argv_sha256": "a" * 64,
            "notify_on_done": {
                "requested": True,
                "channels": ["operator_outbox"],
                "note": "done",
            },
        }
        self._write_metadata(self.metadata)
        self.patcher = mock.patch.object(finalizer, "JOBS_ROOT", self.root)
        self.patcher.start()

    def tearDown(self) -> None:
        self.patcher.stop()
        self.temporary.cleanup()

    def _write_metadata(self, value: dict, *, mode: int = 0o600) -> Path:
        path = self.directory / "metadata.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(mode)
        return path

    def _environment(self, result: str = "success", status: str = "0") -> dict[str, str]:
        return {
            "SERVICE_RESULT": result,
            "EXIT_CODE": "exited",
            "EXIT_STATUS": status,
        }

    def _bind_origin(self) -> tuple[dict, dict[str, str]]:
        notify = self.metadata["notify_on_done"]
        origin, digest = finalizer.job_origin.build_origin(
            unit=self.unit,
            owner=self.metadata["owner"],
            argv_sha256=self.metadata["argv_sha256"],
            scope=self.metadata["scope"],
            notify_on_done=notify,
            created_at_unix=100,
            started_at="1970-01-01T00:01:40Z",
            invoker_tool="grabowski_job_start",
        )
        self.metadata.update({
            "schema_version": 2,
            "origin": origin,
            "origin_sha256": digest,
        })
        self._write_metadata(self.metadata)
        environment = self._environment()
        environment.update({
            "GRABOWSKI_JOB_ORIGIN_SHA256": digest,
            "GRABOWSKI_JOB_INVOKER_TOOL": "grabowski_job_start",
        })
        return origin, environment

    def _install_generic_contract(self) -> dict:
        material = {
            "schema_version": 1,
            "kind": finalizer.GENERIC_JOB_FINALIZATION_KIND,
            "unit": self.unit,
            "job_id": self.job_id,
            "argv_sha256": self.metadata["argv_sha256"],
            "receipt_paths": finalizer._job_receipt_paths(self.directory),
        }
        contract = {
            **material,
            "contract_sha256": hashlib.sha256(finalizer._canonical(material)).hexdigest(),
        }
        self.metadata["finalization_contract"] = contract
        self.metadata["expected_receipt"] = {
            "finalization_path": str(self.directory / "finalization.json")
        }
        self._write_metadata(self.metadata)
        return contract

    def test_finalize_creates_private_hash_bound_receipt_and_is_idempotent(self) -> None:
        first = finalizer.finalize(self.directory, self._environment())
        second = finalizer.finalize(self.directory, self._environment())

        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(second["reason"], "already_exists")
        receipt = first["receipt"]
        expected_hash = receipt["receipt_sha256"]
        unhashed = dict(receipt)
        unhashed.pop("receipt_sha256")
        self.assertEqual(
            expected_hash,
            hashlib.sha256(finalizer._canonical(unhashed)).hexdigest(),
        )
        metadata = (self.directory / "notification.json").lstat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(receipt["terminal_status"], "succeeded")
        self.assertEqual(receipt["delivery_state"], "queued")
        self.assertIn("external_push_delivery", receipt["does_not_establish"])
        self.assertEqual(list(self.directory.glob(".notification.json.*.tmp")), [])

    def test_no_receipt_when_notification_not_requested(self) -> None:
        self.metadata["notify_on_done"]["requested"] = False
        self._write_metadata(self.metadata)
        result = finalizer.finalize(self.directory, self._environment())
        self.assertEqual(result, {"created": False, "reason": "notification_not_requested"})
        self.assertFalse((self.directory / "notification.json").exists())

    def test_generic_success_without_notification_writes_finalization(self) -> None:
        self.metadata["notify_on_done"]["requested"] = False
        contract = self._install_generic_contract()
        result = finalizer.finalize(self.directory, self._environment())
        self.assertEqual(result["reason"], "notification_not_requested")
        receipt = result["finalization"]["receipt"]
        self.assertEqual(receipt["final_status"], "succeeded")
        self.assertEqual(receipt["completion_status"], "complete")
        self.assertIsNone(receipt["failure_type"])
        self.assertEqual(receipt["contract_sha256"], contract["contract_sha256"])
        self.assertTrue((self.directory / "finalization.json").is_file())

    def test_generic_failed_command_writes_failed_receipt(self) -> None:
        self.metadata["notify_on_done"]["requested"] = False
        self._install_generic_contract()
        result = finalizer.finalize(
            self.directory, self._environment("exit-code", "7")
        )
        receipt = result["finalization"]["receipt"]
        self.assertEqual(receipt["final_status"], "failed")
        self.assertEqual(receipt["completion_status"], "failed")
        self.assertEqual(receipt["failure_type"], "failed")

    def test_expected_or_unsupported_contract_fails_closed(self) -> None:
        self.metadata["expected_receipt"] = {
            "finalization_path": str(self.directory / "finalization.json")
        }
        self._write_metadata(self.metadata)
        with self.assertRaisesRegex(RuntimeError, "missing or invalid"):
            finalizer.finalize(self.directory, self._environment())
        self.metadata["finalization_contract"] = {"kind": "unsupported"}
        self._write_metadata(self.metadata)
        with self.assertRaisesRegex(RuntimeError, "unsupported"):
            finalizer.finalize(self.directory, self._environment())

    def test_generic_create_only_winner_conflict_is_preserved(self) -> None:
        self.metadata["notify_on_done"]["requested"] = False
        self._install_generic_contract()
        finalizer.finalize(self.directory, self._environment())
        target = self.directory / "finalization.json"
        before = target.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "terminal status conflicts"):
            finalizer.finalize(
                self.directory, self._environment("exit-code", "1")
            )
        self.assertEqual(target.read_bytes(), before)

    def test_runtime_deploy_contract_is_runner_owned_and_not_overwritten(self) -> None:
        expected_head = "b" * 40
        material = {
            "schema_version": 1,
            "kind": finalizer.RUNTIME_DEPLOY_FINALIZATION_KIND,
            "unit": self.unit,
            "job_id": self.job_id,
            "argv_sha256": self.metadata["argv_sha256"],
            "expected_head": expected_head,
            "receipt_paths": finalizer._job_receipt_paths(self.directory),
        }
        self.metadata["finalization_contract"] = {
            **material,
            "contract_sha256": hashlib.sha256(finalizer._canonical(material)).hexdigest(),
        }
        self.metadata["notify_on_done"]["requested"] = False
        self._write_metadata(self.metadata)
        target = self.directory / "finalization.json"
        target.write_text('{"runner":"owned"}\n', encoding="utf-8")
        target.chmod(0o600)
        before = target.read_bytes()
        result = finalizer.finalize(self.directory, self._environment())
        self.assertEqual(
            result["finalization"]["reason"], "runtime_deploy_runner_owned"
        )
        self.assertEqual(target.read_bytes(), before)

    def test_service_result_mapping(self) -> None:
        cases = {
            ("success", "0"): "succeeded",
            ("timeout", "1"): "timed_out",
            ("signal", "9"): "signalled",
            ("core-dump", "11"): "signalled",
            ("exit-code", "2"): "failed",
            ("", ""): "terminated_unclear",
        }
        for index, ((service_result, exit_status), expected) in enumerate(cases.items()):
            with self.subTest(service_result=service_result, exit_status=exit_status):
                directory = self.root / f"grabowski-job-{index:012x}"
                directory.mkdir(mode=0o700)
                value = dict(self.metadata)
                value["job_id"] = f"{index:012x}"
                value["unit"] = directory.name
                path = directory / "metadata.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                path.chmod(0o600)
                result = finalizer.finalize(
                    directory,
                    {
                        "SERVICE_RESULT": service_result,
                        "EXIT_CODE": "exited",
                        "EXIT_STATUS": exit_status,
                    },
                )
                self.assertEqual(result["receipt"]["terminal_status"], expected)

    def test_rejects_path_escape_and_symlink_job_directory(self) -> None:
        outside = Path(self.temporary.name) / self.unit
        outside.mkdir(mode=0o700)
        with self.assertRaisesRegex(RuntimeError, "outside"):
            finalizer.finalize(outside, self._environment())

        target = self.root / "grabowski-job-111111111111"
        target.mkdir(mode=0o700)
        link = self.root / "grabowski-job-222222222222"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "non-symlink"):
            finalizer.finalize(link, self._environment())

    def test_rejects_symlink_hardlink_public_mode_and_oversize_metadata(self) -> None:
        metadata = self.directory / "metadata.json"
        original = metadata.read_bytes()

        metadata.unlink()
        target = self.directory / "target.json"
        target.write_bytes(original)
        target.chmod(0o600)
        metadata.symlink_to(target.name)
        with self.assertRaises((RuntimeError, OSError)):
            finalizer.finalize(self.directory, self._environment())

        metadata.unlink()
        os.link(target, metadata)
        with self.assertRaisesRegex(RuntimeError, "private regular file"):
            finalizer.finalize(self.directory, self._environment())

        metadata.unlink()
        target.unlink()
        self._write_metadata(self.metadata, mode=0o644)
        with self.assertRaisesRegex(RuntimeError, "private regular file"):
            finalizer.finalize(self.directory, self._environment())

        metadata.write_bytes(b"{" + b" " * finalizer.MAX_METADATA_BYTES + b"}")
        metadata.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "private regular file|too large"):
            finalizer.finalize(self.directory, self._environment())

    def test_rejects_unit_binding_and_invalid_argv_hash(self) -> None:
        self.metadata["unit"] = "grabowski-job-ffffffffffff"
        self._write_metadata(self.metadata)
        with self.assertRaisesRegex(RuntimeError, "unit binding"):
            finalizer.finalize(self.directory, self._environment())

        self.metadata["unit"] = self.unit
        self.metadata["argv_sha256"] = "bad"
        self._write_metadata(self.metadata)
        with self.assertRaisesRegex(RuntimeError, "argv hash"):
            finalizer.finalize(self.directory, self._environment())

    def test_conflicting_existing_receipt_is_preserved(self) -> None:
        target = self.directory / "notification.json"
        target.write_text('{"other":true}\n', encoding="utf-8")
        target.chmod(0o600)
        before = target.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "conflicts"):
            finalizer.finalize(self.directory, self._environment())
        self.assertEqual(target.read_bytes(), before)

    def test_create_only_publish_race_accepts_identical_winner_and_cleans_temp(self) -> None:
        expected = finalizer.finalize(self.directory, self._environment())["receipt"]
        target = self.directory / "notification.json"
        target.unlink()
        real_link = os.link

        def competing_link(
            source,
            destination,
            *,
            src_dir_fd=None,
            dst_dir_fd=None,
            follow_symlinks=True,
        ):
            self.assertIsNotNone(src_dir_fd)
            self.assertIsNotNone(dst_dir_fd)
            target.write_text(
                json.dumps(expected, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            target.chmod(0o600)
            raise FileExistsError(destination)

        with mock.patch.object(finalizer.private_io.os, "link", side_effect=competing_link):
            result = finalizer.finalize(self.directory, self._environment())
        self.assertFalse(result["created"])
        self.assertEqual(result["receipt"], expected)
        self.assertEqual(list(self.directory.glob(".notification.json.*.tmp")), [])
        self.assertEqual(target.lstat().st_nlink, 1)
        self.assertIsNotNone(real_link)

    def test_origin_bound_receipt_is_schema_two_and_launcher_bound(self) -> None:
        origin, environment = self._bind_origin()
        environment["UNRELATED_SECRET"] = "must-not-appear"
        result = finalizer.finalize(self.directory, environment)
        receipt = result["receipt"]
        self.assertEqual(receipt["schema_version"], 2)
        self.assertEqual(receipt["origin_sha256"], self.metadata["origin_sha256"])
        self.assertEqual(receipt["invoker_tool"], origin["invoker_tool"])
        self.assertEqual(receipt["origin_binding"], finalizer.ORIGIN_BINDING)
        self.assertEqual(receipt["trust_boundary"], finalizer.TRUST_BOUNDARY)
        self.assertIn("untrusted_same_uid_job_authenticity", receipt["does_not_establish"])
        self.assertNotIn("must-not-appear", json.dumps(receipt))

    def test_origin_bound_finalizer_rejects_metadata_request_tampering(self) -> None:
        _origin, environment = self._bind_origin()
        self.metadata["notify_on_done"]["note"] = "changed"
        self._write_metadata(self.metadata)
        with self.assertRaisesRegex(RuntimeError, "notification request changed"):
            finalizer.finalize(self.directory, environment)
        self.assertFalse((self.directory / "notification.json").exists())

    def test_origin_rehash_does_not_bypass_launcher_precondition(self) -> None:
        _origin, environment = self._bind_origin()
        modified_origin = dict(self.metadata["origin"])
        modified_origin["notify_on_done"] = {
            **modified_origin["notify_on_done"],
            "note": "attacker-rewritten",
        }
        modified_hash = hashlib.sha256(
            finalizer.job_origin.canonical_json_bytes(modified_origin)
        ).hexdigest()
        self.metadata["origin"] = modified_origin
        self.metadata["origin_sha256"] = modified_hash
        self.metadata["notify_on_done"]["note"] = "attacker-rewritten"
        self._write_metadata(self.metadata)
        with self.assertRaisesRegex(RuntimeError, "launcher precondition"):
            finalizer.finalize(self.directory, environment)
        self.assertFalse((self.directory / "notification.json").exists())

    def test_partial_origin_contract_fails_closed(self) -> None:
        _origin, environment = self._bind_origin()
        environment.pop("GRABOWSKI_JOB_INVOKER_TOOL")
        with self.assertRaisesRegex(RuntimeError, "origin contract is incomplete"):
            finalizer.finalize(self.directory, environment)

    def test_complete_same_uid_control_is_explicitly_not_authenticated(self) -> None:
        _origin, environment = self._bind_origin()
        forged_origin = dict(self.metadata["origin"])
        forged_origin["notify_on_done"] = {
            **forged_origin["notify_on_done"],
            "note": "same-uid-forged",
        }
        forged_hash = hashlib.sha256(
            finalizer.job_origin.canonical_json_bytes(forged_origin)
        ).hexdigest()
        self.metadata["origin"] = forged_origin
        self.metadata["origin_sha256"] = forged_hash
        self.metadata["notify_on_done"]["note"] = "same-uid-forged"
        self._write_metadata(self.metadata)
        environment["GRABOWSKI_JOB_ORIGIN_SHA256"] = forged_hash

        receipt = finalizer.finalize(self.directory, environment)["receipt"]
        self.assertEqual(receipt["note"], "same-uid-forged")
        self.assertEqual(receipt["trust_boundary"], "same_uid_authorized_job")
        self.assertIn(
            "untrusted_same_uid_job_authenticity",
            receipt["does_not_establish"],
        )

    def test_origin_contract_rejects_noncanonical_identity_fields(self) -> None:
        values = dict(
            unit=self.unit,
            owner="uid:1000",
            argv_sha256="a" * 64,
            scope={"cwd": "/tmp"},
            notify_on_done=self.metadata["notify_on_done"],
            created_at_unix=100,
            started_at="1970-01-01T00:01:40Z",
            invoker_tool="grabowski_job_start",
        )
        for key, invalid, message in (
            ("unit", "grabowski-job-not-hex", "origin unit"),
            ("owner", "uid:root", "origin owner"),
            ("started_at", "1970-01-01Z", "origin start time"),
        ):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, message):
                finalizer.job_origin.build_origin(**{**values, key: invalid})

    def test_filtered_environment_includes_directory_and_excludes_unrelated_values(self) -> None:
        source = {
            "GRABOWSKI_JOB_DIRECTORY": str(self.directory),
            "SERVICE_RESULT": "success",
            "UNRELATED_SECRET": "hidden",
        }
        filtered = finalizer._filtered_environment(source)
        self.assertEqual(filtered["GRABOWSKI_JOB_DIRECTORY"], str(self.directory))
        self.assertEqual(filtered["SERVICE_RESULT"], "success")
        self.assertNotIn("UNRELATED_SECRET", filtered)

    def test_process_hardening_is_finalizer_local(self) -> None:
        with mock.patch.object(finalizer.os, "umask") as umask, mock.patch.object(
            finalizer.resource,
            "getrlimit",
            return_value=(1_048_576, 1_048_576),
        ), mock.patch.object(finalizer.resource, "setrlimit") as setrlimit:
            finalizer._harden_process()
        umask.assert_called_once_with(0o077)
        self.assertEqual(
            setrlimit.call_args_list,
            [
                mock.call(finalizer.resource.RLIMIT_CORE, (0, 0)),
                mock.call(
                    finalizer.resource.RLIMIT_NOFILE,
                    (finalizer.FINALIZER_NOFILE_SOFT_LIMIT, 1_048_576),
                ),
            ],
        )

    def test_main_parses_filtered_environment_before_hardening(self) -> None:
        filtered = {key: "" for key in finalizer.FINALIZER_ENV_KEYS}
        with mock.patch.object(
            finalizer,
            "_filtered_environment",
            return_value=filtered,
        ), mock.patch.object(finalizer, "_harden_process") as harden, mock.patch.object(
            finalizer.sys,
            "stderr",
        ):
            self.assertEqual(finalizer.main(), 2)
        harden.assert_not_called()

    def test_main_fails_closed_when_process_hardening_fails(self) -> None:
        filtered = {key: "" for key in finalizer.FINALIZER_ENV_KEYS}
        filtered["GRABOWSKI_JOB_DIRECTORY"] = str(self.directory)
        with mock.patch.object(
            finalizer,
            "_filtered_environment",
            return_value=filtered,
        ), mock.patch.object(
            finalizer,
            "_harden_process",
            side_effect=OSError("limit denied"),
        ), mock.patch.object(finalizer.sys, "stderr") as stderr:
            self.assertEqual(finalizer.main(), 1)
        self.assertIn("process_hardening", "".join(call.args[0] for call in stderr.write.call_args_list))

    def test_detects_metadata_identity_drift(self) -> None:
        path = self.directory / "metadata.json"
        other = self.directory / "other.json"
        other.write_text("{}", encoding="utf-8")
        other.chmod(0o600)
        real = path.lstat()
        drifted = other.lstat()
        with mock.patch.object(Path, "lstat", side_effect=[real, drifted]):
            with self.assertRaisesRegex(RuntimeError, "changed while reading"):
                finalizer._read_private_json(path, max_bytes=finalizer.MAX_METADATA_BYTES)


if __name__ == "__main__":
    unittest.main()
