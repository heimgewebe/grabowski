from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_reposkop_context as context  # noqa: E402


class ReposkopContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.executable = self.root / "reposkop"
        self.executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.executable.chmod(0o700)
        self.receipts = self.root / "receipts"
        self.run_calls: list[tuple[list[str], Path]] = []
        self.audit_records: list[dict[str, object]] = []
        self.audit_bindings: dict[str, dict[str, str]] = {}
        self.audit_lock = threading.Lock()
        self.write_scope_calls: list[tuple[Path, bool]] = []

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def report(
        self,
        *,
        effect_authorized: bool = False,
        schema_version: object = 1,
        observation_kind: str = "reposkop_checkout_observation",
        observation_schema_version: int = 1,
        projection_kind: str = "reposkop_coherence_projection",
        projection_schema_version: int = 1,
    ) -> dict[str, object]:
        target = str(self.repo.resolve())
        purpose = "grabowski-repo-state-context"
        return {
            "kind": "reposkop_coherence_report",
            "schema_version": schema_version,
            "generated_at": "2026-07-29T08:00:00Z",
            "effect_authorized": effect_authorized,
            "report_sha256": "a" * 64,
            "observation": {
                "kind": observation_kind,
                "schema_version": observation_schema_version,
                "observation_sha256": "b" * 64,
                "identities": {"path": target, "purpose": purpose},
            },
            "projection": {
                "kind": projection_kind,
                "schema_version": projection_schema_version,
                "projection_sha256": "c" * 64,
                "effect_authorized": False,
            },
        }

    def patches(
        self,
        report: dict[str, object],
        *,
        audit_error: BaseException | None = None,
    ):
        def fake_run(
            argv, *, cwd, timeout_seconds, stdout_limit, stderr_limit
        ):
            with self.audit_lock:
                self.run_calls.append((list(argv), Path(cwd)))
            self.assertEqual(timeout_seconds, 20)
            self.assertEqual(stdout_limit, context.MAX_REPORT_BYTES)
            self.assertEqual(stderr_limit, context.MAX_STDERR_BYTES)
            stdout = json.dumps(report)
            return {
                "returncode": 0,
                "timed_out": False,
                "duration_seconds": 0.001,
                "stdout_data": stdout.encode("utf-8"),
                "stderr": "",
                "stdout_bytes": len(stdout.encode("utf-8")),
                "stderr_bytes": 0,
                "stdout_limit_exceeded": False,
                "stderr_limit_exceeded": False,
            }

        def fake_write_target(value, *, allow_missing_parents=False):
            path = Path(value)
            self.write_scope_calls.append((path, allow_missing_parents))
            return path, path.exists()

        def fake_find(binding):
            with self.audit_lock:
                stored = self.audit_bindings.get(binding["usage_key_sha256"])
                return dict(stored) if stored is not None else None

        def fake_append(binding, *, publication_contract):
            record = context._audit_record(
                binding,
                recorded_at="2026-07-29T10:00:00+00:00",
                publication_contract=publication_contract,
            )
            with self.audit_lock:
                self.audit_records.append(record)
                if audit_error is not None:
                    raise audit_error
                result = {
                    "audit_ref": "audit-record-sha256:" + "d" * 64,
                    "recorded_at": record["timestamp"],
                    "publication_contract": publication_contract,
                }
                self.audit_bindings[binding["usage_key_sha256"]] = result
                return dict(result)

        return (
            patch.object(context, "REPOSKOP_BIN", self.executable),
            patch.object(context, "RECEIPT_ROOT", self.receipts),
            patch.object(context, "_run_bounded_process", side_effect=fake_run),
            patch.object(context.base, "_require_capability"),
            patch.object(
                context.base,
                "_resolve_existing",
                side_effect=lambda value, _kind: Path(value).resolve(strict=True),
            ),
            patch.object(context.operator, "_require_operator_mutation"),
            patch.object(
                context.base, "_resolve_write_target", side_effect=fake_write_target
            ),
            patch.object(
                context.base,
                "_roots",
                side_effect=lambda kind: [self.root] if kind == "write" else [],
            ),
            patch.object(context.base, "_require_mutations_enabled"),
            patch.object(context, "_find_audit_binding", side_effect=fake_find),
            patch.object(context, "_append_audit_binding", side_effect=fake_append),
        )

    @staticmethod
    @contextmanager
    def patch_context(patches):
        with ExitStack() as stack:
            for patcher in patches:
                stack.enter_context(patcher)
            yield

    def test_accepts_shared_read_execute_without_shared_write(self) -> None:
        self.executable.chmod(0o755)
        executable, digest = context._validate_executable(self.executable)
        self.assertEqual(executable, self.executable)
        self.assertEqual(digest, context._sha256_file(self.executable))

    def test_rejects_group_or_world_writable_executable_before_execution(self) -> None:
        patches = self.patches(self.report())
        with self.patch_context(patches):
            for mode in (0o720, 0o702, 0o777):
                with self.subTest(mode=oct(mode)):
                    self.executable.chmod(mode)
                    with self.assertRaisesRegex(ValueError, "group/world-write"):
                        context.grabowski_reposkop_context(str(self.repo))

        self.assertEqual(self.run_calls, [])
        self.assertFalse(self.receipts.exists())
        self.assertEqual(self.audit_records, [])

    def test_accepts_executable_under_trusted_sticky_writable_ancestor(self) -> None:
        sticky = self.root / "sticky"
        sticky.mkdir()
        sticky.chmod(0o1777)
        executable = sticky / "reposkop"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)

        selected, digest = context._validate_executable(executable)

        self.assertEqual(selected, executable)
        self.assertEqual(digest, context._sha256_file(executable))

    def test_rejects_executable_under_nonsticky_writable_ancestor(self) -> None:
        unsafe = self.root / "unsafe"
        unsafe.mkdir()
        unsafe.chmod(0o777)
        executable = unsafe / "reposkop"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)

        with self.assertRaisesRegex(
            context.ReposkopContextError, "executable ancestor failed"
        ):
            context._validate_executable(executable)

    def test_rejects_executable_beneath_symlink_ancestor(self) -> None:
        real = self.root / "real-bin"
        real.mkdir()
        linked = self.root / "linked-bin"
        linked.symlink_to(real, target_is_directory=True)
        executable = real / "reposkop"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)

        with self.assertRaisesRegex(
            context.ReposkopContextError, "executable ancestor failed"
        ):
            context._validate_executable(linked / "reposkop")

    def test_records_one_receipt_and_replays_unchanged_semantic_state(self) -> None:
        patches = self.patches(self.report())
        with self.patch_context(patches):
            first = context.grabowski_reposkop_context(str(self.repo))
            second = context.grabowski_reposkop_context(str(self.repo))

        self.assertFalse(first["usage_receipt"]["replayed"])
        self.assertFalse(first["usage_receipt"]["recovered_publication"])
        self.assertFalse(first["usage_receipt"]["recovered_audit_binding"])
        self.assertEqual(
            first["usage_receipt"]["audit_contract"],
            context.AUDIT_PUBLICATION_CONTRACT,
        )
        self.assertEqual(
            first["usage_receipt"]["audit_ref"],
            "audit-record-sha256:" + "d" * 64,
        )
        self.assertTrue(second["usage_receipt"]["replayed"])
        self.assertEqual(
            second["usage_receipt"]["audit_contract"],
            context.AUDIT_PUBLICATION_CONTRACT,
        )
        self.assertEqual(
            second["usage_receipt"]["audit_ref"],
            first["usage_receipt"]["audit_ref"],
        )
        self.assertEqual(len(self.audit_records), 1)
        self.assertEqual(self.audit_records[0]["operation"], context.AUDIT_OPERATION)
        self.assertEqual(
            self.audit_records[0]["after_sha256"],
            first["usage_receipt"]["sha256"],
        )
        self.assertEqual(
            first["usage_receipt"]["usage_key_sha256"],
            second["usage_receipt"]["usage_key_sha256"],
        )
        self.assertEqual(len(list(self.receipts.glob("*.json"))), 1)
        self.assertEqual(list(self.receipts.glob("*.pending")), [])
        receipt_path = Path(first["usage_receipt"]["path"])
        self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(receipt_path.stat().st_nlink, 1)
        self.assertEqual(self.receipts.stat().st_mode & 0o777, 0o700)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt["kind"], context.RECEIPT_KIND)
        self.assertFalse(receipt["effect_authorized"])
        self.assertNotIn("recorded_at", receipt)
        self.assertNotIn("report_sha256", receipt)
        self.assertEqual(first["report"]["effect_authorized"], False)
        self.assertEqual(len(self.run_calls), 2)
        self.assertTrue(
            {
                self.receipts,
                Path(first["usage_receipt"]["path"]),
                self.receipts / f".{first['usage_receipt']['usage_key_sha256']}.pending",
                self.receipts / f".{first['usage_receipt']['usage_key_sha256']}.lock",
            }.issubset({path for path, _allow_missing in self.write_scope_calls})
        )
        self.assertTrue(
            {
                self.receipts,
                Path(first["usage_receipt"]["path"]),
                self.receipts / f".{first['usage_receipt']['usage_key_sha256']}.pending",
                self.receipts / f".{first['usage_receipt']['usage_key_sha256']}.lock",
            }.issubset(
                {
                    path
                    for path, allow_missing in self.write_scope_calls
                    if allow_missing
                }
            )
        )
        self.assertEqual(
            self.run_calls[0][0],
            [
                str(self.executable),
                "report",
                str(self.repo.resolve()),
                "--purpose",
                "grabowski-repo-state-context",
                "--json",
            ],
        )

    def test_write_root_policy_blocks_before_receipt_root_creation(self) -> None:
        patches = self.patches(self.report())
        with (
            self.patch_context(patches),
            patch.object(
                context.base,
                "_resolve_write_target",
                side_effect=PermissionError("outside configured write roots"),
            ),
        ):
            with self.assertRaisesRegex(
                PermissionError, "outside configured write roots"
            ):
                context.grabowski_reposkop_context(str(self.repo))
        self.assertFalse(self.receipts.exists())
        self.assertEqual(self.audit_records, [])

    def test_derived_write_policy_blocks_before_receipt_root_creation(self) -> None:
        patches = self.patches(self.report())

        def reject_pending(value, *, allow_missing_parents=False):
            path = Path(value)
            if allow_missing_parents and path.name.endswith(".pending"):
                raise PermissionError("derived target outside configured write roots")
            return path, path.exists()

        with (
            self.patch_context(patches),
            patch.object(
                context.base,
                "_resolve_write_target",
                side_effect=reject_pending,
            ),
        ):
            with self.assertRaisesRegex(
                PermissionError, "derived target outside configured write roots"
            ):
                context.grabowski_reposkop_context(str(self.repo))
        self.assertFalse(self.receipts.exists())
        self.assertEqual(self.audit_records, [])

    def test_audit_failure_prevents_any_receipt_publication(self) -> None:
        patches = self.patches(self.report(), audit_error=RuntimeError("audit failed"))
        with self.patch_context(patches):
            with self.assertRaisesRegex(RuntimeError, "audit failed"):
                context.grabowski_reposkop_context(str(self.repo))
        self.assertEqual(list(self.receipts.glob("*.json")), [])
        self.assertEqual(list(self.receipts.glob("*.pending")), [])
        self.assertEqual(len(self.audit_records), 1)

    def test_audit_before_create_recovers_after_interrupted_publication(self) -> None:
        patches = self.patches(self.report())
        real_publish = context._publish_receipt
        with self.patch_context(patches):
            with patch.object(
                context,
                "_publish_receipt",
                side_effect=RuntimeError("publication interrupted"),
            ):
                with self.assertRaisesRegex(RuntimeError, "publication interrupted"):
                    context.grabowski_reposkop_context(str(self.repo))
            self.assertEqual(list(self.receipts.glob("*.json")), [])
            recovered = context.grabowski_reposkop_context(str(self.repo))

        self.assertEqual(context._publish_receipt, real_publish)
        self.assertFalse(recovered["usage_receipt"]["replayed"])
        self.assertTrue(recovered["usage_receipt"]["recovered_publication"])
        self.assertEqual(len(self.audit_records), 1)
        self.assertTrue(Path(recovered["usage_receipt"]["path"]).is_file())

    def test_existing_exact_receipt_recovers_missing_audit_binding(self) -> None:
        patches = self.patches(self.report())
        with self.patch_context(patches):
            first = context.grabowski_reposkop_context(str(self.repo))
            self.audit_bindings.clear()
            recovered = context.grabowski_reposkop_context(str(self.repo))
        self.assertTrue(Path(first["usage_receipt"]["path"]).is_file())
        self.assertTrue(recovered["usage_receipt"]["replayed"])
        self.assertTrue(recovered["usage_receipt"]["recovered_audit_binding"])
        self.assertEqual(
            recovered["usage_receipt"]["audit_contract"],
            context.AUDIT_RECOVERY_CONTRACT,
        )
        self.assertEqual(
            recovered["usage_receipt"]["sha256"],
            first["usage_receipt"]["sha256"],
        )
        self.assertEqual(len(self.audit_records), 2)
        self.assertEqual(
            self.audit_records[1]["publication_contract"],
            context.AUDIT_RECOVERY_CONTRACT,
        )
        self.assertEqual(
            self.audit_records[1]["recovery"],
            {
                "kind": "existing-exact-receipt-audit-rebinding",
                "receipt_observed_before_audit": True,
            },
        )

    def test_concurrent_identical_calls_serialize_to_one_receipt(self) -> None:
        patches = self.patches(self.report())
        with self.patch_context(patches):
            with ThreadPoolExecutor(max_workers=8) as executor:
                results = list(
                    executor.map(
                        lambda _index: context.grabowski_reposkop_context(
                            str(self.repo)
                        ),
                        range(8),
                    )
                )

        self.assertEqual(len(self.audit_records), 1)
        self.assertEqual(len(list(self.receipts.glob("*.json"))), 1)
        self.assertEqual(list(self.receipts.glob("*.pending")), [])
        self.assertEqual(sum(not item["usage_receipt"]["replayed"] for item in results), 1)
        self.assertEqual(sum(item["usage_receipt"]["replayed"] for item in results), 7)
        self.assertEqual(
            len({item["usage_receipt"]["sha256"] for item in results}),
            1,
        )

    def test_publication_uses_bound_root_descriptor_after_path_replacement(self) -> None:
        patches = self.patches(self.report())
        moved_root = self.root / "receipts-moved"
        attacker_root = self.root / "attacker-receipts"
        real_publish_receipt = context._publish_receipt

        def replace_root_then_publish(binding, *, root_descriptor):
            self.receipts.rename(moved_root)
            attacker_root.mkdir(mode=0o700)
            self.receipts.symlink_to(attacker_root, target_is_directory=True)
            return real_publish_receipt(binding, root_descriptor=root_descriptor)

        with (
            self.patch_context(patches),
            patch.object(
                context,
                "_publish_receipt",
                side_effect=replace_root_then_publish,
            ),
        ):
            with self.assertRaisesRegex(
                ValueError,
                "receipt root|write-root|symlink|disappeared|identity|could not be opened safely",
            ):
                context.grabowski_reposkop_context(str(self.repo))

        # Publication must fail closed without writing into the moved or attacker tree.
        self.assertEqual(list(attacker_root.iterdir()), [])
        self.assertEqual(list(moved_root.glob("*.json")), [])
        self.assertEqual(list(moved_root.glob("*.pending")), [])

    def test_publication_rejects_rename_outside_write_roots_before_mutation(self) -> None:
        patches = self.patches(self.report())
        outside = self.root / "outside-of-write-roots"
        outside.mkdir(mode=0o700)
        moved_root = outside / "receipts-moved"
        real_publish_receipt = context._publish_receipt

        def rename_outside_then_publish(binding, *, root_descriptor):
            self.receipts.rename(moved_root)
            return real_publish_receipt(binding, root_descriptor=root_descriptor)

        with (
            self.patch_context(patches),
            patch.object(
                context,
                "_publish_receipt",
                side_effect=rename_outside_then_publish,
            ),
        ):
            with self.assertRaises(ValueError):
                context.grabowski_reposkop_context(str(self.repo))

        self.assertEqual(list(moved_root.glob("*.json")), [])
        self.assertEqual(list(moved_root.glob("*.pending")), [])

    def test_recovers_linked_pending_after_interruption(self) -> None:
        patches = self.patches(self.report())
        with self.patch_context(patches):
            report, executable = context._run_reposkop(
                self.repo.resolve(), "grabowski-repo-state-context"
            )
            binding = context._usage_binding(
                report,
                target=self.repo.resolve(),
                purpose="grabowski-repo-state-context",
                executable=executable,
            )
            context._ensure_receipt_root()
            self.audit_bindings[binding["usage_key_sha256"]] = {
                "audit_ref": "audit-record-sha256:" + "d" * 64,
                "recorded_at": "2026-07-29T10:00:00+00:00",
                "publication_contract": context.AUDIT_PUBLICATION_CONTRACT,
            }
            with context._receipt_root_descriptor() as root_descriptor:
                context._create_pending(
                    binding,
                    root_descriptor=root_descriptor,
                )
            os.link(binding["pending_path"], binding["receipt_path"])
            self.assertEqual(binding["receipt_path"].stat().st_nlink, 2)
            result = context.grabowski_reposkop_context(str(self.repo))

        self.assertTrue(result["usage_receipt"]["replayed"])
        self.assertFalse(binding["pending_path"].exists())
        self.assertEqual(binding["receipt_path"].stat().st_nlink, 1)

    def test_reuses_complete_pending_only_after_inode_fsync(self) -> None:
        patches = self.patches(self.report())
        with self.patch_context(patches):
            report, executable = context._run_reposkop(
                self.repo.resolve(), "grabowski-repo-state-context"
            )
            binding = context._usage_binding(
                report,
                target=self.repo.resolve(),
                purpose="grabowski-repo-state-context",
                executable=executable,
            )
            context._ensure_receipt_root()
            self.audit_bindings[binding["usage_key_sha256"]] = {
                "audit_ref": "audit-record-sha256:" + "d" * 64,
                "recorded_at": "2026-07-29T10:00:00+00:00",
                "publication_contract": context.AUDIT_PUBLICATION_CONTRACT,
            }
            binding["pending_path"].write_bytes(binding["data"])
            binding["pending_path"].chmod(0o600)
            pending_metadata = binding["pending_path"].stat()
            pending_identity = (pending_metadata.st_dev, pending_metadata.st_ino)
            synced_identities: list[tuple[int, int]] = []
            real_fsync = context.os.fsync

            def record_fsync(descriptor: int) -> None:
                metadata = context.os.fstat(descriptor)
                synced_identities.append((metadata.st_dev, metadata.st_ino))
                real_fsync(descriptor)

            with patch.object(context.os, "fsync", side_effect=record_fsync):
                result = context.grabowski_reposkop_context(str(self.repo))

        self.assertIn(pending_identity, synced_identities)
        self.assertTrue(result["usage_receipt"]["recovered_publication"])
        self.assertFalse(binding["pending_path"].exists())
        self.assertEqual(binding["receipt_path"].read_bytes(), binding["data"])

    def test_replay_fsyncs_existing_final_receipt_directory(self) -> None:
        patches = self.patches(self.report())
        with self.patch_context(patches):
            first = context.grabowski_reposkop_context(str(self.repo))
            root_metadata = self.receipts.stat()
            root_identity = (root_metadata.st_dev, root_metadata.st_ino)
            synced_identities: list[tuple[int, int]] = []
            real_fsync = context.os.fsync

            def record_fsync(descriptor: int) -> None:
                metadata = context.os.fstat(descriptor)
                synced_identities.append((metadata.st_dev, metadata.st_ino))
                real_fsync(descriptor)

            with patch.object(context.os, "fsync", side_effect=record_fsync):
                replay = context.grabowski_reposkop_context(str(self.repo))

        self.assertTrue(Path(first["usage_receipt"]["path"]).is_file())
        self.assertTrue(replay["usage_receipt"]["replayed"])
        self.assertIn(root_identity, synced_identities)

    def test_recovers_partial_pending_after_interrupted_write(self) -> None:
        patches = self.patches(self.report())
        with self.patch_context(patches):
            report, executable = context._run_reposkop(
                self.repo.resolve(), "grabowski-repo-state-context"
            )
            binding = context._usage_binding(
                report,
                target=self.repo.resolve(),
                purpose="grabowski-repo-state-context",
                executable=executable,
            )
            context._ensure_receipt_root()
            self.audit_bindings[binding["usage_key_sha256"]] = {
                "audit_ref": "audit-record-sha256:" + "d" * 64,
                "recorded_at": "2026-07-29T10:00:00+00:00",
                "publication_contract": context.AUDIT_PUBLICATION_CONTRACT,
            }
            binding["pending_path"].write_bytes(binding["data"][:17])
            binding["pending_path"].chmod(0o600)
            result = context.grabowski_reposkop_context(str(self.repo))

        self.assertTrue(result["usage_receipt"]["recovered_publication"])
        self.assertFalse(binding["pending_path"].exists())
        self.assertEqual(binding["receipt_path"].read_bytes(), binding["data"])

    def test_partial_pending_with_wrong_bytes_fails_closed(self) -> None:
        patches = self.patches(self.report())
        with self.patch_context(patches):
            report, executable = context._run_reposkop(
                self.repo.resolve(), "grabowski-repo-state-context"
            )
            binding = context._usage_binding(
                report,
                target=self.repo.resolve(),
                purpose="grabowski-repo-state-context",
                executable=executable,
            )
            context._ensure_receipt_root()
            self.audit_bindings[binding["usage_key_sha256"]] = {
                "audit_ref": "audit-record-sha256:" + "d" * 64,
                "recorded_at": "2026-07-29T10:00:00+00:00",
                "publication_contract": context.AUDIT_PUBLICATION_CONTRACT,
            }
            binding["pending_path"].write_bytes(b"x" * 17)
            binding["pending_path"].chmod(0o600)
            with self.assertRaisesRegex(
                ValueError, "not the exact expected byte prefix"
            ):
                context.grabowski_reposkop_context(str(self.repo))

        self.assertTrue(binding["pending_path"].exists())
        self.assertEqual(binding["pending_path"].read_bytes(), b"x" * 17)
        self.assertFalse(binding["receipt_path"].exists())

    def test_partial_pending_with_extra_link_fails_closed(self) -> None:
        patches = self.patches(self.report())
        with self.patch_context(patches):
            report, executable = context._run_reposkop(
                self.repo.resolve(), "grabowski-repo-state-context"
            )
            binding = context._usage_binding(
                report,
                target=self.repo.resolve(),
                purpose="grabowski-repo-state-context",
                executable=executable,
            )
            context._ensure_receipt_root()
            self.audit_bindings[binding["usage_key_sha256"]] = {
                "audit_ref": "audit-record-sha256:" + "d" * 64,
                "recorded_at": "2026-07-29T10:00:00+00:00",
                "publication_contract": context.AUDIT_PUBLICATION_CONTRACT,
            }
            external = self.root / "linked-partial-pending"
            external.write_bytes(binding["data"][:17])
            external.chmod(0o600)
            os.link(external, binding["pending_path"])
            with self.assertRaisesRegex(
                ValueError, "not safely recoverable"
            ):
                context.grabowski_reposkop_context(str(self.repo))

        self.assertTrue(external.exists())
        self.assertTrue(binding["pending_path"].exists())
        self.assertFalse(binding["receipt_path"].exists())

    def test_bounded_process_kills_oversized_stdout_while_draining(self) -> None:
        executable = self.root / "oversized-reposkop"
        executable.write_text(
            "#!/usr/bin/python3\n"
            "import os\n"
            "os.write(1, b'x' * (1024 * 1024))\n",
            encoding="utf-8",
        )
        executable.chmod(0o700)

        result = context._run_bounded_process(
            [str(executable)],
            cwd=self.root,
            timeout_seconds=5,
            stdout_limit=4096,
            stderr_limit=4096,
        )

        self.assertTrue(result["stdout_limit_exceeded"])
        self.assertFalse(result["timed_out"])
        self.assertGreater(result["stdout_bytes"], 4096)
        self.assertLessEqual(len(result["stdout_data"]), 4096)
        self.assertNotEqual(result["returncode"], 0)

    def test_deadline_closes_descendant_held_pipes_after_child_exit(self) -> None:
        executable = self.root / "inherited-pipe-reposkop"
        executable.write_text(
            "#!/usr/bin/python3\n"
            "import subprocess, sys\n"
            "subprocess.Popen(\n"
            "    [sys.executable, '-c', 'import time; time.sleep(30)'],\n"
            "    stdout=sys.stdout,\n"
            "    stderr=sys.stderr,\n"
            ")\n",
            encoding="utf-8",
        )
        executable.chmod(0o700)

        result = context._run_bounded_process(
            [str(executable)],
            cwd=self.root,
            timeout_seconds=1,
            stdout_limit=4096,
            stderr_limit=4096,
        )

        self.assertTrue(result["timed_out"])
        self.assertLess(result["duration_seconds"], 3)
        self.assertFalse(result["stdout_limit_exceeded"])
        self.assertFalse(result["stderr_limit_exceeded"])

    def test_terminates_redirected_descendants_after_child_exit(self) -> None:
        marker = self.root / "descendant-alive"
        executable = self.root / "redirected-descendant-reposkop"
        child = (
            "import os, time; "
            f"open({str(marker)!r}, 'w').write(str(os.getpid())); "
            "time.sleep(30)"
        )
        executable.write_text(
            "#!/usr/bin/python3\n"
            "import subprocess, sys, time\n"
            "subprocess.Popen(\n"
            f"    [sys.executable, '-c', {child!r}],\n"
            "    stdout=subprocess.DEVNULL,\n"
            "    stderr=subprocess.DEVNULL,\n"
            "    stdin=subprocess.DEVNULL,\n"
            ")\n"
            "time.sleep(0.2)\n"
            "sys.stdout.write('{\"ok\":true}\\n')\n"
            "sys.stdout.flush()\n",
            encoding="utf-8",
        )
        executable.chmod(0o700)

        result = context._run_bounded_process(
            [str(executable)],
            cwd=self.root,
            timeout_seconds=5,
            stdout_limit=4096,
            stderr_limit=4096,
        )

        self.assertEqual(result["returncode"], 0)
        self.assertFalse(result["timed_out"])
        self.assertLess(result["duration_seconds"], 3)
        # Allow the SIGKILL to land, then ensure the redirected descendant is gone.
        deadline = time.monotonic() + 2.0
        while marker.exists() and time.monotonic() < deadline:
            try:
                pid = int(marker.read_text(encoding="utf-8").strip())
            except ValueError:
                break
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            if marker.exists():
                try:
                    pid = int(marker.read_text(encoding="utf-8").strip())
                    os.kill(pid, 0)
                    self.fail(f"descendant pid {pid} still alive after bounded process return")
                except (ProcessLookupError, ValueError):
                    pass

    def test_wait_after_closed_pipes_respects_remaining_deadline(self) -> None:
        executable = self.root / "closed-pipe-reposkop"
        executable.write_text(
            "#!/usr/bin/python3\n"
            "import os, time\n"
            "os.close(1)\n"
            "os.close(2)\n"
            "time.sleep(30)\n",
            encoding="utf-8",
        )
        executable.chmod(0o700)

        result = context._run_bounded_process(
            [str(executable)],
            cwd=self.root,
            timeout_seconds=1,
            stdout_limit=4096,
            stderr_limit=4096,
        )

        self.assertTrue(result["timed_out"])
        self.assertLess(result["duration_seconds"], 3)
        self.assertFalse(result["stdout_limit_exceeded"])
        self.assertFalse(result["stderr_limit_exceeded"])

    def test_run_reposkop_rejects_streaming_limit_exceeded(self) -> None:
        result = {
            "returncode": -9,
            "timed_out": False,
            "duration_seconds": 0.001,
            "stdout_data": b"x" * 16,
            "stderr": "",
            "stdout_bytes": context.MAX_REPORT_BYTES + 1,
            "stderr_bytes": 0,
            "stdout_limit_exceeded": True,
            "stderr_limit_exceeded": False,
        }
        with (
            patch.object(context, "REPOSKOP_BIN", self.executable),
            patch.object(context, "_run_bounded_process", return_value=result),
        ):
            with self.assertRaisesRegex(
                context.ReposkopContextError, "streaming stdout byte limit"
            ):
                context._run_reposkop(
                    self.repo.resolve(), "grabowski-repo-state-context"
                )

    def test_run_reposkop_rejects_invalid_utf8_stdout(self) -> None:
        result = {
            "returncode": 0,
            "timed_out": False,
            "duration_seconds": 0.001,
            "stdout_data": b'{"kind":"reposkop_coherence_report","value":"\xff"}',
            "stderr": "",
            "stdout_bytes": 49,
            "stderr_bytes": 0,
            "stdout_limit_exceeded": False,
            "stderr_limit_exceeded": False,
        }
        with (
            patch.object(context, "REPOSKOP_BIN", self.executable),
            patch.object(context, "_run_bounded_process", return_value=result),
        ):
            with self.assertRaisesRegex(
                context.ReposkopContextError, "not valid UTF-8"
            ):
                context._run_reposkop(
                    self.repo.resolve(), "grabowski-repo-state-context"
                )

    def test_rejects_any_effect_authorization_from_reposkop(self) -> None:
        patches = self.patches(self.report(effect_authorized=True))
        with self.patch_context(patches):
            with self.assertRaisesRegex(ValueError, "effect_authorized=false"):
                context.grabowski_reposkop_context(str(self.repo))
        self.assertFalse(self.receipts.exists())

    def test_rejects_unsupported_nested_schema_identifiers(self) -> None:
        cases = (
            (
                self.report(observation_kind="future_observation"),
                "observation kind or schema",
            ),
            (
                self.report(observation_schema_version=2),
                "observation kind or schema",
            ),
            (
                self.report(projection_kind="future_projection"),
                "projection kind or schema",
            ),
            (
                self.report(projection_schema_version=2),
                "projection kind or schema",
            ),
        )
        for report, message in cases:
            with self.subTest(message=message, report=report):
                patches = self.patches(report)
                with self.patch_context(patches):
                    with self.assertRaisesRegex(ValueError, message):
                        context.grabowski_reposkop_context(str(self.repo))
        self.assertFalse(self.receipts.exists())

    def test_rejects_relative_or_symlink_target(self) -> None:
        patches = self.patches(self.report())
        with self.patch_context(patches):
            with self.assertRaisesRegex(ValueError, "absolute path"):
                context.grabowski_reposkop_context("repo")
            link = self.root / "repo-link"
            link.symlink_to(self.repo, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "may not be a symlink"):
                context.grabowski_reposkop_context(str(link))

    def test_modified_receipt_with_preserved_identity_fails_closed(self) -> None:
        patches = self.patches(self.report())
        with self.patch_context(patches):
            first = context.grabowski_reposkop_context(str(self.repo))
            receipt_path = Path(first["usage_receipt"]["path"])
            payload = json.loads(receipt_path.read_text(encoding="utf-8"))
            payload["does_not_establish"][0] = "task_or_queue_trutx"
            receipt_path.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            os.chmod(receipt_path, 0o600)
            with self.assertRaisesRegex(ValueError, "content does not match its binding"):
                context.grabowski_reposkop_context(str(self.repo))

    def test_verified_audit_lookup_requires_exact_record_binding(self) -> None:
        report = self.report()
        executable = {"path": str(self.executable), "sha256": "e" * 64}
        binding = context._usage_binding(
            report,
            target=self.repo.resolve(),
            purpose="grabowski-repo-state-context",
            executable=executable,
        )
        record = context._audit_record(
            binding,
            recorded_at="2026-07-29T10:00:00+00:00",
            publication_contract=context.AUDIT_PUBLICATION_CONTRACT,
        )
        record["record_sha256"] = "f" * 64
        raw = context._canonical_json(record)
        snapshot = SimpleNamespace(segments=(object(),))
        with (
            patch.object(
                context.audit_query,
                "capture_verified_audit_snapshot",
                return_value=snapshot,
            ),
            patch.object(context.audit_query, "_load_snapshot_segment", return_value=raw),
        ):
            match = context._find_audit_binding(binding)
            record["after_sha256"] = "0" * 64
            mismatch_raw = context._canonical_json(record)
            with patch.object(
                context.audit_query,
                "_load_snapshot_segment",
                return_value=mismatch_raw,
            ):
                mismatch = context._find_audit_binding(binding)

        self.assertEqual(match["audit_ref"], "audit-record-sha256:" + "f" * 64)
        self.assertEqual(match["recorded_at"], "2026-07-29T10:00:00+00:00")
        self.assertEqual(
            match["publication_contract"], context.AUDIT_PUBLICATION_CONTRACT
        )
        self.assertIsNone(mismatch)

    def test_recovery_audit_requires_truthful_durable_marker(self) -> None:
        report = self.report()
        binding = context._usage_binding(
            report,
            target=self.repo.resolve(),
            purpose="grabowski-repo-state-context",
            executable={"path": str(self.executable), "sha256": "e" * 64},
        )
        recovery = context._audit_record(
            binding,
            recorded_at="2026-07-29T10:00:00+00:00",
            publication_contract=context.AUDIT_RECOVERY_CONTRACT,
        )
        self.assertTrue(context._audit_record_matches(recovery, binding))
        self.assertEqual(
            recovery["recovery"],
            {
                "kind": "existing-exact-receipt-audit-rebinding",
                "receipt_observed_before_audit": True,
            },
        )
        recovery.pop("recovery")
        self.assertFalse(context._audit_record_matches(recovery, binding))

    def test_new_receipt_root_creation_fsyncs_each_parent(self) -> None:
        self.receipts = self.root / "nested" / "deeper" / "receipts"
        patches = self.patches(self.report())
        synced_directories: list[tuple[int, int]] = []
        real_fsync = context.os.fsync

        def record_fsync(descriptor: int) -> None:
            metadata = context.os.fstat(descriptor)
            if context.stat.S_ISDIR(metadata.st_mode):
                synced_directories.append((metadata.st_dev, metadata.st_ino))
            real_fsync(descriptor)

        with (
            self.patch_context(patches),
            patch.object(context.os, "fsync", side_effect=record_fsync),
        ):
            result = context.grabowski_reposkop_context(str(self.repo))

        expected = []
        for directory in (
            self.root,
            self.root / "nested",
            self.root / "nested" / "deeper",
        ):
            metadata = directory.stat()
            expected.append((metadata.st_dev, metadata.st_ino))
        for identity in expected:
            self.assertIn(identity, synced_directories)
        self.assertTrue(Path(result["usage_receipt"]["path"]).is_file())

    def test_missing_root_creation_rejects_swapped_symlink_ancestor(self) -> None:
        anchor = self.root / "receipt-anchor-race"
        anchor.mkdir(mode=0o700)
        moved_anchor = self.root / "receipt-anchor-race-moved"
        outside = self.root / "receipt-anchor-race-outside"
        outside.mkdir(mode=0o700)
        self.receipts = anchor / "nested" / "receipts"
        real_open = context.os.open
        swapped = False

        def swap_before_component_open(
            path, flags, mode=0o777, *, dir_fd=None
        ):
            nonlocal swapped
            if path == anchor.name and dir_fd is not None and not swapped:
                anchor.rename(moved_anchor)
                anchor.symlink_to(outside, target_is_directory=True)
                swapped = True
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with (
            patch.object(context, "RECEIPT_ROOT", self.receipts),
            patch.object(
                context.base,
                "_resolve_write_target",
                side_effect=lambda value, **_kwargs: (Path(value), Path(value).exists()),
            ),
            patch.object(context.base, "_roots", return_value=[self.root]),
            patch.object(context.os, "open", side_effect=swap_before_component_open),
        ):
            with self.assertRaisesRegex(
                context.ReposkopContextError,
                "component could not be opened safely",
            ):
                context._ensure_receipt_root()

        self.assertTrue(swapped)
        self.assertEqual(list(moved_anchor.iterdir()), [])
        self.assertEqual(list(outside.iterdir()), [])

    def test_missing_root_creation_reanchors_and_removes_moved_child(self) -> None:
        anchor = self.root / "receipt-anchor"
        anchor.mkdir(mode=0o700)
        moved_anchor = self.root / "receipt-anchor-moved"
        self.receipts = anchor / "nested" / "receipts"
        real_mkdir = context.os.mkdir
        replaced = False

        def move_parent_before_create(
            path, mode=0o777, *, dir_fd=None
        ):
            nonlocal replaced
            if path == "nested" and dir_fd is not None and not replaced:
                anchor.rename(moved_anchor)
                anchor.mkdir(mode=0o700)
                replaced = True
            return real_mkdir(path, mode, dir_fd=dir_fd)

        with (
            patch.object(context, "RECEIPT_ROOT", self.receipts),
            patch.object(
                context.base, "_resolve_write_target",
                side_effect=lambda value, **_kwargs: (Path(value), Path(value).exists()),
            ),
            patch.object(context.base, "_roots", return_value=[self.root]),
            patch.object(context.os, "mkdir", side_effect=move_parent_before_create),
        ):
            with self.assertRaisesRegex(
                context.ReposkopContextError,
                "authorized write-root path",
            ):
                context._ensure_receipt_root()

        self.assertTrue(replaced)
        self.assertEqual(list(anchor.iterdir()), [])
        self.assertEqual(list(moved_anchor.iterdir()), [])

    def test_missing_root_creation_rolls_back_entire_created_chain(self) -> None:
        anchor = self.root / "receipt-chain"
        anchor.mkdir(mode=0o700)
        moved_anchor = self.root / "receipt-chain-moved"
        self.receipts = anchor / "nested" / "deeper" / "receipts"
        real_mkdir = context.os.mkdir
        moved = False

        def move_after_first_created_component(
            path, mode=0o777, *, dir_fd=None
        ):
            nonlocal moved
            if path == "deeper" and dir_fd is not None and not moved:
                anchor.rename(moved_anchor)
                anchor.mkdir(mode=0o700)
                moved = True
            return real_mkdir(path, mode, dir_fd=dir_fd)

        with (
            patch.object(context, "RECEIPT_ROOT", self.receipts),
            patch.object(
                context.base,
                "_resolve_write_target",
                side_effect=lambda value, **_kwargs: (Path(value), Path(value).exists()),
            ),
            patch.object(context.base, "_roots", return_value=[self.root]),
            patch.object(
                context.os, "mkdir", side_effect=move_after_first_created_component
            ),
        ):
            with self.assertRaisesRegex(
                context.ReposkopContextError,
                "authorized write-root path",
            ):
                context._ensure_receipt_root()

        self.assertTrue(moved)
        self.assertEqual(list(anchor.iterdir()), [])
        self.assertEqual(list(moved_anchor.iterdir()), [])

    def test_missing_root_creation_rolls_back_after_child_fsync_failure(self) -> None:
        created = self.root / "fsync-failure"
        self.receipts = created / "receipts"
        real_fsync = context.os.fsync
        failed = False

        def fail_created_directory_fsync(descriptor: int) -> None:
            nonlocal failed
            if created.exists() and not failed:
                observed = context.os.fstat(descriptor)
                linked = created.stat()
                if (observed.st_dev, observed.st_ino) == (
                    linked.st_dev,
                    linked.st_ino,
                ):
                    failed = True
                    raise OSError("injected child fsync failure")
            real_fsync(descriptor)

        with (
            patch.object(context, "RECEIPT_ROOT", self.receipts),
            patch.object(
                context.base,
                "_resolve_write_target",
                side_effect=lambda value, **_kwargs: (Path(value), Path(value).exists()),
            ),
            patch.object(context.base, "_roots", return_value=[self.root]),
            patch.object(context.os, "fsync", side_effect=fail_created_directory_fsync),
        ):
            with self.assertRaisesRegex(
                context.ReposkopContextError,
                "failed safely and was rolled back",
            ):
                context._ensure_receipt_root()

        self.assertTrue(failed)
        self.assertFalse(created.exists())


    def test_rejects_boolean_schema_versions(self) -> None:
        cases = (
            self.report(schema_version=True),
            self.report(observation_schema_version=True),
            self.report(projection_schema_version=True),
        )
        for report in cases:
            with self.subTest(report=report):
                patches = self.patches(report)
                with self.patch_context(patches):
                    with self.assertRaisesRegex(ValueError, "kind or schema"):
                        context.grabowski_reposkop_context(str(self.repo))
        self.assertFalse(self.receipts.exists())

    def test_rejects_nonfinite_json_constants_before_publication(self) -> None:
        report = self.report()
        report["generated_at"] = float("nan")
        patches = self.patches(report)
        with self.patch_context(patches):
            with self.assertRaisesRegex(ValueError, "not valid JSON"):
                context.grabowski_reposkop_context(str(self.repo))
        self.assertFalse(self.receipts.exists())



if __name__ == "__main__":
    unittest.main()
