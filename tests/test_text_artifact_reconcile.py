from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import grabowski_artifacts as artifacts
import grabowski_text_artifact_reconcile as reconcile


def _write_private(path: Path, payload: bytes, mode: int = 0o600) -> None:
    path.write_bytes(payload)
    path.chmod(mode)


def _artifact_fixture(
    root: Path,
    *,
    artifact_id: str = "a" * 32,
) -> tuple[str, str, str, Path, bytes]:
    root.mkdir(mode=0o700, exist_ok=True)
    root.chmod(0o700)
    directory = root / artifact_id
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    filename = "bureau-pr-1-aaaaaaaaaaaa-diff.txt"
    payload = b"diff --git a/a b/a\n+reviewed\n"
    artifact_sha256 = hashlib.sha256(payload).hexdigest()
    _write_private(directory / filename, payload)
    receipt = {
        "schema": artifacts.TEXT_ARTIFACT_SCHEMA,
        "profile": artifacts.TEXT_ARTIFACT_PROFILE,
        "artifact_id": artifact_id,
        "repository": "heimgewebe/bureau",
        "repository_path_sha256": "b" * 64,
        "base_commit": "1" * 40,
        "head_commit": "2" * 40,
        "pull_request_number": 1,
        "filename": filename,
        "diff_sha256": artifact_sha256,
        "byte_size": len(payload),
        "generated_at_unix": 1,
        "encoding": "utf-8",
        "format": "unified-diff",
    }
    receipt_bytes = artifacts._canonical_json_bytes(receipt)
    _write_private(directory / "receipt.json", receipt_bytes)
    return (
        artifact_id,
        artifact_sha256,
        hashlib.sha256(receipt_bytes).hexdigest(),
        directory,
        payload,
    )


def _git_repository(root: Path) -> tuple[Path, str, str]:
    repository = root / "repo"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Test"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "config",
            "user.email",
            "test@example.invalid",
        ],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "remote",
            "add",
            "origin",
            "git@github.com:heimgewebe/reconcile-test.git",
        ],
        check=True,
    )
    (repository / "value.txt").write_text("before\n")
    subprocess.run(["git", "-C", str(repository), "add", "value.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-qm", "base"],
        check=True,
    )
    base = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()
    (repository / "value.txt").write_text("after\n")
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-qam", "head"],
        check=True,
    )
    head = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()
    return repository, base, head


class TextArtifactReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root_patch = patch.object(
            artifacts.base, "_roots", return_value=(self.root,)
        )
        self.root_patch.start()

    def tearDown(self) -> None:
        self.root_patch.stop()
        self.temporary.cleanup()

    def test_inspect_and_reconcile_quarantines_only_exact_sidecars(self) -> None:
        store = self.root / "text-artifacts"
        quarantine = self.root / "quarantine"
        artifact_id, artifact_sha256, receipt_sha256, directory, payload = (
            _artifact_fixture(store)
        )
        sidecar = directory / "artifact.chunk.00"
        _write_private(sidecar, b"transport", 0o644)
        source_inode = sidecar.stat().st_ino

        with (
            patch.object(artifacts, "TEXT_ARTIFACT_ROOT", store),
            patch.object(reconcile, "TEXT_ARTIFACT_QUARANTINE_ROOT", quarantine),
            patch.object(artifacts.base, "_append_audit") as append_audit,
        ):
            inventory = reconcile.inspect_text_artifact_store(artifact_id)
            self.assertEqual(
                inventory["managed"]["artifact_sha256"], artifact_sha256
            )
            self.assertEqual(
                inventory["managed"]["receipt_sha256"], receipt_sha256
            )
            self.assertEqual(inventory["unmanaged_entries"][0]["mode"], 0o644)
            self.assertEqual(
                inventory["unmanaged_entries"][0]["path"],
                f"{artifact_id}/artifact.chunk.00",
            )
            self.assertEqual(
                inventory["unmanaged_entries"][0]["file_type"], "regular"
            )
            result = reconcile.reconcile_text_artifact_store(
                artifact_id,
                inventory["inventory_sha256"],
                artifact_sha256,
                receipt_sha256,
            )
            self.assertEqual(result["status"], "reconciled")
            self.assertEqual(result["moved_entry_count"], 1)
            self.assertEqual(
                {path.name for path in directory.iterdir()},
                {"receipt.json", "bureau-pr-1-aaaaaaaaaaaa-diff.txt"},
            )
            quarantined = Path(result["quarantine_path"])
            self.assertEqual(
                (quarantined / "artifact.chunk.00").read_bytes(), b"transport"
            )
            self.assertEqual(
                (quarantined / "artifact.chunk.00").stat().st_mode & 0o777,
                0o600,
            )
            self.assertEqual(
                (quarantined / "artifact.chunk.00").stat().st_ino,
                source_inode,
            )
            self.assertEqual(
                json.loads((quarantined / "receipt.json").read_text())[
                    "inventory_sha256"
                ],
                inventory["inventory_sha256"],
            )
            self.assertEqual(append_audit.call_count, 2)
            self.assertTrue(
                artifacts.read_text_artifact(
                    artifact_id,
                    artifact_sha256,
                    receipt_sha256,
                )["payload_b64"]
            )
            self.assertEqual(
                (directory / "bureau-pr-1-aaaaaaaaaaaa-diff.txt").read_bytes(),
                payload,
            )

    def test_store_inventory_discovers_bound_anomalies(self) -> None:
        store = self.root / "text-artifacts"
        artifact_id, _, _, directory, _ = _artifact_fixture(store)
        _write_private(directory / "artifact.txt.gz.b64", b"transport", 0o640)

        with patch.object(artifacts, "TEXT_ARTIFACT_ROOT", store):
            inventory = reconcile.inspect_text_artifact_store_root()

        self.assertEqual(inventory["artifact_count"], 1)
        self.assertEqual(inventory["anomaly_count"], 1)
        anomaly = inventory["anomalies"][0]
        self.assertEqual(anomaly["artifact_id"], artifact_id)
        self.assertRegex(inventory["store_inventory_sha256"], r"[0-9a-f]{64}")
        self.assertEqual(
            anomaly["unmanaged_entries"][0]["path"],
            f"{artifact_id}/artifact.txt.gz.b64",
        )
        self.assertEqual(
            anomaly["unmanaged_entries"][0]["file_type"], "regular"
        )

    def test_inspect_rejects_nonallowlisted_sidecar_modes(self) -> None:
        for mode in (0o400, 0o666):
            with self.subTest(mode=oct(mode)):
                case = self.root / oct(mode)
                case.mkdir()
                store = case / "text-artifacts"
                artifact_id, _, _, directory, _ = _artifact_fixture(store)
                sidecar = directory / "artifact.chunk.00"
                _write_private(sidecar, b"transport", mode)
                with patch.object(artifacts, "TEXT_ARTIFACT_ROOT", store):
                    with self.assertRaisesRegex(
                        reconcile.TextArtifactReconciliationError,
                        "bounded owner-controlled regular file",
                    ):
                        reconcile.inspect_text_artifact_store(artifact_id)
                self.assertEqual(sidecar.read_bytes(), b"transport")

    def test_reconcile_fails_before_effect_when_store_is_locked(self) -> None:
        store = self.root / "text-artifacts"
        quarantine = self.root / "quarantine"
        artifact_id, artifact_sha256, receipt_sha256, directory, _ = (
            _artifact_fixture(store)
        )
        sidecar = directory / "artifact.chunk.00"
        _write_private(sidecar, b"transport", 0o644)
        with (
            patch.object(artifacts, "TEXT_ARTIFACT_ROOT", store),
            patch.object(reconcile, "TEXT_ARTIFACT_QUARANTINE_ROOT", quarantine),
        ):
            inventory = reconcile.inspect_text_artifact_store(artifact_id)
            descriptor = os.open(store, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaisesRegex(
                    reconcile.TextArtifactReconciliationError, "store is busy"
                ):
                    reconcile.reconcile_text_artifact_store(
                        artifact_id,
                        inventory["inventory_sha256"],
                        artifact_sha256,
                        receipt_sha256,
                    )
            finally:
                os.close(descriptor)
        self.assertFalse(quarantine.exists())
        self.assertEqual(sidecar.read_bytes(), b"transport")

    def test_quarantine_publication_is_create_only_under_race(self) -> None:
        store = self.root / "text-artifacts"
        quarantine = self.root / "quarantine"
        artifact_id, artifact_sha256, receipt_sha256, directory, _ = (
            _artifact_fixture(store)
        )
        sidecar = directory / "artifact.chunk.00"
        _write_private(sidecar, b"transport", 0o644)
        original = reconcile._rename_directory_noreplace

        def create_destination_then_rename(
            parent_descriptor: int, source_name: str, destination_name: str
        ) -> None:
            os.mkdir(destination_name, 0o700, dir_fd=parent_descriptor)
            original(parent_descriptor, source_name, destination_name)

        with (
            patch.object(artifacts, "TEXT_ARTIFACT_ROOT", store),
            patch.object(reconcile, "TEXT_ARTIFACT_QUARANTINE_ROOT", quarantine),
            patch.object(
                reconcile,
                "_rename_directory_noreplace",
                side_effect=create_destination_then_rename,
            ),
        ):
            inventory = reconcile.inspect_text_artifact_store(artifact_id)
            with self.assertRaisesRegex(
                reconcile.TextArtifactReconciliationError,
                "destination already exists",
            ):
                reconcile.reconcile_text_artifact_store(
                    artifact_id,
                    inventory["inventory_sha256"],
                    artifact_sha256,
                    receipt_sha256,
                )
        destination = quarantine / inventory["inventory_sha256"]
        self.assertTrue(destination.is_dir())
        self.assertEqual(list(destination.iterdir()), [])
        self.assertFalse(any(path.name.startswith(".") for path in quarantine.iterdir()))
        self.assertEqual(sidecar.read_bytes(), b"transport")

    def test_source_replacement_before_isolation_is_preserved_not_deleted(self) -> None:
        store = self.root / "text-artifacts"
        quarantine = self.root / "quarantine"
        artifact_id, artifact_sha256, receipt_sha256, directory, _ = (
            _artifact_fixture(store)
        )
        sidecar = directory / "artifact.chunk.00"
        _write_private(sidecar, b"reviewed", 0o644)
        displaced_original = self.root / "displaced-original"
        original_rename = reconcile._rename_entry_noreplace
        replaced = False

        def replace_then_isolate(
            source_descriptor: int,
            source_name: str,
            destination_descriptor: int,
            destination_name: str,
        ) -> None:
            nonlocal replaced
            if not replaced:
                os.replace(sidecar, displaced_original)
                _write_private(sidecar, b"unreviewed-replacement", 0o644)
                replaced = True
            original_rename(
                source_descriptor,
                source_name,
                destination_descriptor,
                destination_name,
            )

        with (
            patch.object(artifacts, "TEXT_ARTIFACT_ROOT", store),
            patch.object(reconcile, "TEXT_ARTIFACT_QUARANTINE_ROOT", quarantine),
            patch.object(reconcile, "_rename_entry_noreplace", replace_then_isolate),
            patch.object(artifacts.base, "_append_audit"),
        ):
            inventory = reconcile.inspect_text_artifact_store(artifact_id)
            with self.assertRaisesRegex(
                reconcile.TextArtifactReconciliationError,
                "changed before atomic isolation",
            ):
                reconcile.reconcile_text_artifact_store(
                    artifact_id,
                    inventory["inventory_sha256"],
                    artifact_sha256,
                    receipt_sha256,
                )

        self.assertEqual(displaced_original.read_bytes(), b"reviewed")
        staging = [
            path for path in quarantine.iterdir() if path.name.startswith(".")
        ]
        self.assertEqual(len(staging), 1)
        self.assertEqual(
            (staging[0] / "artifact.chunk.00").read_bytes(),
            b"unreviewed-replacement",
        )

    def test_quarantine_count_capacity_blocks_before_source_cleanup(self) -> None:
        store = self.root / "text-artifacts"
        quarantine = self.root / "quarantine"
        first = _artifact_fixture(store, artifact_id="a" * 32)
        second = _artifact_fixture(store, artifact_id="b" * 32)
        _write_private(first[3] / "artifact.chunk.00", b"first", 0o644)
        second_sidecar = second[3] / "artifact.chunk.00"
        _write_private(second_sidecar, b"second", 0o644)

        with (
            patch.object(artifacts, "TEXT_ARTIFACT_ROOT", store),
            patch.object(reconcile, "TEXT_ARTIFACT_QUARANTINE_ROOT", quarantine),
            patch.object(artifacts.base, "_append_audit"),
        ):
            first_inventory = reconcile.inspect_text_artifact_store(first[0])
            reconcile.reconcile_text_artifact_store(
                first[0], first_inventory["inventory_sha256"], first[1], first[2]
            )
            second_inventory = reconcile.inspect_text_artifact_store(second[0])
            with (
                patch.object(reconcile, "_MAX_QUARANTINE_DIRECTORIES", 1),
                self.assertRaisesRegex(
                    reconcile.TextArtifactReconciliationError,
                    "directory capacity is exhausted",
                ),
            ):
                reconcile.reconcile_text_artifact_store(
                    second[0],
                    second_inventory["inventory_sha256"],
                    second[1],
                    second[2],
                )
        self.assertEqual(second_sidecar.read_bytes(), b"second")

    def test_quarantine_byte_capacity_blocks_before_source_cleanup(self) -> None:
        store = self.root / "text-artifacts"
        quarantine = self.root / "quarantine"
        artifact_id, artifact_sha256, receipt_sha256, directory, _ = (
            _artifact_fixture(store)
        )
        sidecar = directory / "artifact.chunk.00"
        _write_private(sidecar, b"transport", 0o644)

        with (
            patch.object(artifacts, "TEXT_ARTIFACT_ROOT", store),
            patch.object(reconcile, "TEXT_ARTIFACT_QUARANTINE_ROOT", quarantine),
            patch.object(reconcile, "_MAX_QUARANTINE_TOTAL_BYTES", 1),
        ):
            inventory = reconcile.inspect_text_artifact_store(artifact_id)
            with self.assertRaisesRegex(
                reconcile.TextArtifactReconciliationError,
                "byte capacity is exhausted",
            ):
                reconcile.reconcile_text_artifact_store(
                    artifact_id,
                    inventory["inventory_sha256"],
                    artifact_sha256,
                    receipt_sha256,
                )
        self.assertEqual(sidecar.read_bytes(), b"transport")
        self.assertEqual(list(quarantine.iterdir()), [])

    def test_reconcile_is_idempotent_but_rejects_new_unreviewed_entries(self) -> None:
        store = self.root / "text-artifacts"
        quarantine = self.root / "quarantine"
        artifact_id, artifact_sha256, receipt_sha256, directory, _ = (
            _artifact_fixture(store)
        )
        _write_private(directory / "artifact.chunk.00", b"transport", 0o644)

        with (
            patch.object(artifacts, "TEXT_ARTIFACT_ROOT", store),
            patch.object(reconcile, "TEXT_ARTIFACT_QUARANTINE_ROOT", quarantine),
            patch.object(artifacts.base, "_append_audit"),
        ):
            inventory = reconcile.inspect_text_artifact_store(artifact_id)
            first = reconcile.reconcile_text_artifact_store(
                artifact_id,
                inventory["inventory_sha256"],
                artifact_sha256,
                receipt_sha256,
            )
            replay = reconcile.reconcile_text_artifact_store(
                artifact_id,
                inventory["inventory_sha256"],
                artifact_sha256,
                receipt_sha256,
            )
            self.assertFalse(first["idempotent_replay"])
            self.assertTrue(replay["idempotent_replay"])
            self.assertEqual(replay["cleaned_entry_count"], 0)
            _write_private(directory / "rogue.bin", b"new", 0o600)
            with self.assertRaisesRegex(
                reconcile.TextArtifactReconciliationError,
                "outside the reviewed quarantine",
            ):
                reconcile.reconcile_text_artifact_store(
                    artifact_id,
                    inventory["inventory_sha256"],
                    artifact_sha256,
                    receipt_sha256,
                )
        self.assertEqual((directory / "rogue.bin").read_bytes(), b"new")

    def test_reconcile_rejects_quarantine_receipt_inventory_rebinding(self) -> None:
        store = self.root / "text-artifacts"
        quarantine = self.root / "quarantine"
        artifact_id, artifact_sha256, receipt_sha256, directory, _ = (
            _artifact_fixture(store)
        )
        _write_private(directory / "artifact.chunk.00", b"transport", 0o644)

        with (
            patch.object(artifacts, "TEXT_ARTIFACT_ROOT", store),
            patch.object(reconcile, "TEXT_ARTIFACT_QUARANTINE_ROOT", quarantine),
            patch.object(artifacts.base, "_append_audit"),
        ):
            inventory = reconcile.inspect_text_artifact_store(artifact_id)
            result = reconcile.reconcile_text_artifact_store(
                artifact_id,
                inventory["inventory_sha256"],
                artifact_sha256,
                receipt_sha256,
            )
            quarantine_receipt = Path(result["quarantine_path"]) / "receipt.json"
            value = json.loads(quarantine_receipt.read_text())
            value["quarantined_entries"][0]["mtime_ns"] += 1
            quarantine_receipt.write_bytes(reconcile._canonical_bytes(value))
            quarantine_receipt.chmod(0o600)
            with self.assertRaisesRegex(
                reconcile.TextArtifactReconciliationError,
                "does not match the inventory hash",
            ):
                reconcile.reconcile_text_artifact_store(
                    artifact_id,
                    inventory["inventory_sha256"],
                    artifact_sha256,
                    receipt_sha256,
                )

    def test_reconcile_rejects_stale_inventory_without_mutation(self) -> None:
        store = self.root / "text-artifacts"
        quarantine = self.root / "quarantine"
        artifact_id, artifact_sha256, receipt_sha256, directory, _ = (
            _artifact_fixture(store)
        )
        sidecar = directory / "artifact.txt.gz.b64"
        _write_private(sidecar, b"first", 0o644)

        with (
            patch.object(artifacts, "TEXT_ARTIFACT_ROOT", store),
            patch.object(reconcile, "TEXT_ARTIFACT_QUARANTINE_ROOT", quarantine),
        ):
            inventory = reconcile.inspect_text_artifact_store(artifact_id)
            sidecar.write_bytes(b"changed")
            sidecar.chmod(0o644)
            with self.assertRaisesRegex(
                reconcile.TextArtifactReconciliationError, "inventory hash"
            ):
                reconcile.reconcile_text_artifact_store(
                    artifact_id,
                    inventory["inventory_sha256"],
                    artifact_sha256,
                    receipt_sha256,
                )
        self.assertEqual(sidecar.read_bytes(), b"changed")
        self.assertFalse(quarantine.exists())

    def test_inspect_rejects_linked_sidecars(self) -> None:
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                case = self.root / kind
                case.mkdir()
                store = case / "text-artifacts"
                artifact_id, _, _, directory, _ = _artifact_fixture(store)
                target = case / "target"
                target.write_bytes(b"linked")
                sidecar = directory / "artifact.chunk.00"
                if kind == "symlink":
                    sidecar.symlink_to(target)
                else:
                    os.link(target, sidecar)
                with patch.object(artifacts, "TEXT_ARTIFACT_ROOT", store):
                    with self.assertRaises(
                        reconcile.TextArtifactReconciliationError
                    ):
                        reconcile.inspect_text_artifact_store(artifact_id)

    def test_reconcile_preserves_fail_closed_publisher_and_restores_publish(
        self,
    ) -> None:
        store = self.root / "text-artifacts"
        quarantine = self.root / "quarantine"
        artifact_id, artifact_sha256, receipt_sha256, directory, _ = (
            _artifact_fixture(store)
        )
        _write_private(directory / "artifact.xz.chunk.00", b"transport", 0o644)
        repository, base, head = _git_repository(self.root)

        with (
            patch.object(artifacts, "TEXT_ARTIFACT_ROOT", store),
            patch.object(reconcile, "TEXT_ARTIFACT_QUARANTINE_ROOT", quarantine),
            patch.object(artifacts.base, "_append_audit"),
        ):
            with self.assertRaisesRegex(
                artifacts.ArtifactTransferError, "unmanaged entries"
            ):
                artifacts.publish_text_artifact(
                    artifacts.TEXT_ARTIFACT_PROFILE,
                    str(repository),
                    base,
                    head,
                )
            inventory = reconcile.inspect_text_artifact_store(artifact_id)
            reconcile.reconcile_text_artifact_store(
                artifact_id,
                inventory["inventory_sha256"],
                artifact_sha256,
                receipt_sha256,
            )
            canary = artifacts.publish_text_artifact(
                artifacts.TEXT_ARTIFACT_PROFILE,
                str(repository),
                base,
                head,
            )
            self.assertRegex(canary["diff_sha256"], r"[0-9a-f]{64}")
            self.assertNotEqual(canary["artifact_id"], artifact_id)

    def test_inspect_fails_when_store_is_exclusively_locked(self) -> None:
        store = self.root / "text-artifacts"
        artifact_id, _, _, _, _ = _artifact_fixture(store)
        descriptor = os.open(store, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(artifacts, "TEXT_ARTIFACT_ROOT", store):
                with self.assertRaisesRegex(
                    reconcile.TextArtifactReconciliationError, "busy"
                ):
                    reconcile.inspect_text_artifact_store(artifact_id)
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
