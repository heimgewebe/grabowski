from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from unittest import TestCase, mock

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "materialize_ntfy_topic_sops.py"
SPEC = importlib.util.spec_from_file_location("materialize_ntfy_topic_sops", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
materializer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(materializer)


class NtfyTopicSopsMaterializationTests(TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.sops = self.root / "sops"
        self.sops.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.sops.chmod(0o700)
        self.age_key = self.root / "keys.txt"
        self.age_key.write_text("AGE-SECRET-KEY-TEST\n", encoding="utf-8")
        self.age_key.chmod(0o600)
        self.runtime = self.root / "ntfy-topic"
        self.runtime.write_text("x" * 64 + "\n", encoding="utf-8")
        self.runtime.chmod(0o600)
        self.encrypted = self.root / "ntfy-topic.sops.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_encrypt_requires_two_distinct_recipients(self) -> None:
        with self.assertRaisesRegex(
            materializer.TopicMaterializationError,
            "at least two distinct age recipients",
        ):
            materializer.encrypt_topic(
                source=self.runtime,
                destination=self.encrypted,
                recipients=["age1same", "age1same"],
                sops_path=self.sops,
            )

    def test_encrypt_refuses_symlink_plaintext_source(self) -> None:
        real = self.root / "real-topic"
        real.write_text("x" * 64 + "\n", encoding="utf-8")
        real.chmod(0o600)
        link = self.root / "topic-link"
        link.symlink_to(real)
        with self.assertRaisesRegex(
            materializer.TopicMaterializationError,
            "unavailable|not a regular file",
        ):
            materializer.encrypt_topic(
                source=link,
                destination=self.encrypted,
                recipients=["age1one", "age1two"],
                sops_path=self.sops,
            )

    def test_encrypt_refuses_group_readable_plaintext(self) -> None:
        self.runtime.chmod(0o640)
        with self.assertRaisesRegex(
            materializer.TopicMaterializationError,
            "must not be accessible",
        ):
            materializer.encrypt_topic(
                source=self.runtime,
                destination=self.encrypted,
                recipients=["age1one", "age1two"],
                sops_path=self.sops,
            )

    def test_encrypt_creates_private_ciphertext_without_plaintext(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[str(self.sops)],
            returncode=0,
            stdout=b'{"topic":"ENC[AES256_GCM,data:opaque]","sops":{}}\n',
            stderr=b"",
        )
        with mock.patch.object(materializer.subprocess, "run", return_value=completed) as run:
            result = materializer.encrypt_topic(
                source=self.runtime,
                destination=self.encrypted,
                recipients=["age1one", "age1two"],
                sops_path=self.sops,
            )

        self.assertEqual(result["status"], "encrypted")
        self.assertEqual(result["recipient_count"], 2)
        self.assertNotIn(("x" * 64).encode(), self.encrypted.read_bytes())
        self.assertEqual(stat.S_IMODE(self.encrypted.stat().st_mode), 0o600)
        argv = run.call_args.args[0]
        self.assertIn("--age", argv)
        self.assertNotIn("x" * 64, argv)

    def test_encrypt_does_not_replace_existing_destination(self) -> None:
        self.encrypted.write_bytes(b"existing-ciphertext")
        self.encrypted.chmod(0o600)
        completed = subprocess.CompletedProcess(
            args=[str(self.sops)],
            returncode=0,
            stdout=b'{"topic":"ENC[AES256_GCM,data:new]","sops":{}}\n',
            stderr=b"",
        )
        with mock.patch.object(materializer.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(
                materializer.TopicMaterializationError,
                "destination already exists",
            ):
                materializer.encrypt_topic(
                    source=self.runtime,
                    destination=self.encrypted,
                    recipients=["age1one", "age1two"],
                    sops_path=self.sops,
                )
        self.assertEqual(self.encrypted.read_bytes(), b"existing-ciphertext")

    def test_materialize_decrypts_and_writes_private_runtime_file(self) -> None:
        self.encrypted.write_text('{"sops":{}}\n', encoding="utf-8")
        self.encrypted.chmod(0o600)
        completed = subprocess.CompletedProcess(
            args=[str(self.sops)],
            returncode=0,
            stdout=json.dumps({"topic": "y" * 64}).encode(),
            stderr=b"",
        )
        with mock.patch.object(materializer.subprocess, "run", return_value=completed):
            result = materializer.materialize_topic(
                encrypted=self.encrypted,
                destination=self.runtime,
                age_key_file=self.age_key,
                sops_path=self.sops,
            )

        self.assertEqual(result["status"], "materialized")
        self.assertEqual(self.runtime.read_text(encoding="utf-8"), "y" * 64 + "\n")
        self.assertEqual(stat.S_IMODE(self.runtime.stat().st_mode), 0o600)

    def test_verify_reports_match_without_returning_topic(self) -> None:
        self.encrypted.write_text('{"sops":{}}\n', encoding="utf-8")
        self.encrypted.chmod(0o600)
        completed = subprocess.CompletedProcess(
            args=[str(self.sops)],
            returncode=0,
            stdout=json.dumps({"topic": "x" * 64}).encode(),
            stderr=b"",
        )
        with mock.patch.object(materializer.subprocess, "run", return_value=completed):
            result = materializer.verify_topic(
                encrypted=self.encrypted,
                runtime=self.runtime,
                age_key_file=self.age_key,
                sops_path=self.sops,
            )

        self.assertEqual(result, {"status": "verified", "matches": True, "runtime_mode_private": True})
        self.assertNotIn("x" * 64, json.dumps(result))

    def test_verify_fails_closed_on_mismatch(self) -> None:
        self.encrypted.write_text('{"sops":{}}\n', encoding="utf-8")
        self.encrypted.chmod(0o600)
        completed = subprocess.CompletedProcess(
            args=[str(self.sops)],
            returncode=0,
            stdout=json.dumps({"topic": "z" * 64}).encode(),
            stderr=b"",
        )
        with mock.patch.object(materializer.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(
                materializer.TopicMaterializationError,
                "does not match encrypted canonical source",
            ):
                materializer.verify_topic(
                    encrypted=self.encrypted,
                    runtime=self.runtime,
                    age_key_file=self.age_key,
                    sops_path=self.sops,
                )

    def test_sops_failure_does_not_expose_stderr(self) -> None:
        self.encrypted.write_text('{"sops":{}}\n', encoding="utf-8")
        self.encrypted.chmod(0o600)
        completed = subprocess.CompletedProcess(
            args=[str(self.sops)],
            returncode=1,
            stdout=b"",
            stderr=b"sensitive diagnostic secret",
        )
        with mock.patch.object(materializer.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(materializer.TopicMaterializationError, "sops operation failed") as caught:
                materializer.materialize_topic(
                    encrypted=self.encrypted,
                    destination=self.runtime,
                    age_key_file=self.age_key,
                    sops_path=self.sops,
                )
        self.assertNotIn("sensitive diagnostic secret", str(caught.exception))


if __name__ == "__main__":
    import unittest

    unittest.main()
