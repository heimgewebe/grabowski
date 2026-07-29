from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
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

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def report(self, *, effect_authorized: bool = False) -> dict[str, object]:
        target = str(self.repo.resolve())
        purpose = "grabowski-repo-state-context"
        return {
            "kind": "reposkop_coherence_report",
            "schema_version": 1,
            "generated_at": "2026-07-29T08:00:00Z",
            "effect_authorized": effect_authorized,
            "report_sha256": "a" * 64,
            "observation": {
                "kind": "reposkop_checkout_observation",
                "schema_version": 1,
                "observation_sha256": "b" * 64,
                "identities": {"path": target, "purpose": purpose},
            },
            "projection": {
                "kind": "reposkop_coherence_projection",
                "schema_version": 1,
                "projection_sha256": "c" * 64,
                "effect_authorized": False,
            },
        }

    def patches(
        self, report: dict[str, object], *, audit_error: BaseException | None = None
    ):
        def fake_run(argv, *, cwd, timeout_seconds, max_output_bytes):
            self.run_calls.append((list(argv), Path(cwd)))
            self.assertEqual(timeout_seconds, 20)
            self.assertEqual(max_output_bytes, context.MAX_REPORT_BYTES)
            return {
                "returncode": 0,
                "stdout": json.dumps(report),
                "stderr": "",
            }

        def fake_audit(record):
            self.audit_records.append(dict(record))
            if audit_error is not None:
                raise audit_error
            return "d" * 64

        return (
            patch.object(context, "REPOSKOP_BIN", self.executable),
            patch.object(context, "RECEIPT_ROOT", self.receipts),
            patch.object(context.operator, "_run", side_effect=fake_run),
            patch.object(context.base, "_require_capability"),
            patch.object(
                context.base,
                "_resolve_existing",
                side_effect=lambda value, _kind: Path(value).resolve(strict=True),
            ),
            patch.object(context.operator, "_require_operator_mutation"),
            patch.object(context.base, "_require_mutations_enabled"),
            patch.object(
                context.base, "_append_audit_with_digest", side_effect=fake_audit
            ),
        )

    def test_records_one_receipt_and_replays_unchanged_semantic_state(self) -> None:
        patches = self.patches(self.report())
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patches[7],
        ):
            first = context.grabowski_reposkop_context(str(self.repo))
            second = context.grabowski_reposkop_context(str(self.repo))

        self.assertFalse(first["usage_receipt"]["replayed"])
        self.assertEqual(
            first["usage_receipt"]["audit_ref"],
            "audit-record-sha256:" + "d" * 64,
        )
        self.assertTrue(second["usage_receipt"]["replayed"])
        self.assertNotIn("audit_ref", second["usage_receipt"])
        self.assertEqual(len(self.audit_records), 1)
        self.assertEqual(
            self.audit_records[0]["operation"], "reposkop-context-usage-record"
        )
        self.assertEqual(
            first["usage_receipt"]["usage_key_sha256"],
            second["usage_receipt"]["usage_key_sha256"],
        )
        self.assertEqual(len(list(self.receipts.glob("*.json"))), 1)
        receipt_path = Path(first["usage_receipt"]["path"])
        self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.receipts.stat().st_mode & 0o777, 0o700)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt["kind"], context.RECEIPT_KIND)
        self.assertFalse(receipt["effect_authorized"])
        self.assertEqual(first["report"]["effect_authorized"], False)
        self.assertEqual(len(self.run_calls), 2)
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

    def test_audit_failure_removes_new_receipt(self) -> None:
        patches = self.patches(self.report(), audit_error=RuntimeError("audit failed"))
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patches[7],
        ):
            with self.assertRaisesRegex(RuntimeError, "audit failed"):
                context.grabowski_reposkop_context(str(self.repo))
        self.assertEqual(list(self.receipts.glob("*.json")), [])
        self.assertEqual(len(self.audit_records), 1)


    def test_rejects_any_effect_authorization_from_reposkop(self) -> None:
        patches = self.patches(self.report(effect_authorized=True))
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patches[7],
        ):
            with self.assertRaisesRegex(
                ValueError, "effect_authorized=false"
            ):
                context.grabowski_reposkop_context(str(self.repo))
        self.assertFalse(self.receipts.exists())

    def test_rejects_relative_or_symlink_target(self) -> None:
        with self.assertRaisesRegex(ValueError, "absolute path"):
            context.grabowski_reposkop_context("repo")
        link = self.root / "repo-link"
        link.symlink_to(self.repo, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "may not be a symlink"):
            context.grabowski_reposkop_context(str(link))

    def test_existing_receipt_identity_drift_fails_closed(self) -> None:
        patches = self.patches(self.report())
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patches[7],
        ):
            first = context.grabowski_reposkop_context(str(self.repo))
            receipt_path = Path(first["usage_receipt"]["path"])
            payload = json.loads(receipt_path.read_text(encoding="utf-8"))
            payload["purpose"] = "tampered"
            receipt_path.write_text(json.dumps(payload), encoding="utf-8")
            os.chmod(receipt_path, 0o600)
            with self.assertRaisesRegex(ValueError, "identity drift"):
                context.grabowski_reposkop_context(str(self.repo))


if __name__ == "__main__":
    unittest.main()
