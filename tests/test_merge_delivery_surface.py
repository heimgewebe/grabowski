from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import grabowski_merge_delivery_surface as surface


class MergeDeliverySurfaceTests(unittest.TestCase):
    def test_runtime_tool_requires_mutation_authority_before_delegation(self) -> None:
        runtime_path = Path(__file__).resolve().parents[1] / "src/grabowski_runtime.py"
        module = ast.parse(runtime_path.read_text(encoding="utf-8"))
        function = next(
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "grabowski_merge_delivery_record"
        )

        guard_index = next(
            index
            for index, statement in enumerate(function.body)
            if isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Attribute)
            and statement.value.func.attr == "_require_operator_mutation"
        )
        delegation_index = next(
            index
            for index, statement in enumerate(function.body)
            if isinstance(statement, ast.Return)
            and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Attribute)
            and statement.value.func.attr == "grabowski_merge_delivery_record"
        )

        self.assertLess(guard_index, delegation_index)

    def test_surface_records_then_appends_bounded_audit(self) -> None:
        receipt = {
            "repository": "heimgewebe/grabowski",
            "pull_request": 96,
            "base_sha": "a" * 40,
            "head_sha": "b" * 40,
            "diff_sha256": "c" * 64,
            "artifact_id": "d" * 32,
            "delivery_channel": "chat-download",
            "delivery_reference_sha256": "e" * 64,
            "delivery_confirmed_at_unix_ns": 1,
        }
        result = {"receipt": receipt, "receipt_sha256": "f" * 64}
        append_audit = Mock()

        with patch.object(surface.delivery, "record_merge_delivery", return_value=result) as record:
            with patch.object(
                surface,
                "_base",
                return_value=SimpleNamespace(_append_audit=append_audit),
            ):
                observed = surface.grabowski_merge_delivery_record(
                    "heimgewebe/grabowski",
                    96,
                    "a" * 40,
                    "b" * 40,
                    "c" * 64,
                    "d" * 32,
                    "c" * 64,
                    "e" * 64,
                    "chat-download",
                    "sandbox:/mnt/data/diff.txt",
                )

        self.assertEqual(result, observed)
        record.assert_called_once()
        append_audit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
