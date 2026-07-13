from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools/systemkatalog_usage_receipt.py"
SPEC = importlib.util.spec_from_file_location("systemkatalog_usage_receipt", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def query_result(*, command: str = "truth-owner") -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": "system_catalog_query_result",
        "catalogRepository": "heimgewebe/systemkatalog",
        "catalogCommit": "a" * 40,
        "command": command,
        "result": {"owner": "repo:grabowski"},
        "sourcePaths": [
            "registry/ecosystem/nodes.json",
            "registry/ecosystem/authority-matrix.v1.json",
        ],
        "doesNotEstablish": ["runtime_health"],
    }


class SystemkatalogUsageReceiptTests(unittest.TestCase):
    def test_build_receipt_binds_real_query_result_and_operator_declaration(self) -> None:
        result = query_result()
        state = {
            "root": Path("/unused"),
            "head": "a" * 40,
            "tracked_worktree_clean": True,
        }
        with (
            patch.object(MODULE, "_catalog_state", side_effect=[state, state]),
            patch.object(MODULE, "_query", return_value=result),
            patch.object(MODULE, "_verify_sources_match_head") as verify_sources,
        ):
            receipt = MODULE.build_receipt(
                systemkatalog_root=Path("/unused"),
                command="truth-owner",
                argument="agent_routing",
                reason="truth_owner",
                result_use="used",
                decision_effect="confirmed",
            )
        verify_sources.assert_called_once_with(
            Path("/unused"), "a" * 40, result["sourcePaths"]
        )

        self.assertEqual(receipt["kind"], "grabowski.systemkatalog_usage_receipt")
        self.assertEqual(receipt["schema_version"], 1)
        self.assertEqual(receipt["systemkatalog"]["commit"], "a" * 40)
        self.assertEqual(
            receipt["systemkatalog"]["catalog_state"],
            {
                "head_stable": True,
                "tracked_worktree_clean": True,
                "source_paths_match_head": True,
            },
        )
        self.assertEqual(
            receipt["systemkatalog"]["query"],
            {"command": "truth-owner", "argument": "agent_routing"},
        )
        self.assertEqual(
            receipt["systemkatalog"]["query_result_sha256"],
            MODULE._sha256_json(result),
        )
        self.assertIs(receipt["usage"]["consulted"], True)
        self.assertEqual(receipt["usage"]["usage_evidence"], "operator_declared")
        self.assertEqual(receipt["usage"]["decision_effect"], "confirmed")
        self.assertIn("decision_causality", receipt["does_not_establish"])
        expected_hash = MODULE._sha256_json(
            {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        )
        self.assertEqual(receipt["receipt_sha256"], expected_hash)

    def test_dirty_catalog_is_rejected_before_query(self) -> None:
        dirty = {
            "root": Path("/catalog"),
            "head": "a" * 40,
            "tracked_worktree_clean": False,
        }
        with (
            patch.object(MODULE, "_catalog_state", return_value=dirty),
            patch.object(MODULE, "_query") as query,
        ):
            with self.assertRaisesRegex(MODULE.UsageReceiptError, "not clean"):
                MODULE.build_receipt(
                    systemkatalog_root=Path("/catalog"),
                    command="truth-owner",
                    argument="agent_routing",
                    reason="truth_owner",
                    result_use="used",
                    decision_effect="confirmed",
                )
        query.assert_not_called()

    def test_catalog_head_change_during_query_is_rejected(self) -> None:
        before = {
            "root": Path("/catalog"),
            "head": "a" * 40,
            "tracked_worktree_clean": True,
        }
        after = {**before, "head": "b" * 40}
        with (
            patch.object(MODULE, "_catalog_state", side_effect=[before, after]),
            patch.object(MODULE, "_query", return_value=query_result()),
        ):
            with self.assertRaisesRegex(MODULE.UsageReceiptError, "HEAD changed"):
                MODULE.build_receipt(
                    systemkatalog_root=Path("/catalog"),
                    command="truth-owner",
                    argument="agent_routing",
                    reason="truth_owner",
                    result_use="used",
                    decision_effect="confirmed",
                )

    def test_query_commit_must_match_verified_head(self) -> None:
        state = {
            "root": Path("/catalog"),
            "head": "b" * 40,
            "tracked_worktree_clean": True,
        }
        with (
            patch.object(MODULE, "_catalog_state", side_effect=[state, state]),
            patch.object(MODULE, "_query", return_value=query_result()),
        ):
            with self.assertRaisesRegex(MODULE.UsageReceiptError, "does not match"):
                MODULE.build_receipt(
                    systemkatalog_root=Path("/catalog"),
                    command="truth-owner",
                    argument="agent_routing",
                    reason="truth_owner",
                    result_use="used",
                    decision_effect="confirmed",
                )

    def test_catalog_state_and_source_bytes_are_git_bound(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
            source = root / "registry.json"
            source.write_text('{"value":1}\n', encoding="utf-8")
            subprocess.run(["git", "add", "registry.json"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)

            state = MODULE._catalog_state(root)
            self.assertTrue(state["tracked_worktree_clean"])
            MODULE._verify_sources_match_head(root, state["head"], ["registry.json"])

            source.write_text('{"value":2}\n', encoding="utf-8")
            self.assertFalse(MODULE._catalog_state(root)["tracked_worktree_clean"])
            with self.assertRaisesRegex(MODULE.UsageReceiptError, "do not match"):
                MODULE._verify_sources_match_head(root, state["head"], ["registry.json"])

    def test_reason_must_match_query_shape(self) -> None:
        with self.assertRaisesRegex(MODULE.UsageReceiptError, "incompatible"):
            MODULE._validate_inputs(
                "truth-owner", "agent_routing", "entrypoint_lookup", "used", "confirmed"
            )

    def test_decision_effect_requires_used_result(self) -> None:
        with self.assertRaisesRegex(MODULE.UsageReceiptError, "require result_use=used"):
            MODULE._validate_inputs(
                "repository", "weltgewebe", "repository_selection", "not_used", "changed"
            )

    def test_argument_is_bounded_identifier_not_free_text(self) -> None:
        with self.assertRaisesRegex(MODULE.UsageReceiptError, "bounded"):
            MODULE._validate_inputs(
                "system", "please summarize everything", "system_overview", "used", "confirmed"
            )

    def test_query_uses_sanitized_environment_and_validates_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            scripts = root / "scripts"
            scripts.mkdir()
            script = scripts / "systemkatalog_query.py"
            script.write_text("# test fixture\n", encoding="utf-8")
            completed = subprocess.CompletedProcess(
                args=[], returncode=0, stdout=json.dumps(query_result()), stderr=""
            )
            with patch.object(MODULE.subprocess, "run", return_value=completed) as run:
                value = MODULE._query(root, "truth-owner", "agent_routing")

        self.assertEqual(value["catalogCommit"], "a" * 40)
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["timeout"], 15)
        self.assertEqual(kwargs["env"]["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertNotIn("HOME", kwargs["env"])

    def test_query_timeout_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "systemkatalog_query.py").write_text("# fixture\n", encoding="utf-8")
            timeout = subprocess.TimeoutExpired(cmd=["python"], timeout=15)
            with patch.object(MODULE.subprocess, "run", side_effect=timeout):
                with self.assertRaisesRegex(MODULE.UsageReceiptError, "timed out"):
                    MODULE._query(root, "truth-owner", "agent_routing")

    def test_query_rejects_symlink_script(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            scripts = root / "scripts"
            scripts.mkdir()
            real = root / "real_query.py"
            real.write_text("# fixture\n", encoding="utf-8")
            (scripts / "systemkatalog_query.py").symlink_to(real)
            with self.assertRaisesRegex(MODULE.UsageReceiptError, "must not be a symlink"):
                MODULE._query(root, "truth-owner", "agent_routing")

    def test_query_rejects_unbound_source_path(self) -> None:
        invalid = query_result()
        invalid["sourcePaths"] = ["../private.txt"]
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "systemkatalog_query.py").write_text("# fixture\n", encoding="utf-8")
            completed = subprocess.CompletedProcess(
                args=[], returncode=0, stdout=json.dumps(invalid), stderr=""
            )
            with patch.object(MODULE.subprocess, "run", return_value=completed):
                with self.assertRaisesRegex(MODULE.UsageReceiptError, "source paths"):
                    MODULE._query(root, "truth-owner", "agent_routing")

    def test_atomic_output_is_private_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            target = Path(raw_tmp) / "nested" / "receipt.json"
            encoded = b'{"ok":true}\n'
            MODULE._write_atomic(target, encoded)
            self.assertEqual(target.read_bytes(), encoded)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(
                [path.name for path in target.parent.iterdir()],
                ["receipt.json"],
            )

    def test_atomic_output_rejects_existing_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            real = root / "real.json"
            real.write_text("unchanged", encoding="utf-8")
            link = root / "receipt.json"
            link.symlink_to(real)
            with self.assertRaisesRegex(MODULE.UsageReceiptError, "must not be a symlink"):
                MODULE._write_atomic(link, b"replacement")
            self.assertEqual(real.read_text(encoding="utf-8"), "unchanged")


if __name__ == "__main__":
    unittest.main()
