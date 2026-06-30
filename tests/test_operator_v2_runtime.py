from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
import urllib.parse
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


def _load_grabowski_mcp():
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    module_name = "grabowski_mcp_operator_v2_test"
    spec = importlib.util.spec_from_file_location(
        module_name,
        ROOT / "src" / "grabowski_mcp.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load grabowski_mcp")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(
        sys.modules,
        {
            "mcp": fake_mcp,
            "mcp.server": fake_server,
            "mcp.server.fastmcp": fake_fastmcp,
            "mcp.types": fake_types,
            module_name: module,
        },
        clear=False,
    ):
        spec.loader.exec_module(module)
    return module


grabowski_mcp = _load_grabowski_mcp()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _state_text(root: Path) -> str:
    chunks: list[str] = []
    for path in root.rglob("*"):
        if path.is_file():
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


class OperatorV2RuntimeTests(unittest.TestCase):
    def _policy(
        self,
        path: Path,
        work: Path,
        excluded: Path,
        secret: Path,
        browser: Path,
        export: Path,
        *,
        capabilities: list[str] | None = None,
        max_read_bytes: int = 2_000_000,
    ) -> None:
        read_root = str(work)
        write_root = str(work)
        excluded_root = str(excluded)
        secret_root = str(secret)
        browser_root = str(browser)
        export_root = str(export)
        caps = capabilities or [
            "file_read",
            "file_write",
            "audit_verify",
            "rollback_text",
            "bundle_registry",
            "secret_inspect",
            "secret_reveal",
            "secret_use",
            "secret_export",
            "browser_profile_read",
        ]
        path.write_text(
            json.dumps(
                {
                    "version": 2,
                    "mode": "test",
                    "active_profile": "test",
                    "read_roots": [read_root],
                    "write_roots": [write_root],
                    "write_excluded_roots": [excluded_root],
                    "secret_roots": [secret_root],
                    "browser_profile_roots": [browser_root],
                    "secret_export_roots": [export_root],
                    "max_read_bytes": max_read_bytes,
                    "max_write_bytes": 2_000_000,
                    "max_list_entries": 500,
                    "max_secret_use_output_bytes": 250_000,
                    "max_secret_use_seconds": 30,
                    "forbid_symlinks": True,
                    "forbidden_components": [".git"],
                    "forbidden_file_patterns": [".env", "*.key"],
                    "forbidden_capabilities": [],
                    "profiles": {
                        "test": {
                            "description": "isolated test profile",
                            "read_roots": [read_root],
                            "write_roots": [write_root],
                            "write_excluded_roots": [excluded_root],
                            "secret_roots": [secret_root],
                            "browser_profile_roots": [browser_root],
                            "secret_export_roots": [export_root],
                            "max_read_bytes": max_read_bytes,
                            "max_write_bytes": 2_000_000,
                            "max_list_entries": 500,
                            "max_secret_use_output_bytes": 250_000,
                            "max_secret_use_seconds": 30,
                            "capabilities": caps,
                        }
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def _patched_runtime(
        self,
        root: Path,
        *,
        capabilities: list[str] | None = None,
        max_read_bytes: int = 2_000_000,
    ):
        work = root / "work"
        excluded = work / "merges"
        secret = work / ".ssh"
        browser = work / "browser"
        export = work / "secret-exports"
        state = root / "state"
        work.mkdir()
        excluded.mkdir()
        secret.mkdir()
        browser.mkdir()
        export.mkdir()
        state.mkdir()
        policy = root / "access.json"
        self._policy(
            policy,
            work,
            excluded,
            secret,
            browser,
            export,
            capabilities=capabilities,
            max_read_bytes=max_read_bytes,
        )
        return (
            work,
            secret,
            browser,
            export,
            state,
            patch.object(grabowski_mcp, "POLICY_PATH", policy),
            patch.object(grabowski_mcp, "STATE_DIR", state),
            patch.object(grabowski_mcp, "AUDIT_LOG", state / "write-audit.jsonl"),
            patch.object(grabowski_mcp, "QUARANTINE_DIR", state / "quarantine"),
            patch.object(
                grabowski_mcp,
                "KILL_SWITCH_PATH",
                state / "operator-kill-switch",
            ),
        )

    def test_v1_policy_loads_and_v2_validation_is_strict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"
            work.mkdir()
            policy = root / "access.json"
            legacy = {
                "version": 1,
                "mode": "legacy",
                "read_roots": [str(work)],
                "write_roots": [str(work)],
                "write_excluded_roots": [],
                "max_read_bytes": 1000,
                "max_write_bytes": 1000,
                "max_list_entries": 50,
                "forbid_symlinks": True,
                "forbidden_components": [".git"],
                "forbidden_file_patterns": [".env"],
                "forbidden_capabilities": ["secret_read"],
            }
            policy.write_text(json.dumps(legacy) + "\n", encoding="utf-8")
            with patch.object(grabowski_mcp, "POLICY_PATH", policy):
                loaded = grabowski_mcp._load_policy()
                self.assertEqual(loaded["version"], 1)

            strict = {
                **legacy,
                "version": 2,
                "secret_roots": [],
                "browser_profile_roots": [],
                "secret_export_roots": [],
                "max_secret_use_output_bytes": 1000,
                "max_secret_use_seconds": 1,
                "profiles": {
                    "strict": {
                        "description": "strict profile",
                        "read_roots": [str(work)],
                        "write_roots": [str(work)],
                        "write_excluded_roots": [],
                        "secret_roots": [],
                        "browser_profile_roots": [],
                        "secret_export_roots": [],
                        "capabilities": ["file_read"],
                    }
                },
                "active_profile": "strict",
            }
            for mutation, pattern in (
                ({"unexpected": True}, "Unknown access policy fields"),
                (
                    {"profiles": {"strict": {**strict["profiles"]["strict"], "capabilities": ["file_read", "file_read"]}}},
                    "duplicates",
                ),
                (
                    {"profiles": {"strict": {**strict["profiles"]["strict"], "capabilities": ["not_real"]}}},
                    "Unknown access capabilities",
                ),
                ({"max_read_bytes": 0}, "Invalid access policy limit"),
                ({"active_profile": "missing"}, "Active access profile is not defined"),
                (
                    {"profiles": {"strict": {**strict["profiles"]["strict"], "forbid_symlinks": False}}},
                    "Unknown access profile fields",
                ),
            ):
                bad = {**strict, **mutation}
                policy.write_text(json.dumps(bad) + "\n", encoding="utf-8")
                with patch.object(grabowski_mcp, "POLICY_PATH", policy):
                    with self.assertRaisesRegex(RuntimeError, pattern):
                        grabowski_mcp._load_policy()

            legacy_with_v2 = {**legacy, "secret_roots": []}
            policy.write_text(json.dumps(legacy_with_v2) + "\n", encoding="utf-8")
            with patch.object(grabowski_mcp, "POLICY_PATH", policy):
                with self.assertRaisesRegex(RuntimeError, "require version 2"):
                    grabowski_mcp._load_policy()

    def test_audit_chain_rejects_unhashed_record_after_v2_transition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _work, _secret, _browser, _export, state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                audit = state / "write-audit.jsonl"
                legacy = {"operation": "legacy", "timestamp": "before-v2"}
                audit.write_text(
                    json.dumps(legacy, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                grabowski_mcp._append_audit(
                    {"operation": "v2-transition", "path": "/test"}
                )
                valid = grabowski_mcp._verify_audit_log(audit)
                self.assertTrue(valid["valid"])
                self.assertEqual(valid["legacy_records"], 1)
                self.assertEqual(valid["v2_records"], 1)

                with audit.open("a", encoding="utf-8") as handle:
                    handle.write(
                        json.dumps(
                            {"operation": "unauthenticated-tail"},
                            sort_keys=True,
                        )
                        + "\n"
                    )
                invalid = grabowski_mcp._verify_audit_log(audit)
                self.assertFalse(invalid["valid"])
                self.assertEqual(
                    invalid["error"],
                    "line-3:legacy-record-after-v2",
                )
                with self.assertRaisesRegex(
                    RuntimeError,
                    "legacy-record-after-v2",
                ):
                    grabowski_mcp._require_valid_audit_chain()

    def test_replace_quarantines_preimage_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                target = work / "note.txt"
                target.write_text("before\n", encoding="utf-8")
                before = _sha256(target)

                record = grabowski_mcp.grabowski_replace_text(
                    str(target),
                    "after\n",
                    before,
                )

                self.assertEqual(target.read_text(encoding="utf-8"), "after\n")
                quarantine = Path(record["quarantine"]["preimage_path"])
                self.assertTrue(quarantine.is_file())
                self.assertEqual(_sha256(quarantine), before)
                self.assertTrue(grabowski_mcp.grabowski_verify_audit()["valid"])

                rollback = grabowski_mcp.grabowski_rollback_text(
                    record["transaction_id"],
                )

                self.assertEqual(target.read_text(encoding="utf-8"), "before\n")
                self.assertEqual(
                    rollback["rolled_back_transaction_id"],
                    record["transaction_id"],
                )
                self.assertEqual(
                    grabowski_mcp.grabowski_verify_audit()["v2_records"],
                    2,
                )

    def test_reversible_remove_quarantines_and_restores_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capabilities = [
                "file_read",
                "file_write",
                "file_delete",
                "audit_verify",
                "rollback_text",
                "bundle_registry",
            ]
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(
                root,
                capabilities=capabilities,
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                target = work / "remove-me.txt"
                target.write_text("remove me\n", encoding="utf-8")
                before = _sha256(target)

                record = grabowski_mcp.grabowski_remove_path(
                    str(target),
                    "file",
                    before,
                )

                self.assertFalse(target.exists())
                self.assertEqual(record["path_type"], "file")
                self.assertEqual(
                    record["rollback"]["tool"],
                    "grabowski_restore_removed_path",
                )
                quarantine = Path(record["quarantine"]["preimage_path"])
                self.assertTrue(quarantine.is_file())
                self.assertEqual(_sha256(quarantine), before)
                self.assertTrue(grabowski_mcp.grabowski_verify_audit()["valid"])

                restored = grabowski_mcp.grabowski_restore_removed_path(
                    record["transaction_id"],
                )

                self.assertEqual(target.read_text(encoding="utf-8"), "remove me\n")
                self.assertEqual(restored["after_sha256"], before)
                self.assertEqual(
                    restored["restored_transaction_id"],
                    record["transaction_id"],
                )
                self.assertEqual(
                    grabowski_mcp.grabowski_verify_audit()["v2_records"],
                    2,
                )

    def test_reversible_remove_handles_empty_directory_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capabilities = [
                "file_read",
                "file_write",
                "file_delete",
                "audit_verify",
                "rollback_text",
                "bundle_registry",
            ]
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(
                root,
                capabilities=capabilities,
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                empty = work / "empty"
                empty.mkdir()
                record = grabowski_mcp.grabowski_remove_path(
                    str(empty),
                    "empty_directory",
                )
                self.assertFalse(empty.exists())
                restored = grabowski_mcp.grabowski_restore_removed_path(
                    record["transaction_id"],
                )
                self.assertTrue(empty.is_dir())
                self.assertEqual(restored["path_type"], "empty_directory")

                nonempty = work / "nonempty"
                nonempty.mkdir()
                (nonempty / "child.txt").write_text("child\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "not empty"):
                    grabowski_mcp.grabowski_remove_path(
                        str(nonempty),
                        "empty_directory",
                    )

    def test_remove_reuses_write_guards_for_sensitive_excluded_and_protected_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capabilities = [
                "file_read",
                "file_write",
                "file_delete",
                "audit_verify",
                "rollback_text",
                "bundle_registry",
            ]
            work, secret, browser, _export, _state, *patches = self._patched_runtime(
                root,
                capabilities=capabilities,
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                secret_file = secret / "token.txt"
                secret_file.write_text("secret\n", encoding="utf-8")
                browser_file = browser / "prefs.js"
                browser_file.write_text("prefs\n", encoding="utf-8")
                excluded_file = work / "merges" / "proof.txt"
                excluded_file.write_text("proof\n", encoding="utf-8")
                protected_state = work / "operator-state"
                protected_state.mkdir()
                protected_file = protected_state / "state.txt"
                protected_file.write_text("state\n", encoding="utf-8")

                with self.assertRaisesRegex(PermissionError, "secret/browser"):
                    grabowski_mcp.grabowski_remove_path(
                        str(secret_file),
                        "file",
                        _sha256(secret_file),
                    )
                with self.assertRaisesRegex(PermissionError, "secret/browser"):
                    grabowski_mcp.grabowski_remove_path(
                        str(browser_file),
                        "file",
                        _sha256(browser_file),
                    )
                with self.assertRaisesRegex(PermissionError, "read-only"):
                    grabowski_mcp.grabowski_remove_path(
                        str(excluded_file),
                        "file",
                        _sha256(excluded_file),
                    )
                with patch.object(grabowski_mcp, "STATE_DIR", protected_state):
                    with self.assertRaisesRegex(PermissionError, "protected"):
                        grabowski_mcp.grabowski_remove_path(
                            str(protected_file),
                            "file",
                            _sha256(protected_file),
                        )

    def test_destroy_path_requires_separate_capability_and_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                target = work / "denied.txt"
                target.write_text("denied\n", encoding="utf-8")
                with self.assertRaisesRegex(PermissionError, "not enabled"):
                    grabowski_mcp.grabowski_destroy_path(
                        str(target),
                        "file",
                        "permanently-delete",
                        _sha256(target),
                    )
                self.assertTrue(target.exists())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capabilities = [
                "file_read",
                "file_write",
                "file_destroy",
                "audit_verify",
                "rollback_text",
                "bundle_registry",
            ]
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(
                root,
                capabilities=capabilities,
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                target = work / "destroy-me.txt"
                target.write_text("destroy me\n", encoding="utf-8")
                before = _sha256(target)

                with self.assertRaisesRegex(ValueError, "confirmation"):
                    grabowski_mcp.grabowski_destroy_path(
                        str(target),
                        "file",
                        "delete",
                        before,
                    )
                with self.assertRaisesRegex(RuntimeError, "precondition failed"):
                    grabowski_mcp.grabowski_destroy_path(
                        str(target),
                        "file",
                        "permanently-delete",
                        "0" * 64,
                    )

                record = grabowski_mcp.grabowski_destroy_path(
                    str(target),
                    "file",
                    "permanently-delete",
                    before,
                )

                self.assertFalse(target.exists())
                self.assertEqual(record["capability"], "file_destroy")
                self.assertFalse(record["rollback"]["available"])
                self.assertTrue(grabowski_mcp.grabowski_verify_audit()["valid"])

    def test_kill_switch_blocks_filesystem_removal_tools(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capabilities = [
                "file_read",
                "file_write",
                "file_delete",
                "file_destroy",
                "audit_verify",
                "rollback_text",
                "bundle_registry",
            ]
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(
                root,
                capabilities=capabilities,
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                remove_target = work / "remove.txt"
                destroy_target = work / "destroy.txt"
                remove_target.write_text("remove\n", encoding="utf-8")
                destroy_target.write_text("destroy\n", encoding="utf-8")
                grabowski_mcp.KILL_SWITCH_PATH.write_text("stop\n", encoding="utf-8")

                with self.assertRaisesRegex(PermissionError, "kill switch"):
                    grabowski_mcp.grabowski_remove_path(
                        str(remove_target),
                        "file",
                        _sha256(remove_target),
                    )
                with self.assertRaisesRegex(PermissionError, "kill switch"):
                    grabowski_mcp.grabowski_destroy_path(
                        str(destroy_target),
                        "file",
                        "permanently-delete",
                        _sha256(destroy_target),
                    )
                self.assertTrue(remove_target.exists())
                self.assertTrue(destroy_target.exists())

    def test_generic_tools_cannot_cross_secret_or_browser_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, secret, browser, _export, _state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                secret_file = secret / "token.txt"
                browser_file = browser / "prefs.js"
                secret_file.write_text("plain-secret-value\n", encoding="utf-8")
                browser_file.write_text("user_pref('x', true);\n", encoding="utf-8")

                listing = grabowski_mcp.grabowski_list_directory(str(work))
                entry_types = {entry["name"]: entry["type"] for entry in listing["entries"]}
                self.assertEqual(entry_types[".ssh"], "secret-root")
                self.assertEqual(entry_types["browser"], "browser-profile-root")

                for tool in (
                    grabowski_mcp.grabowski_read_text,
                    grabowski_mcp.grabowski_stat,
                ):
                    with self.assertRaisesRegex(PermissionError, "secret/browser"):
                        tool(str(secret_file))
                    with self.assertRaisesRegex(PermissionError, "secret/browser"):
                        tool(str(browser_file))

                with self.assertRaisesRegex(PermissionError, "secret/browser"):
                    grabowski_mcp.grabowski_create_text(
                        str(secret / "created.txt"),
                        "no\n",
                    )
                with self.assertRaisesRegex(PermissionError, "secret/browser"):
                    grabowski_mcp.grabowski_create_text(
                        str(browser / "created.txt"),
                        "no\n",
                    )

    def test_secret_inspect_and_reveal_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _work, secret, _browser, _export, state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                secret_value = "plain-secret-value-12345"
                target = secret / "token.txt"
                target.write_text(secret_value + "\n", encoding="utf-8")
                source_sha = _sha256(target)

                directory = grabowski_mcp.grabowski_secret_inspect(str(secret))
                self.assertEqual(directory["entries"][0]["name"], "token.txt")
                inspect = grabowski_mcp.grabowski_secret_inspect(str(target))
                self.assertEqual(inspect["sha256"], source_sha)
                self.assertFalse(inspect["content_returned"])
                self.assertNotIn(secret_value, json.dumps(inspect))

                with self.assertRaisesRegex(RuntimeError, "precondition failed"):
                    grabowski_mcp.grabowski_secret_reveal(str(target), "0" * 64)
                with self.assertRaisesRegex(PermissionError, "acknowledgement"):
                    grabowski_mcp.grabowski_secret_reveal(str(target), source_sha)
                reveal = grabowski_mcp.grabowski_secret_reveal(
                    str(target), source_sha,
                    justification="Need raw value for explicit diagnostic comparison",
                    acknowledge_context_exposure=True,
                )
                self.assertEqual(reveal["text"], secret_value + "\n")
                self.assertNotIn(secret_value, _state_text(state))

                outside = root / "outside.txt"
                outside.write_text("outside\n", encoding="utf-8")
                link = secret / "link.txt"
                link.symlink_to(outside)
                with self.assertRaisesRegex(PermissionError, "Symlink"):
                    grabowski_mcp.grabowski_secret_reveal(str(link), source_sha)

                hardlink = secret / "hardlink.txt"
                os.link(target, hardlink)
                with self.assertRaisesRegex(PermissionError, "Hard-linked"):
                    grabowski_mcp.grabowski_secret_reveal(str(target), source_sha)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _work, secret, _browser, _export, _state, *patches = self._patched_runtime(
                root,
                max_read_bytes=8,
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                oversized = secret / "oversized.txt"
                oversized.write_text("more-than-eight\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "exceeds byte limit"):
                    grabowski_mcp.grabowski_secret_reveal(
                        str(oversized),
                        _sha256(oversized),
                    )
                binary = secret / "binary.txt"
                binary.write_bytes(b"a\x00b")
                with self.assertRaisesRegex(ValueError, "Binary"):
                    grabowski_mcp.grabowski_secret_reveal(
                        str(binary),
                        _sha256(binary),
                    )

    def test_secret_use_consumes_secret_without_leaking_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, secret, _browser, _export, state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                secret_value = "plain-secret-use-value-12345!"
                source = secret / "token.txt"
                source.write_text(secret_value, encoding="utf-8")
                source_sha = _sha256(source)
                script = (
                    "import base64, os, sys, urllib.parse; "
                    "data=open(sys.argv[1], 'rb').read(); "
                    "text=data.decode(); "
                    "print(text); "
                    "print(base64.b64encode(data).decode()); "
                    "print(base64.urlsafe_b64encode(data).decode().rstrip('=')); "
                    "print(urllib.parse.quote_from_bytes(data, safe='')); "
                    "print('argv_has_value=' + str(text in '\\0'.join(sys.argv))); "
                    "print('env_has_value=' + str(any(text in v for v in os.environ.values()))); "
                    "print(text, file=sys.stderr)"
                )

                result = grabowski_mcp.grabowski_secret_use(
                    str(source),
                    source_sha,
                    [sys.executable, "-c", script, "{SECRET_FD_PATH}"],
                    cwd=str(work),
                )

                encoded = base64.b64encode(secret_value.encode()).decode()
                urlsafe = base64.urlsafe_b64encode(secret_value.encode()).decode().rstrip("=")
                quoted = urllib.parse.quote_from_bytes(secret_value.encode(), safe="")
                self.assertEqual(result["returncode"], 0)
                self.assertIn("<REDACTED>", result["stdout"])
                self.assertIn("<REDACTED>", result["stderr"])
                for leaked in (secret_value, encoded, urlsafe, quoted):
                    self.assertNotIn(leaked, result["stdout"])
                    self.assertNotIn(leaked, result["stderr"])
                    self.assertNotIn("argv", result)
                    self.assertNotIn(leaked, _state_text(state))
                self.assertIn("argv_has_value=False", result["stdout"])
                self.assertIn("env_has_value=False", result["stdout"])
                self.assertTrue(grabowski_mcp.grabowski_verify_audit()["valid"])

    def test_secret_use_rejects_shell_and_cleans_temp_fallback_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, secret, _browser, _export, state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                source = secret / "token.txt"
                source.write_text("temp-cleanup-secret", encoding="utf-8")
                source_sha = _sha256(source)

                with self.assertRaisesRegex(PermissionError, "shell"):
                    grabowski_mcp.grabowski_secret_use(
                        str(source),
                        source_sha,
                        ["sh", "-c", "cat {SECRET_FD_PATH}"],
                        cwd=str(work),
                    )
                with self.assertRaisesRegex(ValueError, "not a shell string"):
                    grabowski_mcp.grabowski_secret_use(
                        str(source),
                        source_sha,
                        "cat {SECRET_FD_PATH}",  # type: ignore[arg-type]
                        cwd=str(work),
                    )

                with (
                    patch.object(grabowski_mcp.os, "memfd_create", None, create=True),
                    patch.object(
                        grabowski_mcp.subprocess,
                        "Popen",
                        side_effect=OSError("spawn failed"),
                    ),
                ):
                    with self.assertRaisesRegex(OSError, "spawn failed"):
                        grabowski_mcp.grabowski_secret_use(
                            str(source),
                            source_sha,
                            [sys.executable, "-c", "pass", "{SECRET_FD_PATH}"],
                            cwd=str(work),
                        )
                temp_root = state / "secret-use"
                self.assertTrue(not temp_root.exists() or not list(temp_root.iterdir()))

                with patch.object(grabowski_mcp.os, "memfd_create", None, create=True):
                    timeout = grabowski_mcp.grabowski_secret_use(
                        str(source),
                        source_sha,
                        [
                            sys.executable,
                            "-c",
                            "import time, sys; open(sys.argv[1]).read(); time.sleep(2)",
                            "{SECRET_FD_PATH}",
                        ],
                        cwd=str(work),
                        timeout_seconds=1,
                    )
                self.assertTrue(timeout["timed_out"])
                self.assertTrue(not temp_root.exists() or not list(temp_root.iterdir()))

    def test_secret_export_is_hash_bound_local_create_only_and_audited(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _work, secret, _browser, export, state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                secret_value = "export-secret-value-12345"
                source = secret / "config"
                source.write_text(secret_value, encoding="utf-8")
                source_sha = _sha256(source)
                destination = export / "config.copy"

                with self.assertRaisesRegex(RuntimeError, "precondition failed"):
                    grabowski_mcp.grabowski_secret_export(
                        str(source),
                        str(destination),
                        "0" * 64,
                    )
                with self.assertRaisesRegex(ValueError, "local filesystem"):
                    grabowski_mcp.grabowski_secret_export(
                        str(source),
                        "sftp://host/config",
                        source_sha,
                    )
                with self.assertRaisesRegex(PermissionError, "export roots"):
                    grabowski_mcp.grabowski_secret_export(
                        str(source),
                        str(root / "outside.copy"),
                        source_sha,
                    )

                result = grabowski_mcp.grabowski_secret_export(
                    str(source),
                    str(destination),
                    source_sha,
                )
                self.assertEqual(result["source_sha256"], source_sha)
                self.assertNotIn(secret_value, json.dumps(result))
                self.assertEqual(destination.read_text(encoding="utf-8"), secret_value)
                self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
                self.assertNotIn(secret_value, _state_text(state))
                with self.assertRaisesRegex(FileExistsError, "overwrite"):
                    grabowski_mcp.grabowski_secret_export(
                        str(source),
                        str(destination),
                        source_sha,
                    )

    def test_browser_profile_read_text_and_binary_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _work, _secret, browser, _export, _state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                prefs = browser / "prefs.js"
                prefs.write_text("user_pref('browser.startup.page', 1);\n", encoding="utf-8")
                cookies = browser / "Cookies"
                cookies.write_bytes(b"SQLite format 3\x00secret-cookie")

                listing = grabowski_mcp.grabowski_browser_profile_read(str(browser))
                self.assertEqual(listing["returned"], 2)
                prefs_result = grabowski_mcp.grabowski_browser_profile_read(str(prefs))
                self.assertTrue(prefs_result["content_returned"])
                self.assertIn("browser.startup.page", prefs_result["text"])
                cookies_result = grabowski_mcp.grabowski_browser_profile_read(str(cookies))
                self.assertFalse(cookies_result["content_returned"])
                self.assertIn("sha256", cookies_result)
                self.assertNotIn("secret-cookie", json.dumps(cookies_result))

    def test_secret_use_rejects_secret_variants_in_argv_and_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, secret, _browser, _export, _state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                value = "variant-secret-value-12345"
                source = secret / "token.txt"
                source.write_text(value, encoding="utf-8")
                source_sha = _sha256(source)
                encoded = base64.b64encode(value.encode()).decode()

                with self.assertRaisesRegex(PermissionError, "argv"):
                    grabowski_mcp.grabowski_secret_use(
                        str(source),
                        source_sha,
                        [sys.executable, "-c", "pass", "{SECRET_FD_PATH}", encoded],
                        cwd=str(work),
                    )
                with self.assertRaisesRegex(PermissionError, "environment"):
                    grabowski_mcp.grabowski_secret_use(
                        str(source),
                        source_sha,
                        [sys.executable, "-c", "pass", "{SECRET_FD_PATH}"],
                        cwd=str(work),
                        environment={"LANG": encoded},
                    )
                with patch.dict(os.environ, {"LANG": encoded}):
                    with self.assertRaisesRegex(PermissionError, "environment"):
                        grabowski_mcp.grabowski_secret_use(
                            str(source),
                            source_sha,
                            [sys.executable, "-c", "pass", "{SECRET_FD_PATH}"],
                            cwd=str(work),
                        )

    def test_secret_use_blocks_combined_shell_flags_and_env_to_shell(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, secret, _browser, _export, _state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                source = secret / "token.txt"
                source.write_text("shell-guard-secret", encoding="utf-8")
                source_sha = _sha256(source)
                with self.assertRaisesRegex(PermissionError, "shell"):
                    grabowski_mcp.grabowski_secret_use(
                        str(source),
                        source_sha,
                        ["sh", "-ec", "cat {SECRET_FD_PATH}"],
                        cwd=str(work),
                    )
                with self.assertRaisesRegex(PermissionError, "env-to-shell"):
                    grabowski_mcp.grabowski_secret_use(
                        str(source),
                        source_sha,
                        ["env", "LANG=C", "sh", "-c", "cat {SECRET_FD_PATH}"],
                        cwd=str(work),
                    )

    def test_secret_use_bounds_child_output_while_draining(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, secret, _browser, _export, _state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                source = secret / "token.txt"
                source.write_text("output-secret", encoding="utf-8")
                source_sha = _sha256(source)
                script = "import sys; sys.stdout.write('x' * 200000); sys.stderr.write('y' * 200000)"
                result = grabowski_mcp.grabowski_secret_use(
                    str(source),
                    source_sha,
                    [sys.executable, "-c", script, "{SECRET_FD_PATH}"],
                    cwd=str(work),
                    max_output_bytes=128,
                )
                self.assertEqual(result["returncode"], 0)
                self.assertTrue(result["stdout_truncated"])
                self.assertTrue(result["stderr_truncated"])
                self.assertLessEqual(len(result["stdout"].encode()), 160)
                self.assertLessEqual(len(result["stderr"].encode()), 160)

    def test_secret_reveal_writes_value_free_audit_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _work, secret, _browser, _export, state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                value = "audited-reveal-secret-12345"
                source = secret / "token.txt"
                source.write_text(value, encoding="utf-8")
                result = grabowski_mcp.grabowski_secret_reveal(
                    str(source), _sha256(source),
                    justification="Verify value-free reveal audit evidence",
                    acknowledge_context_exposure=True,
                )
                self.assertIn("audit_record_sha256", result)
                records = grabowski_mcp._audit_records()
                self.assertEqual(records[-1]["operation"], "secret-reveal")
                self.assertEqual(records[-1]["capability"], "secret_reveal")
                self.assertIn("postflight", records[-1])
                self.assertNotIn(value, _state_text(state))

    def test_secret_reveal_requires_valid_audit_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _work, secret, _browser, _export, _state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                source = secret / "token.txt"
                source.write_text("chain-guard-secret", encoding="utf-8")
                grabowski_mcp.AUDIT_LOG.write_text("not-json\n", encoding="utf-8")

                with self.assertRaisesRegex(RuntimeError, "Audit log verification failed"):
                    grabowski_mcp.grabowski_secret_reveal(str(source), _sha256(source))

    def test_browser_profile_read_redacts_sensitive_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _work, _secret, browser, _export, _state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                prefs = browser / "prefs.js"
                prefs.write_text("token=" + "Bearer " + "abcdefghijkl" + "mnopqrstuvwxyz" + "\n", encoding="utf-8")
                result = grabowski_mcp.grabowski_browser_profile_read(str(prefs))
                self.assertTrue(result["content_returned"])
                self.assertIn("<REDACTED>", result["text"])
                self.assertNotIn("abcdefghijklmnopqrstuvwxyz", result["text"])

    def test_secret_export_removes_new_target_when_postflight_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _work, secret, _browser, export, _state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                source = secret / "config"
                source.write_text("cleanup-secret", encoding="utf-8")
                destination = export / "copy"
                original = grabowski_mcp._read_bound_regular_bytes

                def failing_read(path: Path, max_bytes: int) -> dict[str, object]:
                    result = original(path, max_bytes)
                    if path == destination:
                        result = {**result, "sha256": "0" * 64}
                    return result

                with patch.object(grabowski_mcp, "_read_bound_regular_bytes", side_effect=failing_read):
                    with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
                        grabowski_mcp.grabowski_secret_export(
                            str(source),
                            str(destination),
                            _sha256(source),
                        )
                self.assertFalse(destination.exists())

    def test_kill_switch_blocks_use_and_export_but_not_secret_reads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, secret, _browser, export, _state, *patches = self._patched_runtime(root)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                source = secret / "token.txt"
                source.write_text("kill-switch-secret", encoding="utf-8")
                source_sha = _sha256(source)
                grabowski_mcp.KILL_SWITCH_PATH.write_text("stop\n", encoding="utf-8")

                self.assertEqual(
                    grabowski_mcp.grabowski_secret_inspect(str(source))["sha256"],
                    source_sha,
                )
                self.assertEqual(
                    grabowski_mcp.grabowski_secret_reveal(
                        str(source), source_sha,
                        justification="Confirm read path remains available during kill switch",
                        acknowledge_context_exposure=True,
                    )["text"],
                    "kill-switch-secret",
                )
                with self.assertRaisesRegex(PermissionError, "kill switch"):
                    grabowski_mcp.grabowski_secret_use(
                        str(source),
                        source_sha,
                        [sys.executable, "-c", "pass", "{SECRET_FD_PATH}"],
                        cwd=str(work),
                    )
                with self.assertRaisesRegex(PermissionError, "kill switch"):
                    grabowski_mcp.grabowski_secret_export(
                        str(source),
                        str(export / "copy"),
                        source_sha,
                    )

    def test_capability_denial_blocks_every_sensitive_tool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, secret, browser, export, _state, *patches = self._patched_runtime(
                root,
                capabilities=[
                    "file_read",
                    "file_write",
                    "audit_verify",
                    "rollback_text",
                    "bundle_registry",
                ],
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                source = secret / "token.txt"
                source.write_text("capability-secret", encoding="utf-8")
                browser_file = browser / "prefs.js"
                browser_file.write_text("prefs\n", encoding="utf-8")
                source_sha = _sha256(source)
                calls = [
                    lambda: grabowski_mcp.grabowski_secret_inspect(str(source)),
                    lambda: grabowski_mcp.grabowski_secret_reveal(str(source), source_sha),
                    lambda: grabowski_mcp.grabowski_secret_use(
                        str(source),
                        source_sha,
                        [sys.executable, "-c", "pass", "{SECRET_FD_PATH}"],
                        cwd=str(work),
                    ),
                    lambda: grabowski_mcp.grabowski_secret_export(
                        str(source),
                        str(export / "copy"),
                        source_sha,
                    ),
                    lambda: grabowski_mcp.grabowski_browser_profile_read(
                        str(browser_file)
                    ),
                ]
                for call in calls:
                    with self.assertRaisesRegex(PermissionError, "not enabled"):
                        call()


if __name__ == "__main__":
    unittest.main()
