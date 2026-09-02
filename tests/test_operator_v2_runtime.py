from __future__ import annotations

import ast
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
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeContext:
    pass


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
    fake_fastmcp.Context = _FakeContext
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


def _static_tool_guard_requirements() -> tuple[dict[str, tuple[str, ...]], set[str]]:
    guard_names = {
        "_require_capability",
        "_require_mutations_enabled",
        "_require_operator_capability",
        "_require_operator_mutation",
    }
    operator_guard_names = {
        "_require_operator_capability",
        "_require_operator_mutation",
    }
    requirements: dict[str, tuple[str, ...]] = {}
    operator_tools: set[str] = set()
    for path in sorted((ROOT / "src").glob("grabowski_*.py")):
        module = ast.parse(path.read_text(encoding="utf-8"))
        for node in module.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            tool_name = None
            for decorator in node.decorator_list:
                if not (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "tool"
                ):
                    continue
                for keyword in decorator.keywords:
                    if (
                        keyword.arg == "name"
                        and isinstance(keyword.value, ast.Constant)
                        and isinstance(keyword.value.value, str)
                    ):
                        tool_name = keyword.value.value
            if tool_name is None:
                continue
            capabilities = []
            has_operator_guard = False
            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue
                function = child.func
                function_name = (
                    function.id
                    if isinstance(function, ast.Name)
                    else function.attr
                    if isinstance(function, ast.Attribute)
                    else None
                )
                if (
                    function_name in guard_names
                    and child.args
                    and isinstance(child.args[0], ast.Constant)
                    and isinstance(child.args[0].value, str)
                ):
                    capabilities.append(child.args[0].value)
                    if function_name in operator_guard_names:
                        has_operator_guard = True
            requirements[tool_name] = tuple(sorted(set(capabilities)))
            if has_operator_guard:
                operator_tools.add(tool_name)
    return requirements, operator_tools


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
            "audit_read",
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
                    "allowed_grips": ["*"],
                    "forbidden_hosts": [],
                    "max_risk_level": "high",
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
                            "allowed_grips": ["*"],
                            "forbidden_hosts": [],
                            "max_risk_level": "high",
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
        state.mkdir(mode=0o700)
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
                        "allowed_grips": ["repo-orient"],
                        "forbidden_hosts": [],
                        "max_risk_level": "low",
                    }
                },
                "active_profile": "strict",
            }
            for mutation, pattern in (
                ({"unexpected": True}, "Unknown access policy fields"),
                (
                    {
                        "profiles": {
                            "strict": {
                                **strict["profiles"]["strict"],
                                "capabilities": ["file_read", "file_read"],
                            }
                        }
                    },
                    "duplicates",
                ),
                (
                    {
                        "profiles": {
                            "strict": {
                                **strict["profiles"]["strict"],
                                "capabilities": ["not_real"],
                            }
                        }
                    },
                    "Unknown access capabilities",
                ),
                ({"max_read_bytes": 0}, "Invalid access policy limit"),
                ({"active_profile": "missing"}, "Active access profile is not defined"),
                (
                    {
                        "profiles": {
                            "strict": {
                                **strict["profiles"]["strict"],
                                "allowed_grips": ["not-a-grip"],
                            }
                        }
                    },
                    "Unknown allowed grips",
                ),
                (
                    {
                        "profiles": {
                            "strict": {
                                **strict["profiles"]["strict"],
                                "forbidden_hosts": ["bad/host"],
                            }
                        }
                    },
                    "bare hostnames",
                ),
                (
                    {
                        "profiles": {
                            "strict": {
                                **strict["profiles"]["strict"],
                                "max_risk_level": "root",
                            }
                        }
                    },
                    "max_risk_level",
                ),
                (
                    {
                        "profiles": {
                            "strict": {
                                **strict["profiles"]["strict"],
                                "forbid_symlinks": False,
                            }
                        }
                    },
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

    def test_pre_t006_v2_profiles_project_session_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"
            work.mkdir()
            policy = root / "access.json"
            pre_t006 = {
                "version": 2,
                "mode": "test",
                "active_profile": "test",
                "read_roots": [str(work)],
                "write_roots": [str(work)],
                "write_excluded_roots": [],
                "secret_roots": [],
                "browser_profile_roots": [],
                "secret_export_roots": [],
                "max_read_bytes": 1000,
                "max_write_bytes": 1000,
                "max_list_entries": 50,
                "max_secret_use_output_bytes": 1000,
                "max_secret_use_seconds": 1,
                "forbid_symlinks": True,
                "forbidden_components": [".git"],
                "forbidden_file_patterns": [".env"],
                "forbidden_capabilities": [],
                "profiles": {
                    "test": {
                        "description": "pre-T006 profile",
                        "read_roots": [str(work)],
                        "write_roots": [str(work)],
                        "write_excluded_roots": [],
                        "secret_roots": [],
                        "browser_profile_roots": [],
                        "secret_export_roots": [],
                        "capabilities": ["file_read"],
                    }
                },
            }
            policy.write_text(json.dumps(pre_t006) + "\n", encoding="utf-8")
            with patch.object(grabowski_mcp, "POLICY_PATH", policy):
                loaded = grabowski_mcp._load_policy()
                contract = grabowski_mcp._session_profile_contract(loaded)

            self.assertEqual(contract["profile"], "test")
            self.assertEqual(contract["read_roots"], [str(work)])
            self.assertEqual(contract["write_roots"], [str(work)])
            self.assertEqual(contract["allowed_grips"], ["*"])
            self.assertEqual(contract["forbidden_hosts"], [])
            self.assertEqual(contract["max_risk_level"], "high")

    def test_session_profile_contract_and_grip_policy_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(
                root,
                capabilities=["file_read", "terminal_execute"],
            )
            policy = json.loads((root / "access.json").read_text(encoding="utf-8"))
            profile = policy["profiles"]["test"]
            profile["allowed_grips"] = ["repo-orient"]
            profile["max_risk_level"] = "low"
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patch.object(grabowski_mcp, "_load_policy", return_value=policy),
            ):
                contract = grabowski_mcp._session_profile_contract()
                self.assertEqual(contract["read_roots"], [str(work)])
                self.assertEqual(contract["write_roots"], [str(work)])
                self.assertEqual(contract["allowed_grips"], ["repo-orient"])
                self.assertEqual(contract["forbidden_hosts"], [])
                self.assertEqual(contract["max_risk_level"], "low")

                allowed = grabowski_mcp._session_grip_policy_decision(
                    "repo-orient",
                    {"repo": str(work)},
                )
                self.assertTrue(allowed["allowed"])
                self.assertEqual(allowed["risk"], "low")

                blocked_name = grabowski_mcp.grip_run(
                    "branch-publish",
                    {"repo": str(work), "branch": "x", "expected_head": "0" * 40},
                    profile="operator",
                    allow_mutation=True,
                )
                self.assertEqual(blocked_name["receipt"]["status"], "blocked")
                self.assertIn(
                    "session profile blocks grip", blocked_name["output"]["error"]
                )

                blocked_high = grabowski_mcp._session_grip_policy_decision(
                    "captain-run",
                    {"actions": []},
                )
                self.assertFalse(blocked_high["allowed_by_risk"])
                self.assertFalse(blocked_high["escalation_valid"])

    def test_grip_run_checks_capability_before_session_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(
                root,
                capabilities=["file_read"],
            )
            policy = json.loads((root / "access.json").read_text(encoding="utf-8"))
            policy["profiles"]["test"]["allowed_grips"] = ["repo-orient"]
            policy["profiles"]["test"]["max_risk_level"] = "low"
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patch.object(grabowski_mcp, "_load_policy", return_value=policy),
            ):
                with self.assertRaisesRegex(PermissionError, "terminal_execute"):
                    grabowski_mcp.grip_run(
                        "branch-publish",
                        {"repo": str(work), "branch": "x", "expected_head": "0" * 40},
                        profile="operator",
                        allow_mutation=True,
                    )

    def test_connector_snapshot_wrapper_injects_server_owned_binding(self) -> None:
        server_observed_tools = {
            "schema_version": 1,
            "tools": [
                "alpha",
                {
                    "name": "grabowski_bureau_candidate_assess",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "grabowski_secret_reveal",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "grabowski_task_start",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
        }
        client_parameters = {
            "client_id": "chatgpt-api-tool",
            "session_id": "session-1",
            "observed_tool_count": 140,
            "observed_names_sha256": "a" * 64,
            "observed_release_id": "release-real",
            "observed_agent_instructions_sha256": "b" * 64,
            "observed_tools": server_observed_tools,
        }
        deployment = {
            "release_id": "release-real",
            "repo_head": "c" * 40,
        }
        contract = {
            "registered_tool_count": 140,
            "registered_names_sha256": "a" * 64,
            "runtime_matches_deployment_contract": True,
        }
        with (
            patch.object(grabowski_mcp, "_require_capability"),
            patch.object(grabowski_mcp, "_require_mutations_enabled"),
            patch.object(
                grabowski_mcp,
                "_session_grip_policy_decision",
                return_value={"allowed": True},
            ),
            patch.object(
                grabowski_mcp,
                "_deployment_metadata",
                return_value=deployment,
            ),
            patch.object(
                grabowski_mcp,
                "_runtime_tool_contract_summary",
                return_value=contract,
            ) as summary,
            patch.object(
                grabowski_mcp,
                "_runtime_connector_observed_tools",
                return_value=server_observed_tools,
            ) as observed,
            patch.object(
                grabowski_mcp.grabowski_grips,
                "grip_run",
                return_value={"ok": True},
            ) as run,
        ):
            result = grabowski_mcp.grip_run(
                "connector-snapshot-bind",
                client_parameters,
                profile="operator",
                allow_mutation=True,
            )

        self.assertEqual({"ok": True}, result)
        summary.assert_called_once_with(deployment)
        observed.assert_called_once_with()
        dispatched = run.call_args.args[1]
        self.assertEqual(
            {
                "registered_tool_count": 140,
                "registered_names_sha256": "a" * 64,
                "runtime_matches_deployment_contract": True,
            },
            dispatched["_server_tool_contract"],
        )
        self.assertEqual(deployment, dispatched["_server_runtime"])
        self.assertEqual(
            grabowski_mcp.AGENT_INSTRUCTIONS_SHA256,
            dispatched["_server_agent_instructions_sha256"],
        )
        self.assertIs(
            server_observed_tools,
            dispatched["_server_observed_tools"],
        )

    def test_connector_snapshot_wrapper_rejects_server_binding_spoofing(self) -> None:
        public_parameters = {
            "client_id": "chatgpt-api-tool",
            "session_id": "session-1",
            "observed_tool_count": 140,
            "observed_names_sha256": "a" * 64,
            "observed_release_id": "release-real",
            "observed_agent_instructions_sha256": "b" * 64,
        }
        server_parameters = (
            "_server_tool_contract",
            "_server_runtime",
            "_server_agent_instructions_sha256",
            "_server_observed_tools",
        )
        for parameter in server_parameters:
            with self.subTest(parameter=parameter):
                with (
                    patch.object(grabowski_mcp, "_require_capability"),
                    patch.object(grabowski_mcp, "_require_mutations_enabled"),
                ):
                    result = grabowski_mcp.grip_run(
                        "connector-snapshot-bind",
                        {**public_parameters, parameter: {"spoofed": True}},
                        profile="operator",
                        allow_mutation=True,
                    )
                self.assertEqual("blocked", result["status"])
                self.assertIn(
                    f"caller supplied reserved server parameter: {parameter}",
                    result["output"]["error"],
                )

    def test_agent_execution_frontdoor_receives_server_runtime_actor_identity(self) -> None:
        class Session:
            pass

        class RequestContext:
            session = Session()

        decision = {
            "allowed": True,
            "session_profile": {"profile": "trusted-owner"},
        }
        with (
            patch.object(
                grabowski_mcp.grabowski_grips,
                "grip_required_capability",
                return_value="terminal_execute",
            ),
            patch.object(grabowski_mcp, "_require_mutations_enabled"),
            patch.object(
                grabowski_mcp,
                "_session_grip_policy_decision",
                return_value=decision,
            ),
            patch.object(
                grabowski_mcp.grabowski_grips,
                "grip_run",
                return_value={"ok": True},
            ) as run,
        ):
            result = grabowski_mcp.grip_run(
                "agent-execution-happy-path",
                {"base": "main", "title": "session actor"},
                allow_mutation=True,
                ctx=RequestContext(),
            )

        self.assertEqual({"ok": True}, result)
        dispatched = run.call_args.args[1]
        identity = dispatched["_server_runtime_actor_identity"]
        verified = grabowski_mcp.grabowski_merge_guard.verify_server_runtime_actor_identity(
            identity
        )
        self.assertTrue(verified["owner_id"].startswith("runtime-actor:"))

        with (
            patch.object(
                grabowski_mcp.grabowski_grips,
                "grip_required_capability",
                return_value="terminal_execute",
            ),
            patch.object(grabowski_mcp, "_require_mutations_enabled"),
            patch.object(
                grabowski_mcp,
                "_session_grip_policy_decision",
                return_value=decision,
            ),
            patch.object(grabowski_mcp.grabowski_grips, "grip_run") as blocked_run,
        ):
            blocked = grabowski_mcp.grip_run(
                "agent-execution-happy-path",
                {"base": "main", "title": "session actor"},
                allow_mutation=True,
                ctx=None,
            )
        self.assertEqual("blocked", blocked["receipt"]["status"])
        self.assertIn(
            "server runtime actor identity is unavailable", blocked["output"]["error"]
        )
        blocked_run.assert_not_called()

    def test_session_escalation_normalizes_only_exact_integral_json_floats(self) -> None:
        now = 1_000_000
        base = {
            "target": {"repo": "heimgewebe/grabowski"},
            "reason": "bounded transport normalization test",
            "recovery": {"plan": "no mutation in this unit test"},
        }
        with patch.object(grabowski_mcp.time, "time", return_value=now):
            integral = {**base, "expires_at_unix": float(now + 60)}
            grabowski_mcp._validate_session_escalation(integral)

            for invalid in (
                True,
                str(now + 60),
                float(now + 60) + 0.5,
                float("nan"),
                float("inf"),
                float("-inf"),
            ):
                with self.subTest(invalid=invalid):
                    with self.assertRaisesRegex(RuntimeError, "must be an integer"):
                        grabowski_mcp._validate_session_escalation(
                            {**base, "expires_at_unix": invalid}
                        )

            with self.assertRaisesRegex(RuntimeError, "is expired"):
                grabowski_mcp._validate_session_escalation(
                    {**base, "expires_at_unix": float(now - 1)}
                )
            with self.assertRaisesRegex(RuntimeError, "too far in the future"):
                grabowski_mcp._validate_session_escalation(
                    {
                        **base,
                        "expires_at_unix": float(
                            now + grabowski_mcp.SESSION_ESCALATION_MAX_SECONDS + 1
                        ),
                    }
                )

    def test_captain_transport_normalizes_only_contract_integer_fields(self) -> None:
        canonical = {
            "delay_seconds": 8,
            "actions": [
                {
                    "target": {"repo": "heimgewebe/bureau", "pr": 2237},
                    "scope": {"max_targets": 1},
                }
            ],
            "status_projection": {
                "schema_version": 1,
                "kind": "grabowski_pr_review_status_projection",
                "repo": "heimgewebe/bureau",
                "pr": 2237,
                "pull_request": 2237,
                "head_sha": "a" * 40,
                "base_sha": "b" * 40,
                "diff_sha256": "c" * 64,
                "audit_sha256": "d" * 64,
                "review_policy_version": 1,
                "gate_verdict": "PASS",
                "self_review_gate_valid": True,
                "all_findings_triaged": True,
                "material_findings_remaining": 0,
                "minimum_review_iterations": 5,
                "actual_review_iterations": 6,
                "review_tier": "high_critical",
                "tuning_signal": "observe",
                "unresolved_review_threads": 0,
                "measurement": 1.0,
            },
            "review_evidence": {
                "schema_version": 1,
                "kind": "grabowski_self_review_audit",
                "generated_at": "2026-09-02T20:00:00+00:00",
                "repo": "heimgewebe/bureau",
                "pr": 2237,
                "head_sha": "a" * 40,
                "base_sha": "b" * 40,
                "review_policy_version": 1,
                "diff_sha256": "c" * 64,
                "review_tier": "high_critical",
                "minimum_review_iterations": 5,
                "actual_review_iterations": 6,
                "all_findings_triaged": True,
                "finding_count": 1,
                "material_findings_after_first_review": 1,
                "material_findings_remaining": 0,
                "uncertainty": 0.25,
                "residual_risk_accepted": False,
                "residual_risk_reason": "",
                "gate_verdict": "PASS",
                "self_review_gate_valid": True,
                "tuning_signal": "observe",
            },
            "codex_review_evidence": {
                "schema_version": 1,
                "pr": 2237,
                "exit_code": 0,
                "finding_count": 18,
                "completion": {"comment_id": 5514070466, "review_id": None},
                "policy": {"minimum_self_review_iterations": 5},
            },
            "execution_intent": {
                "schema_version": 1,
                "context": {"pr": 1.0, "measurement": 2.0},
            },
        }

        def transported(value):
            if isinstance(value, bool):
                return value
            if isinstance(value, int):
                return float(value)
            if isinstance(value, list):
                return [transported(item) for item in value]
            if isinstance(value, dict):
                return {key: transported(item) for key, item in value.items()}
            return value

        normalized = grabowski_mcp._normalize_captain_transport_integer_fields(
            transported(canonical)
        )

        self.assertEqual(canonical, normalized)
        self.assertIsInstance(normalized["delay_seconds"], int)
        self.assertIsInstance(normalized["status_projection"]["measurement"], float)
        self.assertIsInstance(normalized["status_projection"]["pr"], int)
        self.assertIsInstance(normalized["status_projection"]["review_policy_version"], int)
        self.assertIsInstance(
            normalized["status_projection"]["material_findings_remaining"], int
        )
        self.assertIsInstance(normalized["actions"][0]["target"]["pr"], int)
        self.assertIsInstance(normalized["codex_review_evidence"]["finding_count"], int)
        self.assertIsInstance(normalized["review_evidence"]["review_policy_version"], int)
        self.assertIsInstance(
            normalized["review_evidence"]["material_findings_after_first_review"], int
        )
        self.assertIsInstance(normalized["review_evidence"]["uncertainty"], float)
        self.assertIsInstance(normalized["execution_intent"]["context"]["pr"], float)
        self.assertEqual(1.0, normalized["execution_intent"]["context"]["pr"])

        invalid = grabowski_mcp._normalize_captain_transport_integer_fields(
            {"pr": 2237.5, "schema_version": float("inf")}
        )
        self.assertEqual(2237.5, invalid["pr"])
        self.assertEqual(float("inf"), invalid["schema_version"])

    def test_captain_run_normalizes_transport_pr_before_dispatch(self) -> None:
        parameters = {
            "actions": [
                {
                    "action": "pr-merge",
                    "target": {
                        "repo": "heimgewebe/bureau",
                        "pr": 2237.0,
                        "base": "main",
                    },
                    "scope": {"max_targets": 1.0},
                }
            ],
            "status_projection": {
                "schema_version": 1.0,
                "pull_request": 2237.0,
                "measurement": 1.0,
            },
            "session_escalation": {
                "target": {"repo": "heimgewebe/bureau"},
                "reason": "bounded transport normalization test",
                "expires_at_unix": float(int(__import__("time").time()) + 60),
                "recovery": {"plan": "no mutation in this unit test"},
            },
        }

        class Session:
            pass

        class RequestContext:
            session = Session()

        decision = {
            "allowed": True,
            "session_profile": {"profile": "test"},
        }
        with (
            patch.object(grabowski_mcp, "_require_capability"),
            patch.object(
                grabowski_mcp.grabowski_grips,
                "grip_required_capability",
                return_value="terminal_execute",
            ),
            patch.object(
                grabowski_mcp, "_session_grip_policy_decision", return_value=decision
            ),
            patch.object(
                grabowski_mcp,
                "_captain_audit_intent",
                return_value={"audit_record_sha256": "a" * 64},
            ),
            patch.object(
                grabowski_mcp,
                "_captain_audit_completion",
                return_value={"audit_record_sha256": "b" * 64},
            ),
            patch.object(
                grabowski_mcp.grabowski_grips, "grip_run", return_value={"ok": True}
            ) as run,
        ):
            result = grabowski_mcp.grip_run(
                "captain-run", parameters, ctx=RequestContext()
            )

        self.assertEqual({"ok": True}, result)
        dispatched = run.call_args.args[1]
        self.assertEqual(2237, dispatched["actions"][0]["target"]["pr"])
        self.assertIsInstance(dispatched["actions"][0]["target"]["pr"], int)
        self.assertEqual(1, dispatched["actions"][0]["scope"]["max_targets"])
        self.assertIsInstance(dispatched["status_projection"]["measurement"], float)
        self.assertNotIn("session_escalation", dispatched)

    def test_high_risk_grip_requires_explicit_session_escalation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _work, _secret, _browser, _export, _state, *patches = self._patched_runtime(
                root,
                capabilities=["file_read", "terminal_execute"],
            )
            policy = json.loads((root / "access.json").read_text(encoding="utf-8"))
            policy["profiles"]["test"]["allowed_grips"] = ["captain-run"]
            policy["profiles"]["test"]["max_risk_level"] = "high"
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patch.object(grabowski_mcp, "_load_policy", return_value=policy),
            ):
                missing = grabowski_mcp._session_grip_policy_decision(
                    "captain-run", {"actions": []}
                )
                self.assertFalse(missing["allowed"])
                self.assertIn("session_escalation", missing["escalation_error"])

                valid_parameters = {
                    "actions": [],
                    "session_escalation": {
                        "target": {"repo": "heimgewebe/grabowski"},
                        "reason": "bounded test",
                        "expires_at_unix": int(__import__("time").time()) + 60,
                        "recovery": {"plan": "no mutation in this unit test"},
                    },
                }
                valid = grabowski_mcp._session_grip_policy_decision(
                    "captain-run",
                    valid_parameters,
                )
                self.assertTrue(valid["allowed"])

                transport_parameters = json.loads(json.dumps(valid_parameters))
                transport_parameters["session_escalation"]["expires_at_unix"] = float(
                    valid_parameters["session_escalation"]["expires_at_unix"]
                )
                transported = grabowski_mcp._session_grip_policy_decision(
                    "captain-run", transport_parameters
                )
                self.assertTrue(transported["allowed"])

                class Session:
                    pass

                class RequestContext:
                    session = Session()

                with patch.object(
                    grabowski_mcp.grabowski_grips, "grip_run", return_value={"ok": True}
                ) as run:
                    result = grabowski_mcp.grip_run(
                        "captain-run", transport_parameters, ctx=RequestContext()
                    )

                self.assertEqual(result, {"ok": True})
                dispatched = run.call_args.args[1]
                self.assertNotIn("session_escalation", dispatched)
                identity = dispatched.pop("_server_runtime_actor_identity")
                self.assertEqual(dispatched, {"actions": []})
                verified = grabowski_mcp.grabowski_merge_guard.verify_server_runtime_actor_identity(
                    identity
                )
                self.assertTrue(verified["owner_id"].startswith("runtime-actor:"))

                spoofed = dict(valid_parameters)
                spoofed["_server_runtime_actor_identity"] = identity
                with patch.object(
                    grabowski_mcp.grabowski_grips, "grip_run"
                ) as blocked_run:
                    blocked = grabowski_mcp.grip_run(
                        "captain-run", spoofed, ctx=RequestContext()
                    )
                self.assertEqual("blocked", blocked["receipt"]["status"])
                self.assertIn("reserved server parameter", blocked["output"]["error"])
                blocked_run.assert_not_called()

                task_id = "a" * 24
                task_owner = f"task:{task_id}"
                task_parameters = dict(valid_parameters)
                task_parameters["execution_intent"] = {
                    "context": {"lease_owner_id": task_owner}
                }
                task_keys = ["component:test-task"]
                task_binding = {
                    "task_id": task_id,
                    "lease_owner_id": task_owner,
                    "state": "running",
                    "attempt": 1,
                    "updated_at_unix": int(__import__("time").time()),
                    "resource_keys_sha256": (
                        grabowski_mcp.grabowski_merge_guard._sha256_json(task_keys)
                    ),
                    "lease_bindings_sha256": "b" * 64,
                }
                task_evidence = {
                    "schema_version": 1,
                    "kind": "grabowski_live_task_lease_delegation_evidence",
                    **task_binding,
                    "task_record_sha256": (
                        grabowski_mcp.grabowski_merge_guard._sha256_json(task_binding)
                    ),
                    "resource_keys": task_keys,
                    "minimum_expires_at_unix": int(__import__("time").time()) + 60,
                    "observed_at_unix": int(__import__("time").time()),
                }
                fake_tasks = types.SimpleNamespace(
                    server_task_lease_delegation_evidence=lambda owner: (
                        task_evidence if owner == task_owner else None
                    )
                )
                with (
                    patch.dict(sys.modules, {"grabowski_tasks": fake_tasks}),
                    patch.object(
                        grabowski_mcp.grabowski_grips,
                        "grip_run",
                        return_value={"ok": True},
                    ) as task_run,
                ):
                    task_result = grabowski_mcp.grip_run(
                        "captain-run", task_parameters, ctx=RequestContext()
                    )
                self.assertEqual({"ok": True}, task_result)
                task_dispatched = task_run.call_args.args[1]
                task_actor = task_dispatched["_server_runtime_actor_identity"]
                task_delegation = task_dispatched["_server_task_lease_delegation"]
                verified_task = grabowski_mcp.grabowski_merge_guard.verify_server_task_lease_delegation(
                    task_delegation,
                    actor_identity=task_actor,
                    captain_request_sha256_value=(
                        grabowski_mcp.grabowski_merge_guard.captain_request_sha256(
                            task_dispatched
                        )
                    ),
                )
                self.assertEqual(task_owner, verified_task["lease_owner_id"])

                spoofed_task = dict(task_parameters)
                spoofed_task["_server_task_lease_delegation"] = task_delegation
                blocked_task = grabowski_mcp.grip_run(
                    "captain-run", spoofed_task, ctx=RequestContext()
                )
                self.assertEqual("blocked", blocked_task["receipt"]["status"])
                self.assertIn(
                    "reserved server parameter", blocked_task["output"]["error"]
                )

                operator_owner = "operator:test-mcp-delegation"
                operator_parameters = dict(valid_parameters)
                operator_parameters["execution_intent"] = {
                    "context": {"lease_owner_id": operator_owner}
                }
                operator_keys = ["component:test-direct-operator"]
                observed_at = int(__import__("time").time())
                operator_snapshots = [
                    {
                        "resource_key": operator_keys[0],
                        "owner_id": operator_owner,
                        "acquired_at_unix": observed_at - 1,
                        "updated_at_unix": observed_at - 1,
                        "expires_at_unix": observed_at + 60,
                        "metadata_sha256": "c" * 64,
                    }
                ]
                operator_evidence = {
                    "schema_version": 1,
                    "kind": "grabowski_live_operator_lease_delegation_evidence",
                    "lease_owner_id": operator_owner,
                    "resource_keys": operator_keys,
                    "resource_keys_sha256": (
                        grabowski_mcp.grabowski_merge_guard._sha256_json(operator_keys)
                    ),
                    "lease_snapshots": operator_snapshots,
                    "lease_bindings_sha256": (
                        grabowski_mcp.grabowski_merge_guard._sha256_json(
                            operator_snapshots
                        )
                    ),
                    "minimum_expires_at_unix": observed_at + 60,
                    "observed_at_unix": observed_at,
                }
                fake_resources = types.SimpleNamespace(
                    operator_lease_delegation_evidence=lambda owner: (
                        operator_evidence if owner == operator_owner else None
                    )
                )
                with (
                    patch.dict(
                        sys.modules, {"grabowski_resources": fake_resources}
                    ),
                    patch.object(
                        grabowski_mcp.grabowski_grips,
                        "grip_run",
                        return_value={"ok": True},
                    ) as operator_run,
                ):
                    operator_result = grabowski_mcp.grip_run(
                        "captain-run", operator_parameters, ctx=RequestContext()
                    )
                self.assertEqual({"ok": True}, operator_result)
                operator_dispatched = operator_run.call_args.args[1]
                operator_actor = operator_dispatched[
                    "_server_runtime_actor_identity"
                ]
                operator_delegation = operator_dispatched[
                    "_server_operator_lease_delegation"
                ]
                verified_operator = (
                    grabowski_mcp.grabowski_merge_guard.verify_server_operator_lease_delegation(
                        operator_delegation,
                        actor_identity=operator_actor,
                        captain_request_sha256_value=(
                            grabowski_mcp.grabowski_merge_guard.captain_request_sha256(
                                operator_dispatched
                            )
                        ),
                    )
                )
                self.assertEqual(
                    operator_owner, verified_operator["lease_owner_id"]
                )

                spoofed_operator = dict(operator_parameters)
                spoofed_operator["_server_operator_lease_delegation"] = (
                    operator_delegation
                )
                blocked_operator = grabowski_mcp.grip_run(
                    "captain-run", spoofed_operator, ctx=RequestContext()
                )
                self.assertEqual(
                    "blocked", blocked_operator["receipt"]["status"]
                )
                self.assertIn(
                    "reserved server parameter",
                    blocked_operator["output"]["error"],
                )

                unavailable = grabowski_mcp.grip_run(
                    "captain-run", valid_parameters, ctx=None
                )
                self.assertEqual("blocked", unavailable["receipt"]["status"])
                self.assertIn(
                    "server runtime actor identity is unavailable",
                    unavailable["output"]["error"],
                )

    def test_captain_surface_accepts_incompatible_runtime_session(self) -> None:
        class Session:
            __slots__ = ()

        class RequestContext:
            session = Session()

        parameters = {
            "actions": [],
            "session_escalation": {
                "target": {"repo": "heimgewebe/grabowski"},
                "reason": "bounded regression",
            },
        }
        with (
            patch.object(grabowski_mcp, "_require_capability"),
            patch.object(grabowski_mcp, "_require_mutations_enabled"),
            patch.object(
                grabowski_mcp,
                "_session_grip_policy_decision",
                return_value={
                    "allowed": True,
                    "session_profile": {"profile": "test"},
                },
            ),
            patch.object(
                grabowski_mcp,
                "_captain_audit_intent",
                return_value={"audit_record_sha256": "a" * 64},
            ),
            patch.object(
                grabowski_mcp,
                "_captain_audit_completion",
                return_value={"audit_record_sha256": "b" * 64},
            ),
            patch.object(
                grabowski_mcp.grabowski_grips, "_default_github_runner"
            ) as github,
        ):
            result = grabowski_mcp._grip_run_core(
                "captain-run",
                parameters,
                profile="captain",
                allow_mutation=True,
                ctx=RequestContext(),
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("actions must be a non-empty list", result["output"]["error"])
        self.assertNotIn("server runtime lease identity failed", json.dumps(result))
        github.assert_not_called()

    @staticmethod
    def _gate_audit_close_result(*, gate_outcome: str = "pass", status: str = "passed") -> dict[str, object]:
        return {
            "status": status,
            "receipt_sha256": "d" * 64,
            "receipt": {"status": status},
            "output": {
                "convergence_gate_outcome": gate_outcome,
                "completion_scope": "systemic" if gate_outcome == "pass" else None,
                "systemic_convergence_claim": gate_outcome == "pass",
                "close_file_sha256": "e" * 64 if status == "passed" else None,
                "completion_classification": {
                    "convergence_receipt_sha256": "f" * 64,
                    "system_convergence_plan": {
                        "plan_sha256": "c" * 64,
                        "systemic_closure_gate": "hard",
                    },
                },
                "replayed": False,
            },
        }

    @staticmethod
    def _gate_audit_parameters() -> dict[str, object]:
        return {
            "obligation_id": "goo-gate-audit-0001",
            "outcome": "completed",
            "evidence": [],
            "closure_classification": {
                "convergence_required": True,
                "reason": "systemic",
                "convergence_receipt": {"status": "passed"},
                "system_convergence_plan": {
                    "plan_sha256": "c" * 64,
                    "systemic_closure_gate": "hard",
                },
            },
        }

    def test_operator_obligation_close_audits_pending_and_terminal_gate_result(self) -> None:
        allowed = {"allowed": True, "session_profile": {"profile": "test"}}
        parameters = self._gate_audit_parameters()
        inner = self._gate_audit_close_result()
        with (
            patch.object(grabowski_mcp, "_require_mutations_enabled"),
            patch.object(
                grabowski_mcp, "_session_grip_policy_decision", return_value=allowed
            ),
            patch.object(
                grabowski_mcp.grabowski_grips, "grip_run", return_value=inner
            ) as grip_run,
            patch.object(
                grabowski_mcp,
                "_append_audit_with_digest",
                side_effect=["a" * 64, "b" * 64],
            ) as append_audit,
        ):
            result = grabowski_mcp._grip_run_core(
                "operator-obligation-close",
                parameters,
                profile="operator",
                allow_mutation=True,
            )

        grip_run.assert_called_once()
        self.assertEqual(2, append_audit.call_count)
        attempt = append_audit.call_args_list[0].args[0]
        completion = append_audit.call_args_list[1].args[0]
        self.assertEqual("operator-obligation-convergence-gate-attempt", attempt["operation"])
        self.assertEqual("pending", attempt["convergence_gate_outcome"])
        self.assertEqual("hard", attempt["systemic_closure_gate"])
        self.assertEqual("operator-obligation-convergence-gate-result", completion["operation"])
        self.assertEqual("a" * 64, completion["attempt_audit_sha256"])
        self.assertEqual("d" * 64, completion["grip_receipt_sha256"])
        self.assertEqual("pass", completion["convergence_gate_outcome"])
        self.assertEqual("c" * 64, completion["system_convergence_plan_sha256"])
        self.assertEqual(
            {
                "status": "complete",
                "attempt_audit_sha256": "a" * 64,
                "result_audit_sha256": "b" * 64,
            },
            result["gate_audit"],
        )

    def test_operator_obligation_close_records_blocked_gate_result(self) -> None:
        allowed = {"allowed": True, "session_profile": {"profile": "test"}}
        inner = self._gate_audit_close_result(gate_outcome="blocked", status="blocked")
        with (
            patch.object(grabowski_mcp, "_require_mutations_enabled"),
            patch.object(
                grabowski_mcp, "_session_grip_policy_decision", return_value=allowed
            ),
            patch.object(
                grabowski_mcp.grabowski_grips, "grip_run", return_value=inner
            ),
            patch.object(
                grabowski_mcp,
                "_append_audit_with_digest",
                side_effect=["a" * 64, "b" * 64],
            ) as append_audit,
        ):
            result = grabowski_mcp._grip_run_core(
                "operator-obligation-close",
                self._gate_audit_parameters(),
                profile="operator",
                allow_mutation=True,
            )

        completion = append_audit.call_args_list[1].args[0]
        self.assertEqual("blocked", completion["convergence_gate_outcome"])
        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("complete", result["gate_audit"]["status"])

    def test_operator_obligation_close_audit_preflight_failure_prevents_effect(self) -> None:
        allowed = {"allowed": True, "session_profile": {"profile": "test"}}
        with (
            patch.object(grabowski_mcp, "_require_mutations_enabled"),
            patch.object(
                grabowski_mcp, "_session_grip_policy_decision", return_value=allowed
            ),
            patch.object(grabowski_mcp.grabowski_grips, "grip_run") as grip_run,
            patch.object(
                grabowski_mcp, "_append_audit_with_digest", side_effect=OSError("audit down")
            ),
        ):
            result = grabowski_mcp._grip_run_core(
                "operator-obligation-close",
                self._gate_audit_parameters(),
                profile="operator",
                allow_mutation=True,
            )

        grip_run.assert_not_called()
        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("preflight_failed", result["gate_audit"]["status"])
        self.assertIn(
            "operator_obligation_close_effect_started",
            result["gate_audit"]["does_not_establish"],
        )

    def test_operator_obligation_close_result_audit_failure_preserves_effect_result(self) -> None:
        allowed = {"allowed": True, "session_profile": {"profile": "test"}}
        inner = self._gate_audit_close_result()

        def append(record: dict[str, object]) -> str:
            if record["operation"] == "operator-obligation-convergence-gate-attempt":
                return "a" * 64
            raise OSError("audit completion down")

        with (
            patch.object(grabowski_mcp, "_require_mutations_enabled"),
            patch.object(
                grabowski_mcp, "_session_grip_policy_decision", return_value=allowed
            ),
            patch.object(
                grabowski_mcp.grabowski_grips, "grip_run", return_value=inner
            ),
            patch.object(grabowski_mcp, "_append_audit_with_digest", side_effect=append),
        ):
            result = grabowski_mcp._grip_run_core(
                "operator-obligation-close",
                self._gate_audit_parameters(),
                profile="operator",
                allow_mutation=True,
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual("completion_failed", result["gate_audit"]["status"])
        self.assertEqual("a" * 64, result["gate_audit"]["attempt_audit_sha256"])
        self.assertIn(
            "convergence_gate_result_audit_completion",
            result["gate_audit"]["does_not_establish"],
        )

    def test_grip_core_uses_per_grip_capability_without_terminal_leakage(self) -> None:
        allowed = {
            "allowed": True,
            "session_profile": {"profile": "test"},
        }
        output = {"receipt": {"status": "passed"}}
        with (
            patch.object(grabowski_mcp, "_session_grip_policy_decision", return_value=allowed),
            patch.object(grabowski_mcp, "_require_capability") as require_capability,
            patch.object(grabowski_mcp, "_require_mutations_enabled") as require_mutations,
            patch.object(grabowski_mcp.grabowski_grips, "grip_run", return_value=output),
        ):
            observed = grabowski_mcp._grip_run_core(
                "browser-semantic-observe",
                {"worker_id": "a" * 20},
                profile="operator",
                allow_mutation=False,
            )
            require_capability.assert_called_once_with("browser_worker")
            require_mutations.assert_not_called()
            require_capability.reset_mock()

            acted = grabowski_mcp._grip_run_core(
                "browser-semantic-act",
                {
                    "worker_id": "b" * 20,
                    "snapshot_id": "bsid2_" + "c" * 64,
                    "action_kind": "read_state",
                },
                profile="operator",
                allow_mutation=True,
            )
            require_capability.assert_not_called()
            require_mutations.assert_called_once_with("browser_worker")
            require_mutations.reset_mock()

            terminal = grabowski_mcp._grip_run_core(
                "repo-orient",
                {"repo": "/tmp/repo"},
                profile="operator",
                allow_mutation=False,
            )
            require_capability.assert_called_once_with("terminal_execute")

        self.assertIs(observed, output)
        self.assertIs(acted, output)
        self.assertIs(terminal, output)

    def test_session_forbidden_hosts_block_operator_argv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(
                root,
                capabilities=["terminal_execute"],
            )
            policy = json.loads((root / "access.json").read_text(encoding="utf-8"))
            policy["profiles"]["test"]["forbidden_hosts"] = ["prod.example"]
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patch.object(grabowski_mcp, "_load_policy", return_value=policy),
            ):
                with self.assertRaisesRegex(PermissionError, "Forbidden host"):
                    grabowski_mcp._reject_forbidden_hosts_in_argv(
                        ["ssh", "prod.example", "hostname"], policy=policy
                    )
                with self.assertRaisesRegex(PermissionError, "Forbidden host"):
                    grabowski_mcp._reject_forbidden_hosts_in_argv(
                        ["curl", "https://prod.example/status"], policy=policy
                    )

                policy["profiles"]["test"]["forbidden_hosts"] = [
                    "wg-prod-1",
                    "heim-pc",
                    "heimserver",
                ]
                with self.assertRaisesRegex(PermissionError, "wg-prod-1"):
                    grabowski_mcp._reject_forbidden_hosts_in_argv(
                        ["ssh", "wg-prod-1", "hostname"], policy=policy
                    )
                with self.assertRaisesRegex(PermissionError, "heim-pc"):
                    grabowski_mcp._reject_forbidden_hosts_in_argv(
                        ["ssh", "heim-pc", "hostname"], policy=policy
                    )
                with self.assertRaisesRegex(PermissionError, "heimserver"):
                    grabowski_mcp._reject_forbidden_hosts_in_argv(
                        ["ssh", "heimserver", "hostname"], policy=policy
                    )
                grabowski_mcp._reject_forbidden_hosts_in_argv(
                    ["ssh", "heimberry", "hostname"], policy=policy
                )
                grabowski_mcp._reject_forbidden_hosts_in_argv(
                    ["echo", "heim", "pc", "hostname"], policy=policy
                )

    def test_write_outside_profile_scope_remains_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(
                root,
                capabilities=["file_read", "file_write", "audit_verify"],
            )
            outside = root / "outside.txt"
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                with self.assertRaisesRegex(
                    PermissionError, "outside configured write roots"
                ):
                    grabowski_mcp.grabowski_create_text(str(outside), "blocked\n")

    def test_write_target_missing_parent_preflight_is_opt_in_and_effect_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(
                root,
                capabilities=["file_read", "file_write", "audit_verify"],
            )
            target = work / "future" / "nested" / "receipt.json"
            outside = root / "outside" / "nested" / "receipt.json"
            traversal = work / "new" / ".." / ".." / "outside" / "receipts"
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                with self.assertRaises(FileNotFoundError):
                    grabowski_mcp._resolve_write_target(str(target))
                resolved, exists = grabowski_mcp._resolve_write_target(
                    str(target), allow_missing_parents=True
                )
                self.assertEqual(resolved, target)
                self.assertFalse(exists)
                self.assertFalse((work / "future").exists())
                with self.assertRaisesRegex(
                    PermissionError, "Parent traversal is forbidden"
                ):
                    grabowski_mcp._resolve_write_target(
                        str(traversal), allow_missing_parents=True
                    )
                self.assertFalse((work / "new").exists())
                self.assertFalse((root / "outside").exists())
                with self.assertRaisesRegex(
                    PermissionError, "outside configured write roots"
                ):
                    grabowski_mcp._resolve_write_target(
                        str(outside), allow_missing_parents=True
                    )
                self.assertFalse((root / "outside").exists())

    def test_audit_chain_rejects_unhashed_record_after_v2_transition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _work, _secret, _browser, _export, state, *patches = self._patched_runtime(
                root
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                audit = state / "write-audit.jsonl"
                legacy = {"operation": "legacy", "timestamp": "before-v2"}
                audit.write_text(
                    json.dumps(legacy, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                audit.chmod(0o600)
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
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(
                root
            )
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

    def test_tool_capability_requirements_cover_runtime_contract(self) -> None:
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        expected_tools = set(contract["expected_tools"])

        self.assertEqual(
            set(grabowski_mcp.TOOL_CAPABILITY_REQUIREMENTS)
            - grabowski_mcp.STAGED_UNPUBLISHED_TOOL_NAMES,
            expected_tools,
        )
        self.assertEqual(
            grabowski_mcp.STAGED_UNPUBLISHED_TOOL_NAMES,
            {"grabowski_agent_workspace_adopt"},
        )

    def test_staged_workspace_adopt_remains_implemented_but_not_public(self) -> None:
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        self.assertNotIn("grabowski_agent_workspace_adopt", contract["expected_tools"])
        self.assertIn(
            "grabowski_agent_workspace_adopt",
            grabowski_mcp.TOOL_CAPABILITY_REQUIREMENTS,
        )
        runtime_source = (ROOT / "src" / "grabowski_runtime.py").read_text(encoding="utf-8")
        self.assertIn("STAGED_UNPUBLISHED_TOOL_NAMES", runtime_source)
        self.assertIn("manager.remove_tool(tool_name)", runtime_source)

    def test_tool_capability_requirements_reference_known_capabilities(self) -> None:
        all_capabilities = set(grabowski_mcp.ALL_CAPABILITIES)
        used_capabilities = {
            capability
            for required in grabowski_mcp.TOOL_CAPABILITY_REQUIREMENTS.values()
            for capability in required
        }

        self.assertTrue(used_capabilities.issubset(all_capabilities))

    def test_tool_capability_requirements_match_static_tool_guards(self) -> None:
        requirements, operator_tools = _static_tool_guard_requirements()

        self.assertEqual(grabowski_mcp.TOOL_CAPABILITY_REQUIREMENTS, requirements)
        self.assertEqual(
            grabowski_mcp.OPERATOR_CAPABILITY_REQUIREMENT_TOOLS,
            operator_tools,
        )

    def test_legacy_policy_does_not_implicitly_gain_audit_read(self) -> None:
        policy = {
            "mode": "bounded-read-write",
            "read_roots": [],
            "write_roots": [],
        }
        profile = grabowski_mcp._legacy_profile(policy)
        self.assertIn("audit_verify", profile["capabilities"])
        self.assertNotIn("audit_read", profile["capabilities"])

    def test_legacy_operator_capability_semantics_are_mirrored(self) -> None:
        policy = {
            "version": 1,
            "mode": "legacy-test",
            "read_roots": [],
            "write_roots": [],
            "forbidden_capabilities": [],
        }

        missing = {
            item["tool"]: item["missing_capabilities"]
            for item in grabowski_mcp._capability_requirement_summary(policy)[
                "missing_enabled_requirements"
            ]
        }

        self.assertNotIn("grabowski_terminal_run", missing)
        self.assertNotIn("grabowski_git", missing)
        self.assertNotIn("grip_run", missing)

    def test_status_reports_registered_tool_missing_required_capability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capabilities = [
                "file_read",
                "file_write",
                "file_destroy",
                "audit_verify",
                "rollback_text",
            ]
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(
                root,
                capabilities=capabilities,
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                status = grabowski_mcp.grabowski_status(view="evidence")

        missing = {
            item["tool"]: item["missing_capabilities"]
            for item in status["capability_requirements"][
                "missing_enabled_requirements"
            ]
        }
        summary = status["capability_requirements"]
        self.assertEqual(summary["registered_tool_requirements"], 198)
        self.assertEqual(summary["known_tool_requirements"], 199)
        self.assertEqual(
            summary["staged_unpublished_tools"],
            ["grabowski_agent_workspace_adopt"],
        )
        self.assertEqual(missing["grabowski_remove_path"], ["file_delete"])
        self.assertEqual(missing["grabowski_restore_removed_path"], ["file_delete"])
        self.assertEqual(missing["repoground_bundle_discover"], ["bundle_registry"])
        self.assertEqual(missing["grabowski_audit_query"], ["audit_read"])
        self.assertEqual(missing["grabowski_audit_trace"], ["audit_read"])
        self.assertEqual(missing["grabowski_audit_analyze"], ["audit_read"])
        self.assertEqual(
            missing["grabowski_reposkop_effectiveness"], ["audit_read"]
        )
        self.assertEqual(
            missing["grabowski_checkout_binding_terminal_preview"],
            ["git_cli", "github_cli"],
        )
        self.assertEqual(
            missing["grabowski_checkout_binding_terminal_apply"],
            ["git_cli", "github_cli", "resource_lease"],
        )
        self.assertNotIn("grabowski_verify_audit", missing)
        self.assertNotIn("grip_run", missing)
        self.assertEqual(
            missing["grabowski_connector_transport_diagnostics"],
            ["user_service_control"],
        )
        self.assertNotIn("grabowski_destroy_path", missing)
        self.assertNotIn("grabowski_friction_summary", missing)

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

    def test_remove_reuses_write_guards_for_sensitive_excluded_and_protected_roots(
        self,
    ) -> None:
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
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(
                root
            )
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

    def test_canonical_marker_is_typed_only_even_for_trusted_owner(self) -> None:
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
            work, _secret, _browser, _export, state, *patches = self._patched_runtime(
                root,
                capabilities=capabilities,
            )
            state.chmod(0o700)
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patch.object(
                    grabowski_mcp,
                    "_roots",
                    side_effect=lambda kind, ignore_missing=False: [work, state],
                ),
                patch.object(grabowski_mcp, "_excluded_roots", return_value=[]),
                patch.object(grabowski_mcp, "_path_is_sensitive", return_value=False),
                patch.object(
                    grabowski_mcp, "_trusted_owner_enabled", return_value=True
                ),
            ):
                marker_path = grabowski_mcp.KILL_SWITCH_PATH
                with self.assertRaisesRegex(PermissionError, "typed lifecycle tools"):
                    grabowski_mcp.grabowski_create_text(str(marker_path), "stop\n")
                self.assertFalse(marker_path.exists())

                marker_path.write_text("legacy stop\n", encoding="utf-8")
                marker_path.chmod(0o600)
                before = marker_path.read_bytes()
                before_sha = _sha256(marker_path)
                with self.assertRaisesRegex(PermissionError, "typed lifecycle tools"):
                    grabowski_mcp.grabowski_replace_text(
                        str(marker_path), "changed\n", before_sha
                    )
                with self.assertRaisesRegex(PermissionError, "typed lifecycle tools"):
                    grabowski_mcp.grabowski_remove_path(
                        str(marker_path), "file", before_sha
                    )
                with self.assertRaisesRegex(PermissionError, "typed lifecycle tools"):
                    grabowski_mcp.grabowski_destroy_path(
                        str(marker_path),
                        "file",
                        "permanently-delete",
                        before_sha,
                    )
                self.assertEqual(marker_path.read_bytes(), before)

    def test_path_blockade_applies_to_generic_file_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(
                root
            )
            blocked = work / "blocked"
            blocked.mkdir()
            record = grabowski_mcp.blockade_policy.BlockadeRecord(
                blockade_id="path-freeze-1",
                posture="mutation_freeze",
                scope=grabowski_mcp.blockade_policy.Scope("path", str(blocked)),
                reason="Test path freeze.",
                trigger_class="manual_path_freeze",
                engaged_at=grabowski_mcp.datetime.now(grabowski_mcp.timezone.utc),
                evidence_refs=("test:path-freeze",),
                provenance=grabowski_mcp.blockade_policy.Provenance(
                    tool="test",
                    request_id="request-1",
                    session_id="session-1",
                    task_id="task-1",
                    owner_id="owner-1",
                ),
            )
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patch.object(
                    grabowski_mcp,
                    "_operator_blockade_records",
                    return_value=((record,), {"marker_source": "test"}),
                ),
            ):
                with self.assertRaisesRegex(
                    PermissionError, "mutation_blocked_by_mutation_freeze"
                ):
                    grabowski_mcp.grabowski_create_text(
                        str(blocked / "denied.txt"), "denied\n"
                    )
                allowed = work / "allowed.txt"
                result = grabowski_mcp.grabowski_create_text(str(allowed), "allowed\n")
                self.assertTrue(allowed.is_file())
                self.assertEqual(result["after_sha256"], _sha256(allowed))

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
            work, secret, browser, _export, _state, *patches = self._patched_runtime(
                root
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                secret_file = secret / "token.txt"
                browser_file = browser / "prefs.js"
                secret_file.write_text("plain-secret-value\n", encoding="utf-8")
                browser_file.write_text("user_pref('x', true);\n", encoding="utf-8")

                listing = grabowski_mcp.grabowski_list_directory(str(work))
                entry_types = {
                    entry["name"]: entry["type"] for entry in listing["entries"]
                }
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
            _work, secret, _browser, _export, state, *patches = self._patched_runtime(
                root
            )
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
                    str(target),
                    source_sha,
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
            work, secret, _browser, _export, state, *patches = self._patched_runtime(
                root
            )
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
                urlsafe = (
                    base64.urlsafe_b64encode(secret_value.encode()).decode().rstrip("=")
                )
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

    def test_trusted_owner_secret_use_accepts_source_from_read_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(
                root
            )
            source = work / "workspace-token.txt"
            source.write_text("trusted-owner-read-root-secret-12345", encoding="utf-8")
            source_sha = _sha256(source)
            policy_path = root / "access.json"

            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                with self.assertRaisesRegex(PermissionError, "outside configured secret roots"):
                    grabowski_mcp.grabowski_secret_use(
                        str(source),
                        source_sha,
                        [sys.executable, "-c", "pass", "{SECRET_FD_PATH}"],
                        cwd=str(work),
                    )

                policy = json.loads(policy_path.read_text(encoding="utf-8"))
                policy["profiles"]["test"]["trusted_owner"] = True
                policy_path.write_text(
                    json.dumps(policy, sort_keys=True) + "\n", encoding="utf-8"
                )

                result = grabowski_mcp.grabowski_secret_use(
                    str(source),
                    source_sha,
                    [
                        sys.executable,
                        "-c",
                        "import sys; print(open(sys.argv[1], 'r').read())",
                        "{SECRET_FD_PATH}",
                    ],
                    cwd=str(work),
                )

                self.assertEqual(result["returncode"], 0)
                self.assertEqual(result["source_path"], str(source))
                self.assertIn("<REDACTED>", result["stdout"])
                self.assertNotIn(
                    "trusted-owner-read-root-secret-12345", result["stdout"]
                )

    def test_trusted_owner_secret_use_preserves_disjoint_secret_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, _secret, _browser, _export, _state, *patches = self._patched_runtime(
                root
            )
            disjoint_secret = root / "disjoint-secret"
            disjoint_secret.mkdir()
            source = disjoint_secret / "legacy-token.txt"
            source.write_text("trusted-owner-secret-root-12345", encoding="utf-8")
            source_sha = _sha256(source)
            policy_path = root / "access.json"
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
            policy["secret_roots"] = [str(disjoint_secret)]
            policy["profiles"]["test"]["secret_roots"] = [str(disjoint_secret)]
            policy["profiles"]["test"]["trusted_owner"] = True
            policy_path.write_text(
                json.dumps(policy, sort_keys=True) + "\n", encoding="utf-8"
            )

            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                result = grabowski_mcp.grabowski_secret_use(
                    str(source),
                    source_sha,
                    [
                        sys.executable,
                        "-c",
                        "import sys; print(open(sys.argv[1], 'r').read())",
                        "{SECRET_FD_PATH}",
                    ],
                    cwd=str(work),
                )

                self.assertEqual(result["returncode"], 0)
                self.assertEqual(result["source_path"], str(source))
                self.assertIn("<REDACTED>", result["stdout"])
                self.assertNotIn("trusted-owner-secret-root-12345", result["stdout"])

    def test_secret_use_annotations_match_open_world_command_effects(self) -> None:
        annotations = grabowski_mcp.SECRET_USE_ANNOTATIONS.values
        self.assertFalse(annotations["readOnlyHint"])
        self.assertTrue(annotations["destructiveHint"])
        self.assertFalse(annotations["idempotentHint"])
        self.assertTrue(annotations["openWorldHint"])

    def test_trusted_owner_secret_use_command_shape_relaxes_local_shell_guard_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory)
            with (
                patch.object(grabowski_mcp, "_trusted_owner_enabled", return_value=True),
                patch.object(grabowski_mcp, "_resolve_executable", return_value="/bin/sh"),
            ):
                command = grabowski_mcp._validate_secret_use_argv(
                    ["sh", "-c", "printf ok {SECRET_FD_PATH}"],
                    cwd=cwd,
                    secret_data=b"synthetic-value",
                )
                self.assertEqual(command[0], "/bin/sh")
                with self.assertRaisesRegex(PermissionError, "argv"):
                    grabowski_mcp._validate_secret_use_argv(
                        ["sh", "-c", "printf synthetic-value {SECRET_FD_PATH}"],
                        cwd=cwd,
                        secret_data=b"synthetic-value",
                    )

    def test_secret_use_blocks_direct_github_merge_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory)
            with (
                patch.object(grabowski_mcp, "_trusted_owner_enabled", return_value=True),
                patch.object(grabowski_mcp, "_resolve_executable", return_value="/usr/bin/gh"),
            ):
                with self.assertRaisesRegex(PermissionError, "Captain pr-merge"):
                    grabowski_mcp._validate_secret_use_argv(
                        [
                            "gh",
                            "pr",
                            "merge",
                            "350",
                            "--subject",
                            "{SECRET_FD_PATH}",
                        ],
                        cwd=cwd,
                        secret_data=b"synthetic-value",
                    )

    def test_trusted_owner_secret_use_environment_accepts_nonsecret_extra_keys(self) -> None:
        with patch.object(grabowski_mcp, "_trusted_owner_enabled", return_value=True):
            environment = grabowski_mcp._secret_use_environment(
                {"EXTRA_CONTEXT": "metadata-only"},
                b"synthetic-value",
            )
            self.assertEqual(environment["EXTRA_CONTEXT"], "metadata-only")
            with self.assertRaisesRegex(PermissionError, "environment"):
                grabowski_mcp._secret_use_environment(
                    {"EXTRA_CONTEXT": "synthetic-value"},
                    b"synthetic-value",
                )

    def test_trusted_owner_secret_use_cwd_accepts_sensitive_operator_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory).resolve()
            with (
                patch.object(grabowski_mcp, "_trusted_owner_enabled", return_value=True),
                patch.object(grabowski_mcp, "_roots", return_value=[cwd]),
                patch.object(grabowski_mcp, "_path_is_sensitive", return_value=True),
                patch.object(
                    grabowski_mcp,
                    "_protected_generic_write_target",
                    return_value=True,
                ),
            ):
                self.assertEqual(grabowski_mcp._resolve_secret_use_cwd(str(cwd)), cwd)

    def test_secret_use_rejects_shell_and_cleans_temp_fallback_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, secret, _browser, _export, state, *patches = self._patched_runtime(
                root
            )
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
            _work, secret, _browser, export, state, *patches = self._patched_runtime(
                root
            )
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
            _work, _secret, browser, _export, _state, *patches = self._patched_runtime(
                root
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                prefs = browser / "prefs.js"
                prefs.write_text(
                    "user_pref('browser.startup.page', 1);\n", encoding="utf-8"
                )
                cookies = browser / "Cookies"
                cookies.write_bytes(b"SQLite format 3\x00secret-cookie")

                listing = grabowski_mcp.grabowski_browser_profile_read(str(browser))
                self.assertEqual(listing["returned"], 2)
                prefs_result = grabowski_mcp.grabowski_browser_profile_read(str(prefs))
                self.assertTrue(prefs_result["content_returned"])
                self.assertIn("browser.startup.page", prefs_result["text"])
                cookies_result = grabowski_mcp.grabowski_browser_profile_read(
                    str(cookies)
                )
                self.assertFalse(cookies_result["content_returned"])
                self.assertIn("sha256", cookies_result)
                self.assertNotIn("secret-cookie", json.dumps(cookies_result))

    def test_secret_use_rejects_secret_variants_in_argv_and_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, secret, _browser, _export, _state, *patches = self._patched_runtime(
                root
            )
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
            work, secret, _browser, _export, _state, *patches = self._patched_runtime(
                root
            )
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
            work, secret, _browser, _export, _state, *patches = self._patched_runtime(
                root
            )
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
            _work, secret, _browser, _export, state, *patches = self._patched_runtime(
                root
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                value = "audited-reveal-secret-12345"
                source = secret / "token.txt"
                source.write_text(value, encoding="utf-8")
                result = grabowski_mcp.grabowski_secret_reveal(
                    str(source),
                    _sha256(source),
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
            _work, secret, _browser, _export, _state, *patches = self._patched_runtime(
                root
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                source = secret / "token.txt"
                source.write_text("chain-guard-secret", encoding="utf-8")
                grabowski_mcp.AUDIT_LOG.write_text("not-json\n", encoding="utf-8")

                with self.assertRaisesRegex(
                    RuntimeError, "Audit log verification failed"
                ):
                    grabowski_mcp.grabowski_secret_reveal(str(source), _sha256(source))

    def test_browser_profile_read_redacts_sensitive_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _work, _secret, browser, _export, _state, *patches = self._patched_runtime(
                root
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                prefs = browser / "prefs.js"
                prefs.write_text(
                    "token=" + "Bearer " + "abcdefghijkl" + "mnopqrstuvwxyz" + "\n",
                    encoding="utf-8",
                )
                result = grabowski_mcp.grabowski_browser_profile_read(str(prefs))
                self.assertTrue(result["content_returned"])
                self.assertIn("<REDACTED>", result["text"])
                self.assertNotIn("abcdefghijklmnopqrstuvwxyz", result["text"])

    def test_secret_export_removes_new_target_when_postflight_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _work, secret, _browser, export, _state, *patches = self._patched_runtime(
                root
            )
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

                with patch.object(
                    grabowski_mcp, "_read_bound_regular_bytes", side_effect=failing_read
                ):
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
            work, secret, _browser, export, _state, *patches = self._patched_runtime(
                root
            )
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
                        str(source),
                        source_sha,
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
                    lambda: grabowski_mcp.grabowski_secret_reveal(
                        str(source), source_sha
                    ),
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


class CaptainAuditTrailTests(unittest.TestCase):
    class Session:
        pass

    class RequestContext:
        session = None

    def setUp(self) -> None:
        self.RequestContext.session = self.Session()

    def test_audit_material_binds_target_and_context_without_exposing_context(self) -> None:
        parameters = {
            "actions": [
                {
                    "action": "pr-merge",
                    "target": {
                        "repository": "heimgewebe/grabowski",
                        "pull_request": 468,
                        "expected_head": "a" * 40,
                        "base": "main",
                    },
                }
            ],
            "execution_intent": {"context": {"lease_owner_id": "operator:test", "secret": "do-not-log"}},
        }
        material = grabowski_mcp._captain_audit_action_material(parameters)
        self.assertEqual("pr-merge", material["action"])
        self.assertEqual("a" * 40, material["expected_head"])
        self.assertEqual("main", material["expected_base"])
        self.assertEqual(64, len(material["target_sha256"]))
        self.assertEqual(64, len(material["context_sha256"]))
        self.assertNotIn("do-not-log", json.dumps(material, sort_keys=True))

    def test_verified_append_returns_the_exact_appended_record_digest(self) -> None:
        with (
            patch.object(
                grabowski_mcp, "_append_audit_with_digest", return_value="a" * 64
            ) as append,
            patch.object(
                grabowski_mcp,
                "_verify_audit_log",
                side_effect=AssertionError("must not reread a moving chain tail"),
            ) as verify,
        ):
            result = grabowski_mcp._append_verified_captain_audit(
                {"operation": "test"}
            )
        self.assertEqual("a" * 64, result["audit_record_sha256"])
        append.assert_called_once_with({"operation": "test"})
        verify.assert_not_called()

    def test_verified_append_rejects_missing_atomic_digest(self) -> None:
        with patch.object(
            grabowski_mcp, "_append_audit_with_digest", return_value="invalid"
        ):
            with self.assertRaisesRegex(RuntimeError, "digest unavailable"):
                grabowski_mcp._append_verified_captain_audit({"operation": "test"})

    def test_completion_audit_retries_only_pre_append_lock_timeout(self) -> None:
        record = {"operation": "captain-run-audit-completion"}
        with (
            patch.object(
                grabowski_mcp,
                "_append_verified_captain_audit",
                side_effect=[
                    RuntimeError(grabowski_mcp.CAPTAIN_AUDIT_LOCK_TIMEOUT_ERROR),
                    RuntimeError(grabowski_mcp.CAPTAIN_AUDIT_LOCK_TIMEOUT_ERROR),
                    {"audit_chain_valid": True, "audit_record_sha256": "a" * 64},
                ],
            ) as append,
            patch.object(grabowski_mcp.time, "sleep") as sleep,
        ):
            result = grabowski_mcp._append_verified_captain_completion_audit(record)
        self.assertEqual("a" * 64, result["audit_record_sha256"])
        self.assertEqual(3, append.call_count)
        self.assertEqual(
            [
                unittest.mock.call(
                    grabowski_mcp.CAPTAIN_AUDIT_COMPLETION_LOCK_RETRY_DELAYS[0]
                ),
                unittest.mock.call(
                    grabowski_mcp.CAPTAIN_AUDIT_COMPLETION_LOCK_RETRY_DELAYS[1]
                ),
            ],
            sleep.call_args_list,
        )

    def test_completion_audit_does_not_retry_ambiguous_runtime_error(self) -> None:
        record = {"operation": "captain-run-audit-completion"}
        with (
            patch.object(
                grabowski_mcp,
                "_append_verified_captain_audit",
                side_effect=RuntimeError("Audit append size postflight mismatch"),
            ) as append,
            patch.object(grabowski_mcp.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "Audit append size postflight mismatch"
            ):
                grabowski_mcp._append_verified_captain_completion_audit(record)
        append.assert_called_once_with(record)
        sleep.assert_not_called()

    def test_completion_audit_lock_retry_exhaustion_remains_visible(self) -> None:
        record = {"operation": "captain-run-audit-completion"}
        attempts = len(grabowski_mcp.CAPTAIN_AUDIT_COMPLETION_LOCK_RETRY_DELAYS) + 1
        with (
            patch.object(
                grabowski_mcp,
                "_append_verified_captain_audit",
                side_effect=RuntimeError(grabowski_mcp.CAPTAIN_AUDIT_LOCK_TIMEOUT_ERROR),
            ) as append,
            patch.object(grabowski_mcp.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(
                RuntimeError, grabowski_mcp.CAPTAIN_AUDIT_LOCK_TIMEOUT_ERROR
            ):
                grabowski_mcp._append_verified_captain_completion_audit(record)
        self.assertEqual(attempts, append.call_count)
        self.assertEqual(attempts - 1, sleep.call_count)

    def test_intent_audit_lock_timeout_is_not_retried(self) -> None:
        parameters = {"actions": []}
        actor = grabowski_mcp.grabowski_merge_guard.issue_server_runtime_actor_identity(
            object(), profile="test", now_unix=100
        )
        with (
            patch.object(
                grabowski_mcp.grabowski_merge_guard,
                "verify_server_runtime_actor_identity",
                return_value={"owner_id": "runtime-actor:test"},
            ),
            patch.object(
                grabowski_mcp,
                "_append_verified_captain_audit",
                side_effect=RuntimeError(grabowski_mcp.CAPTAIN_AUDIT_LOCK_TIMEOUT_ERROR),
            ) as append,
            patch.object(grabowski_mcp.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(
                RuntimeError, grabowski_mcp.CAPTAIN_AUDIT_LOCK_TIMEOUT_ERROR
            ):
                grabowski_mcp._captain_audit_intent(parameters, actor)
        self.assertEqual(1, append.call_count)
        sleep.assert_not_called()

    def test_intent_audit_failure_blocks_before_grip_dispatch(self) -> None:
        parameters = {"actions": [], "session_escalation": {"target": {}, "reason": "test"}}
        with (
            patch.object(grabowski_mcp, "_require_capability"),
            patch.object(grabowski_mcp, "_require_mutations_enabled"),
            patch.object(grabowski_mcp, "_session_grip_policy_decision", return_value={"allowed": True, "session_profile": {"profile": "test"}}),
            patch.object(grabowski_mcp.grabowski_merge_guard, "issue_server_runtime_actor_identity", return_value={"identity": "server"}),
            patch.object(grabowski_mcp, "_captain_audit_intent", side_effect=RuntimeError("audit unavailable")),
            patch.object(grabowski_mcp.grabowski_grips, "grip_run") as run,
        ):
            result = grabowski_mcp.grip_run(
                "captain-run", parameters, profile="captain", allow_mutation=True, ctx=self.RequestContext()
            )
        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("captain audit intent unavailable", result["output"]["error"])
        run.assert_not_called()

    def test_completion_audit_failure_returns_bounded_error_code(self) -> None:
        parameters = {"actions": [], "session_escalation": {"target": {}, "reason": "test"}}
        grip_result = {
            "receipt": {
                "status": "passed",
                "receipt_sha256": "c" * 64,
                "output_sha256": "d" * 64,
            },
            "output": {},
        }
        with (
            patch.object(grabowski_mcp, "_require_capability"),
            patch.object(grabowski_mcp, "_require_mutations_enabled"),
            patch.object(
                grabowski_mcp,
                "_session_grip_policy_decision",
                return_value={
                    "allowed": True,
                    "session_profile": {"profile": "test"},
                },
            ),
            patch.object(
                grabowski_mcp.grabowski_merge_guard,
                "issue_server_runtime_actor_identity",
                return_value={"identity": "server"},
            ),
            patch.object(
                grabowski_mcp,
                "_captain_audit_intent",
                return_value={
                    "audit_chain_valid": True,
                    "audit_record_sha256": "a" * 64,
                },
            ),
            patch.object(
                grabowski_mcp,
                "_captain_audit_completion",
                side_effect=RuntimeError(
                    grabowski_mcp.CAPTAIN_AUDIT_LOCK_TIMEOUT_ERROR
                ),
            ),
            patch.object(
                grabowski_mcp.grabowski_grips,
                "grip_run",
                return_value=grip_result,
            ),
        ):
            result = grabowski_mcp.grip_run(
                "captain-run",
                parameters,
                profile="captain",
                allow_mutation=True,
                ctx=self.RequestContext(),
            )
        self.assertEqual("completion_failed", result["captain_audit"]["status"])
        self.assertEqual("RuntimeError", result["captain_audit"]["error_class"])
        self.assertEqual("audit_lock_timeout", result["captain_audit"]["error_code"])
        self.assertNotIn(
            grabowski_mcp.CAPTAIN_AUDIT_LOCK_TIMEOUT_ERROR,
            json.dumps(result["captain_audit"], sort_keys=True),
        )

    def test_successful_dispatch_returns_intent_and_completion_audit_refs(self) -> None:
        parameters = {"actions": [], "session_escalation": {"target": {}, "reason": "test"}}
        grip_result = {"receipt": {"status": "blocked", "receipt_sha256": "c" * 64, "output_sha256": "d" * 64}, "output": {}}
        with (
            patch.object(grabowski_mcp, "_require_capability"),
            patch.object(grabowski_mcp, "_require_mutations_enabled"),
            patch.object(grabowski_mcp, "_session_grip_policy_decision", return_value={"allowed": True, "session_profile": {"profile": "test"}}),
            patch.object(grabowski_mcp.grabowski_merge_guard, "issue_server_runtime_actor_identity", return_value={"identity": "server"}),
            patch.object(grabowski_mcp, "_captain_audit_intent", return_value={"audit_chain_valid": True, "audit_record_sha256": "a" * 64}),
            patch.object(grabowski_mcp, "_captain_audit_completion", return_value={"audit_chain_valid": True, "audit_record_sha256": "b" * 64}) as completion,
            patch.object(grabowski_mcp.grabowski_grips, "grip_run", return_value=grip_result),
        ):
            result = grabowski_mcp.grip_run(
                "captain-run", parameters, profile="captain", allow_mutation=True, ctx=self.RequestContext()
            )
        self.assertEqual("complete", result["captain_audit"]["status"])
        self.assertEqual("a" * 64, result["captain_audit"]["intent"]["audit_record_sha256"])
        self.assertEqual("b" * 64, result["captain_audit"]["completion"]["audit_record_sha256"])
        self.assertEqual("a" * 64, completion.call_args.kwargs["intent_audit_sha256"])
