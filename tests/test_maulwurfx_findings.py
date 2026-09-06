from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
for path in (SRC, TOOLS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import grabowski_connector_policy as connector_policy  # noqa: E402
import grabowski_external_connector_gateway as gateway  # noqa: E402



class _Request:
    def __init__(self, body: bytes, token: str) -> None:
        self.method = "POST"
        self.headers = {
            "authorization": f"Bearer {token}",
            "content-length": str(len(body)),
        }
        self._body = body

    async def stream(self):
        yield self._body


class MaulwurfXFindingTests(unittest.TestCase):
    EXTERNAL = "E" * 43
    INTERNAL = "I" * 43

    def finding_arguments(self) -> dict[str, object]:
        return {
            "title": "Bureau intake identity mismatch",
            "category": "bureau",
            "severity": "medium",
            "facts": [
                "A candidate record was rejected for an unknown live-register task."
            ],
            "evidence_refs": ["audit-record-sha256:" + "a" * 64],
            "interpretation": "The observed rejection merits operator review.",
            "uncertainty": 0.2,
            "proposed_action": (
                "Compare the exact caller, runtime, and schema identity with the live register."
            ),
            "does_not_establish": ["shared root cause", "safe retry"],
        }

    def make_manifest(self, root: Path, head: str = "a" * 40) -> Path:
        manifest = root / "deployment-manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "completion_status": "complete",
                    "release_id": "release-test-1",
                    "repo_head": head,
                }
            ),
            encoding="utf-8",
        )
        os.chmod(manifest, 0o600)
        return manifest

    def make_finding_root(self, root: Path) -> Path:
        parent = root / "external-connectors"
        parent.mkdir(mode=0o700)
        os.chmod(parent, 0o700)
        return parent / "maulwurf-x-findings"

    def make_server(
        self, finding_root: Path, manifest: Path
    ) -> gateway.ExternalConnectorGateway:
        return gateway.ExternalConnectorGateway(
            connector_id="maulwurf-x",
            external_token=self.EXTERNAL,
            internal_token=self.INTERNAL,
            allowed_tools=["grabowski_status"],
            gateway_tools=[gateway.PROPOSAL_TOOL_NAME],
            upstream="http://127.0.0.1:18183/mcp",
            finding_root=finding_root,
            deployment_manifest=manifest,
        )

    def make_call_body(self, request_id: int) -> bytes:
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {
                    "name": gateway.PROPOSAL_TOOL_NAME,
                    "arguments": self.finding_arguments(),
                },
            }
        ).encode("utf-8")

    def test_tools_list_adds_one_gateway_proposal_on_terminal_page_only(self) -> None:
        terminal = {
            "jsonrpc": "2.0",
            "id": 4,
            "result": {
                "tools": [
                    {"name": "grabowski_status", "inputSchema": {}},
                    {"name": "grabowski_destroy_path", "inputSchema": {}},
                ],
                "nextCursor": None,
            },
        }
        projected = json.loads(
            gateway._filter_tools_list_payload(
                json.dumps(terminal).encode("utf-8"),
                {"grabowski_status"},
                {gateway.PROPOSAL_TOOL_NAME},
            ).decode("utf-8")
        )
        tools = projected["result"]["tools"]
        self.assertEqual(
            [tool["name"] for tool in tools],
            ["grabowski_status", gateway.PROPOSAL_TOOL_NAME],
        )
        proposal = tools[-1]
        self.assertFalse(proposal["annotations"]["readOnlyHint"])
        self.assertFalse(proposal["annotations"]["destructiveHint"])
        self.assertTrue(proposal["annotations"]["idempotentHint"])
        self.assertFalse(proposal["inputSchema"]["additionalProperties"])

        nonterminal = json.loads(json.dumps(terminal))
        nonterminal["result"]["nextCursor"] = "page-2"
        projected_nonterminal = json.loads(
            gateway._filter_tools_list_payload(
                json.dumps(nonterminal).encode("utf-8"),
                {"grabowski_status"},
                {gateway.PROPOSAL_TOOL_NAME},
            ).decode("utf-8")
        )
        self.assertEqual(
            [tool["name"] for tool in projected_nonterminal["result"]["tools"]],
            ["grabowski_status"],
        )

    def test_v2_policy_allows_only_the_fixed_gateway_proposal_tool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "transport-connectors"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            marker = root / connector_policy.ENFORCEMENT_MARKER_NAME
            marker.write_bytes(connector_policy.ENFORCEMENT_MARKER_PAYLOAD)
            os.chmod(marker, 0o600)
            policy_path = root / "maulwurf-x.tools.json"
            policy_path.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "connector_id": "maulwurf-x",
                        "mode": "allowlist",
                        "allowed_tools": ["grabowski_status"],
                        "gateway_tools": [gateway.PROPOSAL_TOOL_NAME],
                        "read_only_only": True,
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(policy_path, 0o600)
            loaded = gateway._load_gateway_policy(policy_path, "maulwurf-x")
            self.assertEqual(loaded["gateway_tools"], [gateway.PROPOSAL_TOOL_NAME])
            self.assertTrue(loaded["read_only_only"])

            policy_path.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "connector_id": "maulwurf-x",
                        "mode": "allowlist",
                        "allowed_tools": ["grabowski_status"],
                        "gateway_tools": ["grabowski_task_start"],
                        "read_only_only": True,
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(policy_path, 0o600)
            with self.assertRaisesRegex(
                gateway.GatewayConfigurationError, "unsupported gateway tools"
            ):
                gateway._load_gateway_policy(policy_path, "maulwurf-x")

    def test_finding_record_is_content_addressed_create_only_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding_root = self.make_finding_root(root)
            manifest = self.make_manifest(root)
            first = gateway._record_finding_proposal(
                connector_id="maulwurf-x",
                arguments=self.finding_arguments(),
                finding_root=finding_root,
                deployment_manifest=manifest,
            )
            second = gateway._record_finding_proposal(
                connector_id="maulwurf-x",
                arguments=self.finding_arguments(),
                finding_root=finding_root,
                deployment_manifest=manifest,
            )
            self.assertEqual(first["status"], "recorded")
            self.assertEqual(second["status"], "duplicate")
            self.assertEqual(first["finding_id"], second["finding_id"])
            self.assertFalse(first["execution_authority"])
            self.assertTrue(first["create_only"])
            files = list(finding_root.glob("*.json"))
            self.assertEqual(len(files), 1)
            self.assertEqual(stat.S_IMODE(finding_root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)
            stored = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(stored["principal"], "maulwurf-x")
            self.assertEqual(stored["runtime"]["repo_head"], "a" * 40)
            self.assertEqual(
                stored["finding"],
                gateway._normalize_finding_arguments(self.finding_arguments()),
            )
            self.assertNotIn("execution", stored)
            hidden = [
                path for path in finding_root.iterdir() if path.name.startswith(".")
            ]
            self.assertEqual([path.name for path in hidden], [gateway.FINDING_LOCK_NAME])
            self.assertEqual(stat.S_IMODE(hidden[0].stat().st_mode), 0o600)

    def test_runtime_identity_is_part_of_finding_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding_root = self.make_finding_root(root)
            manifest = self.make_manifest(root, "a" * 40)
            first = gateway._record_finding_proposal(
                connector_id="maulwurf-x",
                arguments=self.finding_arguments(),
                finding_root=finding_root,
                deployment_manifest=manifest,
            )
            self.make_manifest(root, "b" * 40)
            second = gateway._record_finding_proposal(
                connector_id="maulwurf-x",
                arguments=self.finding_arguments(),
                finding_root=finding_root,
                deployment_manifest=manifest,
            )
            self.assertNotEqual(first["finding_id"], second["finding_id"])
            self.assertEqual(len(list(finding_root.glob("*.json"))), 2)

    def test_finding_schema_rejects_extra_fields_nan_and_wrong_principal(self) -> None:
        args = self.finding_arguments()
        args["execute_now"] = True
        with self.assertRaisesRegex(ValueError, "shape"):
            gateway._normalize_finding_arguments(args)

        args = self.finding_arguments()
        args["uncertainty"] = float("nan")
        with self.assertRaisesRegex(ValueError, "uncertainty"):
            gateway._normalize_finding_arguments(args)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding_root = self.make_finding_root(root)
            manifest = self.make_manifest(root)
            with self.assertRaisesRegex(
                gateway.GatewayConfigurationError, "principal is not authorized"
            ):
                gateway._record_finding_proposal(
                    connector_id="other",
                    arguments=self.finding_arguments(),
                    finding_root=finding_root,
                    deployment_manifest=manifest,
                )

    def test_finding_store_has_a_hard_file_cap_and_rejects_unsafe_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding_root = self.make_finding_root(root)
            gateway._ensure_private_finding_root(finding_root)
            previous = gateway.MAX_FINDING_FILES
            gateway.MAX_FINDING_FILES = 2
            try:
                for index in (1, 2):
                    path = finding_root / (f"{index:064x}.json")
                    path.write_text("{}", encoding="utf-8")
                    os.chmod(path, 0o600)
                with self.assertRaisesRegex(
                    gateway.GatewayConfigurationError, "store is full"
                ):
                    gateway._enforce_finding_store_capacity(
                        finding_root, finding_root / (f"{3:064x}.json")
                    )
            finally:
                gateway.MAX_FINDING_FILES = previous

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding_root = self.make_finding_root(root)
            gateway._ensure_private_finding_root(finding_root)
            unexpected = finding_root / "not-a-finding.txt"
            unexpected.write_text("x", encoding="utf-8")
            os.chmod(unexpected, 0o600)
            with self.assertRaisesRegex(
                gateway.GatewayConfigurationError, "unexpected entry"
            ):
                gateway._enforce_finding_store_capacity(
                    finding_root, finding_root / (f"{4:064x}.json")
                )

    def test_gateway_local_tool_call_records_finding_without_upstream(self) -> None:
        try:
            __import__("starlette")
        except ModuleNotFoundError:
            self.skipTest("starlette runtime dependency is not installed")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding_root = self.make_finding_root(root)
            manifest = self.make_manifest(root)
            server = self.make_server(finding_root, manifest)
            response = asyncio.run(
                server.proxy(_Request(self.make_call_body(17), self.EXTERNAL))
            )
            result = json.loads(response.body.decode("utf-8"))
            self.assertEqual(result["id"], 17)
            receipt = result["result"]["structuredContent"]
            self.assertEqual(receipt["status"], "recorded")
            self.assertFalse(receipt["execution_authority"])
            self.assertEqual(len(list(finding_root.glob("*.json"))), 1)

    def test_concurrent_duplicate_records_create_exactly_one_proposal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding_root = self.make_finding_root(root)
            manifest = self.make_manifest(root)

            def record_once(_: int) -> dict[str, object]:
                return gateway._record_finding_proposal(
                    connector_id="maulwurf-x",
                    arguments=self.finding_arguments(),
                    finding_root=finding_root,
                    deployment_manifest=manifest,
                )

            with ThreadPoolExecutor(max_workers=10) as executor:
                receipts = list(executor.map(record_once, range(10)))
            self.assertEqual(
                [receipt["status"] for receipt in receipts].count("recorded"), 1
            )
            self.assertEqual(
                [receipt["status"] for receipt in receipts].count("duplicate"), 9
            )
            self.assertEqual(len({receipt["finding_id"] for receipt in receipts}), 1)
            self.assertEqual(len(list(finding_root.glob("*.json"))), 1)
            hidden = [
                path for path in finding_root.iterdir() if path.name.startswith(".")
            ]
            self.assertEqual([path.name for path in hidden], [gateway.FINDING_LOCK_NAME])
            self.assertEqual(stat.S_IMODE(hidden[0].stat().st_mode), 0o600)

    def test_gateway_rejects_proposal_surface_for_other_principals(self) -> None:
        with self.assertRaisesRegex(
            gateway.GatewayConfigurationError, "proposal tool is not authorized"
        ):
            gateway.ExternalConnectorGateway(
                connector_id="other",
                external_token=self.EXTERNAL,
                internal_token=self.INTERNAL,
                allowed_tools=["grabowski_status"],
                gateway_tools=[gateway.PROPOSAL_TOOL_NAME],
                upstream="http://127.0.0.1:18183/mcp",
            )


if __name__ == "__main__":
    unittest.main()
