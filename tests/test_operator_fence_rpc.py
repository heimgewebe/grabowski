from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import grabowski_operator_fence as fence
import grabowski_operator_fence_rpc as rpc


INTENT = "a" * 64
EVIDENCE = "b" * 64


class Clock:
    def __init__(self, value: int = 1_000) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += seconds


def request(request_id: str, operation: str, **arguments: object) -> dict[str, object]:
    return rpc.request_document(
        request_id=request_id,
        operation=operation,
        arguments=arguments,
    )


class OperatorFenceRpcTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / "state" / "operator-fence.sqlite3"
        self.clock = Clock()
        self.store = fence.OperatorFenceStore(self.database, clock=self.clock)

    def ssh_material(self) -> tuple[Path, Path]:
        known_hosts = self.root / "known_hosts"
        known_hosts.write_text("heimberry ssh-ed25519 AAAATEST\n", encoding="utf-8")
        os.chmod(known_hosts, 0o600)
        identity_file = self.root / "operator-fence-key"
        identity_file.write_text("test-private-key-placeholder\n", encoding="utf-8")
        os.chmod(identity_file, 0o600)
        return known_hosts, identity_file

    def ssh_client(self) -> rpc.OperatorFenceSshClient:
        known_hosts, identity_file = self.ssh_material()
        return rpc.OperatorFenceSshClient(
            host="heimberry",
            remote_user="alex",
            expected_peer_id="grabowski",
            known_hosts_path=known_hosts,
            identity_file=identity_file,
        )

    def test_peer_identity_is_injected_and_cannot_be_spoofed(self) -> None:
        grant = rpc.dispatch_request(
            self.store,
            peer_id="grabowski",
            request=request(
                "r1",
                "acquire",
                session_id="primary-session",
                reason="primary_normal",
                lease_seconds=30,
            ),
        )
        self.assertTrue(grant["ok"])
        self.assertEqual(grant["result"]["owner_id"], "grabowski")

        spoofed = {
            "schema_version": 1,
            "kind": rpc.REQUEST_KIND,
            "request_id": "r2",
            "operation": "acquire",
            "arguments": {
                "owner_id": "der-kleine-maulwurf",
                "session_id": "primary-session",
                "reason": "primary_normal",
                "lease_seconds": 30,
            },
        }
        with self.assertRaises(rpc.OperatorFenceRpcError):
            rpc.dispatch_request(self.store, peer_id="grabowski", request=spoofed)

    def test_second_peer_is_denied_while_primary_writer_is_live(self) -> None:
        first = rpc.dispatch_request(
            self.store,
            peer_id="grabowski",
            request=request(
                "primary-acquire",
                "acquire",
                session_id="primary-session",
                reason="primary_normal",
                lease_seconds=30,
            ),
        )
        self.assertTrue(first["ok"])
        second = rpc.dispatch_request(
            self.store,
            peer_id="der-kleine-maulwurf",
            request=request(
                "secondary-acquire",
                "acquire",
                session_id="secondary-session",
                reason="primary_unavailable",
                lease_seconds=30,
            ),
        )
        self.assertFalse(second["ok"])
        self.assertEqual(second["error"], {"kind": "denied", "code": "writer_active"})

    def test_unresolved_effect_blocks_secondary_takeover_after_lease_expiry(self) -> None:
        grant = rpc.dispatch_request(
            self.store,
            peer_id="grabowski",
            request=request(
                "a1",
                "acquire",
                session_id="primary-session",
                reason="primary_normal",
                lease_seconds=5,
            ),
        )
        generation = int(grant["result"]["generation"])
        begun = rpc.dispatch_request(
            self.store,
            peer_id="grabowski",
            request=request(
                "b1",
                "begin",
                session_id="primary-session",
                generation=generation,
                operation_id="op-1",
                operation_name="grabowski_git",
                intent_sha256=INTENT,
            ),
        )
        self.assertTrue(begun["ok"])
        unknown = rpc.dispatch_request(
            self.store,
            peer_id="grabowski",
            request=request(
                "s1",
                "settle",
                session_id="primary-session",
                generation=generation,
                operation_id="op-1",
                operation_name="grabowski_git",
                intent_sha256=INTENT,
                outcome="outcome_unknown",
                evidence_sha256=EVIDENCE,
            ),
        )
        self.assertTrue(unknown["ok"])
        self.assertFalse(unknown["result"]["terminal"])
        self.clock.advance(6)
        takeover = rpc.dispatch_request(
            self.store,
            peer_id="der-kleine-maulwurf",
            request=request(
                "a2",
                "acquire",
                session_id="secondary-session",
                reason="primary_unavailable",
                lease_seconds=30,
            ),
        )
        self.assertFalse(takeover["ok"])
        self.assertEqual(
            takeover["error"], {"kind": "denied", "code": "unresolved_inflight"}
        )

    def test_reconciler_identity_is_bound_to_authenticated_peer(self) -> None:
        grant = self.store.acquire(
            owner_id="grabowski",
            session_id="primary-session",
            reason="primary_normal",
            lease_seconds=5,
        )
        generation = int(grant["generation"])
        self.store.begin_effect(
            owner_id="grabowski",
            session_id="primary-session",
            generation=generation,
            operation_id="op-1",
            operation_name="grabowski_git",
            intent_sha256=INTENT,
        )
        self.store.settle_effect(
            owner_id="grabowski",
            session_id="primary-session",
            generation=generation,
            operation_id="op-1",
            operation_name="grabowski_git",
            intent_sha256=INTENT,
            outcome="outcome_unknown",
            evidence_sha256=EVIDENCE,
        )
        self.clock.advance(6)
        reconciled = rpc.dispatch_request(
            self.store,
            peer_id="der-kleine-maulwurf",
            request=request(
                "reconcile-1",
                "reconcile",
                generation=generation,
                operation_id="op-1",
                operation_name="grabowski_git",
                intent_sha256=INTENT,
                outcome="effect_applied",
                evidence_sha256="c" * 64,
            ),
        )
        self.assertTrue(reconciled["ok"])
        self.assertEqual(
            reconciled["result"]["recorded_settlement"]["reconciler_id"],
            "der-kleine-maulwurf",
        )

    def test_serve_requires_the_forced_command_sentinel_before_touching_state(self) -> None:
        raw = rpc._canonical_json_bytes(request("status-1", "status")) + b"\n"
        output = BytesIO()
        rc = rpc.serve_once(
            state_path=self.root / "uncreated" / "fence.sqlite3",
            peer_id="grabowski",
            input_stream=BytesIO(raw),
            output_stream=output,
            environment={"SSH_ORIGINAL_COMMAND": "unexpected"},
        )
        self.assertEqual(rc, 0)
        response = json.loads(output.getvalue())
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "unexpected_original_command")
        self.assertFalse((self.root / "uncreated").exists())

    def test_serve_local_round_trip_uses_exact_request_contract(self) -> None:
        raw = rpc._canonical_json_bytes(request("status-1", "status")) + b"\n"
        output = BytesIO()
        rc = rpc.serve_once(
            state_path=self.root / "rpc" / "fence.sqlite3",
            peer_id="grabowski",
            input_stream=BytesIO(raw),
            output_stream=output,
            required_original_command=None,
            environment={},
        )
        self.assertEqual(rc, 0)
        response = json.loads(output.getvalue())
        self.assertTrue(response["ok"])
        self.assertEqual(response["request_id"], "status-1")
        self.assertEqual(response["peer_id"], "grabowski")
        self.assertEqual(response["result"]["generation"], 0)

    def test_protocol_is_one_request_bounded_and_rejects_extra_arguments(self) -> None:
        with self.assertRaises(rpc.OperatorFenceRpcError):
            rpc.request_document(
                request_id="bad",
                operation="status",
                arguments={"unexpected": True},
            )
        with self.assertRaises(rpc.OperatorFenceRpcError):
            rpc._request_from_bytes(b"x" * (rpc.MAX_REQUEST_BYTES + 1))

    def test_ssh_client_requires_pinned_host_and_dedicated_private_identity(self) -> None:
        known_hosts, identity_file = self.ssh_material()
        client = rpc.OperatorFenceSshClient(
            host="heimberry",
            remote_user="alex",
            expected_peer_id="grabowski",
            known_hosts_path=known_hosts,
            identity_file=identity_file,
        )
        argv = client.ssh_argv()
        self.assertEqual(argv[0], "/usr/bin/ssh")
        self.assertEqual(argv[1:3], ["-F", "/dev/null"])
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("ClearAllForwardings=yes", argv)
        self.assertIn("ForwardAgent=no", argv)
        self.assertIn("ForwardX11=no", argv)
        self.assertIn("ControlMaster=no", argv)
        self.assertIn("ControlPath=none", argv)
        self.assertIn("ControlPersist=no", argv)
        self.assertIn("ProxyCommand=none", argv)
        self.assertIn("ProxyJump=none", argv)
        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertIn("IdentityAgent=none", argv)
        self.assertIn("NumberOfPasswordPrompts=0", argv)
        self.assertIn("PasswordAuthentication=no", argv)
        self.assertIn("KbdInteractiveAuthentication=no", argv)
        self.assertIn("GSSAPIAuthentication=no", argv)
        self.assertIn("HostbasedAuthentication=no", argv)
        self.assertIn("PubkeyAuthentication=yes", argv)
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn(f"UserKnownHostsFile={known_hosts}", argv)
        self.assertIn("GlobalKnownHostsFile=/dev/null", argv)
        self.assertIn("UpdateHostKeys=no", argv)
        self.assertIn("VerifyHostKeyDNS=no", argv)
        self.assertIn(str(identity_file), argv)
        self.assertEqual(argv[-1], rpc.REMOTE_COMMAND)

        os.chmod(known_hosts, 0o622)
        with self.assertRaises(rpc.OperatorFenceRpcError) as unsafe_hosts:
            rpc.OperatorFenceSshClient(
                host="heimberry",
                remote_user="alex",
                expected_peer_id="grabowski",
                known_hosts_path=known_hosts,
                identity_file=identity_file,
            )
        self.assertEqual(unsafe_hosts.exception.code, "unsafe_known_hosts")

        os.chmod(known_hosts, 0o600)
        os.chmod(identity_file, 0o644)
        with self.assertRaises(rpc.OperatorFenceRpcError) as unsafe_identity:
            rpc.OperatorFenceSshClient(
                host="heimberry",
                remote_user="alex",
                expected_peer_id="grabowski",
                known_hosts_path=known_hosts,
                identity_file=identity_file,
            )
        self.assertEqual(unsafe_identity.exception.code, "unsafe_identity_file")

        os.chmod(identity_file, 0o600)
        with self.assertRaises(rpc.OperatorFenceRpcError) as invalid_host:
            rpc.OperatorFenceSshClient(
                host="-F",
                remote_user="alex",
                expected_peer_id="grabowski",
                known_hosts_path=known_hosts,
                identity_file=identity_file,
            )
        self.assertEqual(invalid_host.exception.code, "invalid_host")

        with self.assertRaises(rpc.OperatorFenceRpcError) as invalid_user:
            rpc.OperatorFenceSshClient(
                host="heimberry",
                remote_user="-oProxyCommand=evil",
                expected_peer_id="grabowski",
                known_hosts_path=known_hosts,
                identity_file=identity_file,
            )
        self.assertEqual(invalid_user.exception.code, "invalid_remote_user")

    def test_ssh_client_rejects_response_for_wrong_forced_peer(self) -> None:
        client = self.ssh_client()
        response = {
            "schema_version": 1,
            "kind": rpc.RESPONSE_KIND,
            "request_id": "r1",
            "peer_id": "der-kleine-maulwurf",
            "ok": True,
            "result": {"generation": 1},
            "error": None,
        }
        completed = subprocess.CompletedProcess(
            args=client.ssh_argv(),
            returncode=0,
            stdout=rpc._canonical_json_bytes(response) + b"\n",
            stderr=b"",
        )
        with mock.patch.object(rpc.subprocess, "run", return_value=completed):
            with self.assertRaises(rpc.OperatorFenceRpcError) as caught:
                client.call(request("r1", "status"))
        self.assertEqual(caught.exception.code, "response_binding_mismatch")

    def test_ssh_client_sends_canonical_request_without_shell(self) -> None:
        client = self.ssh_client()
        response = {
            "schema_version": 1,
            "kind": rpc.RESPONSE_KIND,
            "request_id": "r1",
            "peer_id": "grabowski",
            "ok": True,
            "result": {"generation": 0},
            "error": None,
        }
        completed = subprocess.CompletedProcess(
            args=client.ssh_argv(),
            returncode=0,
            stdout=rpc._canonical_json_bytes(response) + b"\n",
            stderr=b"",
        )
        with mock.patch.object(rpc.subprocess, "run", return_value=completed) as run:
            result = client.call(request("r1", "status"))
        self.assertTrue(result["ok"])
        call = run.call_args
        self.assertIsInstance(call.args[0], list)
        self.assertEqual(
            call.kwargs["input"],
            rpc._canonical_json_bytes(request("r1", "status")) + b"\n",
        )
        self.assertFalse(call.kwargs["check"])


if __name__ == "__main__":
    unittest.main()
