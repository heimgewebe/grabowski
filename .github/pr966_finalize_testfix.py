#!/usr/bin/env python3
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "tests" / "test_privileged_broker_peer.py"
text = path.read_text(encoding="utf-8")
start = text.find("    def test_truncated_stderr_blocks_public_output_evidence(")
end = text.find("\n\nif __name__ == \"__main__\":", start)
if start < 0 or end < 0:
    raise SystemExit("truncated stderr test boundary missing")
replacement = r'''    def test_truncated_stderr_blocks_public_output_evidence(self) -> None:
        operation = {
            "kind": "preflight",
            "operation": "apt_preflight",
            "plan_id": "20260827T010203Z-123456abcdef",
            "package_paths": [
                "/var/lib/heim-pc/package-update-stages/20260827T010203Z-123456abcdef/debs/a.deb"
            ],
            "exact_evidence": True,
        }
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (
            b"",
            b"x" * (broker_tool.MAX_OUTPUT_BYTES + 1),
        )
        reference = {
            "request_id": "e" * 32,
            "reference_sha256": "f" * 64,
            "action": broker_tool.POWER_ACTION,
            "target": "{}",
        }
        execution = {
            "mode": "argv-json",
            "argv": ["/usr/bin/true"],
            "cwd": "/",
            "timeout_seconds": 5,
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }
        with (
            mock.patch.object(broker_tool, "_package_stage_operation", return_value=operation),
            mock.patch.object(broker_tool, "_package_stage_lock", return_value=nullcontext()),
            mock.patch.object(
                broker_tool,
                "_find_package_apply_evidence",
                return_value={
                    "evidence_sha256": "a" * 64,
                    "request_id": "b" * 32,
                    "timestamp_unix": int(broker_tool.time.time()),
                },
            ),
            mock.patch.object(broker_tool.subprocess, "Popen", return_value=process),
            mock.patch.object(broker_tool, "append_audit"),
        ):
            result = broker_tool._execute_broker_command(
                reference=reference,
                execution=execution,
                operator_peer=self.peer(),
            )
        self.assertIs(result["record"]["stderr_truncated"], True)
        self.assertEqual(result["output_evidence_status"], "unavailable")
        self._output_evidence.assert_not_called()
'''
path.write_text(text[:start] + replacement + text[end:], encoding="utf-8")
