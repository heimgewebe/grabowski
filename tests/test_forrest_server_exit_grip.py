from __future__ import annotations

import subprocess
import unittest
from unittest import mock

import grabowski_forrest_server_exit as runtime
import grabowski_grips


PRE = """
# Funnel on:
#     - https://wg-prod-1.tail6dbb90.ts.net:8443
#     - https://wg-prod-1.tail6dbb90.ts.net

https://wg-prod-1.tail6dbb90.ts.net (Funnel on)
|-- / proxy http://127.0.0.1:18000

https://wg-prod-1.tail6dbb90.ts.net:8443 (Funnel on)
|-- / proxy http://127.0.0.1:18090
"""
POST = """
# Funnel on:
#     - https://wg-prod-1.tail6dbb90.ts.net:8443

https://wg-prod-1.tail6dbb90.ts.net:8443 (Funnel on)
|-- / proxy http://127.0.0.1:18090
"""
SOCKETS = "LISTEN 0 4096 127.0.0.1:18090 0.0.0.0:*\n"


def result(argv: list[str], stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")


class ForrestServerExitRuntimeTests(unittest.TestCase):
    def test_apply_removes_only_443_and_preserves_8443(self):
        sequence = [
            result(["tailscale", "serve", "status"], PRE),
            result(["ss", "-ltnH"], SOCKETS),
            result(["tailscale", "serve", "--https=443", "off"]),
            result(["tailscale", "serve", "status"], POST),
            result(["ss", "-ltnH"], SOCKETS),
        ]
        with mock.patch.object(runtime, "_run_remote", side_effect=sequence) as remote:
            output = runtime.apply()
        self.assertTrue(output["ok"])
        self.assertEqual(output["before"]["routes"]["443"], runtime.EXPECTED_443)
        self.assertNotIn("443", output["after"]["routes"])
        self.assertEqual(output["after"]["routes"]["8443"], runtime.PRESERVED_8443)
        self.assertEqual(
            remote.call_args_list[2],
            mock.call(["tailscale", "serve", "--https=443", "off"]),
        )

    def test_apply_fails_before_mutation_when_protected_route_drifts(self):
        drifted = PRE.replace("127.0.0.1:18090", "127.0.0.1:19090")
        sequence = [
            result(["tailscale", "serve", "status"], drifted),
            result(["ss", "-ltnH"], SOCKETS),
        ]
        with mock.patch.object(runtime, "_run_remote", side_effect=sequence) as remote:
            with self.assertRaisesRegex(RuntimeError, "protected 8443"):
                runtime.apply()
        self.assertEqual(remote.call_count, 2)


class ForrestServerExitGripTests(unittest.TestCase):
    def test_surface_exposes_fixed_parameterless_mutation(self):
        self.assertIn("forrest-server-exit-apply", grabowski_grips.GRIP_SURFACE_ALLOWLIST)
        spec = grabowski_grips.GRIP_SPECS["forrest-server-exit-apply"]
        self.assertEqual(spec.required_parameters, ())
        self.assertEqual(spec.effect, grabowski_grips.MUTATING)

    def test_grip_receipt_binds_fixed_effect_and_post_readback(self):
        output = {
            "ok": True,
            "fixedHost": runtime.HOST,
            "removedHttpsPort": 443,
            "removedProxyTarget": runtime.EXPECTED_443,
            "preservedHttpsPort": 8443,
            "preservedProxyTarget": runtime.PRESERVED_8443,
            "before": {
                "routes": {"443": runtime.EXPECTED_443, "8443": runtime.PRESERVED_8443},
                "port18000Listening": False,
                "port18090Listening": True,
                "stateSha256": "a" * 64,
            },
            "after": {
                "routes": {"8443": runtime.PRESERVED_8443},
                "port18000Listening": False,
                "port18090Listening": True,
                "stateSha256": "b" * 64,
            },
            "providerMutationPerformed": True,
        }
        with mock.patch.object(runtime, "apply", return_value=output):
            receipt = grabowski_grips.grip_run(
                "forrest-server-exit-apply", {}, allow_mutation=True
            )
        self.assertEqual(receipt["status"], "passed")
        checks = {item["id"]: item["status"] for item in receipt["receipt"]["checks"]}
        self.assertEqual(checks["https-443-only"], "pass")
        self.assertEqual(checks["protected-8443-preserved"], "pass")
        self.assertEqual(checks["provider-post-readback"], "pass")

    def test_grip_rejects_any_caller_parameter(self):
        receipt = grabowski_grips.grip_run(
            "forrest-server-exit-apply", {"host": "other"}, allow_mutation=True
        )
        self.assertEqual(receipt["status"], "blocked")
        self.assertIn("accepts no caller parameters", receipt["output"]["error"])


if __name__ == "__main__":
    unittest.main()
