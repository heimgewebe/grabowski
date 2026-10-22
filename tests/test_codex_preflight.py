"""Synthetic app-server regression tests: no real credentials or provider calls."""
import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import grabowski_codex_preflight as preflight


FAKE_APP_SERVER = r"""
import json
import sys
import time
mode = sys.argv[1]
methods = []
for line in sys.stdin:
    try:
        request = json.loads(line)
    except ValueError:
        sys.exit(3)
    method = request["method"]
    if "id" not in request:
        if method != "initialized":
            sys.exit(4)
        continue
    methods.append(method)
    if method not in {"initialize", "account/read", "account/rateLimits/read", "model/list"}:
        sys.exit(5)
    if mode == "timeout" and method == "account/read":
        time.sleep(5)
    if mode == "partial" and method == "account/read":
        sys.stdout.write('{"jsonrpc":')
        sys.stdout.flush()
        time.sleep(5)
    if mode == "abort" and method == "account/read":
        sys.exit(2)
    if mode in {"remote_notification", "semantic_notification"} and method == "initialize":
        event = "remoteControl/status/changed" if mode == "remote_notification" else "item/reasoning/textDelta"
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "method": event, "params": {}}, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    if mode == "malformed_notification" and method == "initialize":
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "method": {}, "params": {}}) + "\n")
        sys.stdout.flush()
    if mode == "mixed" and method == "initialize":
        sys.stdout.write("unexpected provider text\n")
        sys.stdout.flush()
    if mode == "large" and method == "initialize":
        sys.stdout.write("x" * 140000 + "\n")
        sys.stdout.flush()
    if mode == "refresh_forbidden" and method == "account/read" and request["params"].get("refreshToken") is not False:
        response = {"jsonrpc": "2.0", "id": request["id"], "error": {"code": 409, "message": "forced token refresh forbidden"}}
    elif mode == "revoked" and method == "account/read":
        response = {"jsonrpc": "2.0", "id": request["id"], "error": {"code": 401, "message": "token_revoked"}}
    elif mode in {"transient", "cached_model"} and method == "account/rateLimits/read":
        response = {"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32000, "message": "network failed"}}
    elif mode == "model_error" and method == "model/list":
        response = {"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32600, "message": "provider no longer allowed"}}
    elif method == "initialize":
        response = {"jsonrpc": "2.0", "id": request["id"], "result": {"userAgent": "codex-test", "serverInfo": {"version": "test"}}}
    elif method == "account/read":
        account = {"type": "apiKey"} if mode == "wrong_auth" else {"type": "chatgpt"}
        routing = {"chatgptAccountId": "expected-account"}
        if mode == "no_workspace":
            routing = None
        response = {"jsonrpc": "2.0", "id": request["id"], "result": {
            "account": account, "requiresOpenaiAuth": True, "workspaceRouting": routing,
        }}
    elif method == "account/rateLimits/read":
        response = {"jsonrpc": "2.0", "id": request["id"], "result": {
            "accountId": "other-account" if mode == "wrong_credential" else "expected-account",
            "ordinaryUsageAllowed": False if mode == "quota_denied" else True,
            "rateLimits": {},
        }}
    elif method == "model/list":
        item = {"id": "gpt-5.6-sol", "model": "gpt-5.6-sol", "hidden": False,
            "supportedReasoningEfforts": [{"reasoningEffort": "high"}]}
        if mode == "wrong_model":
            item["model"] = "gpt-5.6-luna"
        if mode == "hidden":
            item["hidden"] = True
        if mode == "wrong_effort":
            item["supportedReasoningEfforts"] = [{"reasoningEffort": "low"}]
        if mode == "no_model":
            data = []
        elif mode == "duplicate_model":
            data = [item, item]
        else:
            data = [item]
        response = {"jsonrpc": "2.0", "id": request["id"], "result": {
            "data": data, "nextCursor": None,
        }}
    else:
        sys.exit(6)
    if mode == "unversioned":
        response.pop("jsonrpc", None)
    if mode == "trailing_semantic" and method == "model/list":
        tail = json.dumps({"jsonrpc": "2.0", "method": "item/reasoning/textDelta", "params": {}})
        sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n" + tail + "\n")
        sys.stdout.flush()
        continue
    sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    if method == "model/list" and mode in {"trailing_delayed", "trailing_allowed_delayed"}:
        time.sleep(0.06)
        event = "item/reasoning/textDelta" if mode == "trailing_delayed" else "remoteControl/status/changed"
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "method": event, "params": {}}) + "\n")
        sys.stdout.flush()
    if method == "model/list" and mode == "exit_nonzero_after_reply":
        sys.exit(2)
    if method == "model/list" and mode == "hold_open_after_reply":
        time.sleep(5)
"""


class CodexPreflightProtocolTests(unittest.TestCase):
    def probe(self, mode="valid", timeout=3):
        return preflight._check_protocol(
            [sys.executable, "-u", "-c", FAKE_APP_SERVER, mode],
            model="gpt-5.6-sol",
            effort="high",
            deadline_seconds=timeout,
        )

    def assert_denied(self, mode, expected=None, timeout=3):
        with self.assertRaises(preflight.CodexPreflightDenied) as caught:
            self.probe(mode, timeout)
        if expected is not None:
            self.assertEqual(expected, caught.exception.code)

    def test_metadata_happy_path_never_invokes_model_thread(self):
        result = self.probe()
        self.assertEqual("metadata_accepted", result["status"])
        self.assertEqual("gpt-5.6-sol", result["model"])
        self.assertTrue(result["no_thread_request_sent"])
        self.assertIn("later_remote_model_inference_success", result["does_not_establish"])

    def test_authoritative_unversioned_json_rpc_reply(self):
        self.assertEqual("metadata_accepted", self.probe("unversioned")["status"])

    def test_real_app_server_remote_control_status_notification_is_nonsemantic(self):
        self.assertEqual("metadata_accepted", self.probe("remote_notification")["status"])

    def test_unsolicited_semantic_notification_remains_forbidden(self):
        self.assert_denied("semantic_notification", "unexpected_notification")

    def test_unhashable_notification_method_denied_not_exception(self):
        self.assert_denied("malformed_notification", "unexpected_notification")

    def test_trailing_semantic_output_after_model_list_denied(self):
        self.assert_denied("trailing_semantic", "unexpected_trailing_output")

    def test_delayed_trailing_semantic_event_is_denied_before_metadata_acceptance(self):
        self.assert_denied("trailing_delayed", "unexpected_trailing_output")

    def test_appserver_that_never_closes_after_stdin_eof_is_denied(self):
        self.assert_denied("hold_open_after_reply", "timeout", timeout=1)

    def test_late_allowed_status_notification_is_drained_before_acceptance(self):
        self.assertEqual("metadata_accepted", self.probe("trailing_allowed_delayed")["status"])

    def test_exit_nonzero_after_complete_model_list_fails_closed(self):
        self.assert_denied("exit_nonzero_after_reply", "transport_closed")

    def test_killpg_permission_failure_does_not_skip_cleanup(self):
        with mock.patch.object(preflight.os, "killpg", side_effect=PermissionError("synthetic deny")):
            self.assertEqual("metadata_accepted", self.probe()["status"])

    def test_preflight_never_forces_shared_auth_refresh(self):
        self.assertEqual("metadata_accepted", self.probe("refresh_forbidden")["status"])

    def test_revoked_token_blocks(self):
        self.assert_denied("revoked", "invalid_rpc_reply")

    def test_transient_refresh_or_usage_failures_block(self):
        self.assert_denied("transient", "invalid_rpc_reply")

    def test_cached_model_cannot_override_failed_remote_usage(self):
        self.assert_denied("cached_model", "invalid_rpc_reply")

    def test_provider_no_longer_allows_model(self):
        self.assert_denied("model_error", "invalid_rpc_reply")

    def test_wrong_auth_and_workspace_identity_fail_closed(self):
        self.assert_denied("wrong_auth", "chatgpt_auth_unavailable")
        self.assert_denied("no_workspace", "workspace_identity_unavailable")
        self.assert_denied("wrong_credential", "credential_workspace_mismatch")

    def test_quota_denial_blocks(self):
        self.assert_denied("quota_denied", "remote_usage_unavailable")

    def test_exact_model_and_effort_match_or_block(self):
        self.assert_denied("wrong_model", "model_identity_mismatch")
        self.assert_denied("hidden", "model_identity_mismatch")
        self.assert_denied("wrong_effort", "model_effort_unavailable")
        self.assert_denied("no_model", "exact_model_unavailable")
        self.assert_denied("duplicate_model", "model_identity_mismatch")

    def test_malformed_mixed_output_denied(self):
        self.assert_denied("mixed", "malformed_output")
        self.assert_denied("large", "oversized_or_mixed_output")

    def test_timeout_partial_and_aborted_preflight(self):
        self.assert_denied("timeout", "timeout", timeout=1)
        self.assert_denied("partial", "timeout", timeout=1)
        self.assert_denied("abort", "transport_closed")

    def test_unapproved_rpc_method_denied_locally(self):
        process = mock.Mock()
        with self.assertRaises(preflight.CodexPreflightDenied) as caught:
            preflight._Rpc(process, 12345.0).call(1, "thread/start", {})
        self.assertEqual("unapproved_method", caught.exception.code)


class CodexPreflightBindingTests(unittest.TestCase):
    route = {"provider_family": "openai", "model": "gpt-5.6-sol"}
    command = [
        "codex", "--model", "gpt-5.6-sol", "-c",
        'model_reasoning_effort="high"', "--sandbox", "read-only",
        "--ask-for-approval", "never", "Read-only review",
    ]

    def test_non_codex_provider_skipped(self):
        self.assertIsNone(preflight.require_codex_review_preflight(
            ["claude", "review"], {"provider_family": "anthropic", "model": "claude-opus-5.5"}
        ))

    def test_codex_bound_route_cannot_skip_preflight_via_renamed_executable(self):
        with self.assertRaises(preflight.CodexPreflightDenied) as caught:
            preflight.require_codex_review_preflight(["/usr/bin/custom-codex-wrapper", "review"], self.route)
        self.assertEqual("not_codex", caught.exception.code)

    def test_catalogue_model_provider_and_effort_exact(self):
        self.assertEqual(("gpt-5.6-sol", "high"), preflight._exact_reviewer_model(self.command, self.route))
        for command, route, expected in (
            (self.command, {"provider_family": "other", "model": "gpt-5.6-sol"}, "provider_mismatch"),
            (self.command, {"provider_family": "openai", "model": "gpt-6-astra"}, "model_identity_mismatch"),
            (["codex", "--model", "gpt-5.6-sol", "review"], self.route, "effort_identity_unavailable"),
            (["codex", "--model", "gpt-5.6-sol", "--model", "other", "-c",
              'model_reasoning_effort="high"', "review"], self.route, "model_identity_unavailable"),
        ):
            with self.subTest(expected=expected):
                with self.assertRaises(preflight.CodexPreflightDenied) as caught:
                    preflight._exact_reviewer_model(command, route)
                self.assertEqual(expected, caught.exception.code)

    def test_owner_dedicated_sandbox_binding_and_no_direct_provider_argv(self):
        from grabowski_agent_sandbox import PreparedSandboxCommand
        fake = PreparedSandboxCommand(
            command=("authenticated-launch", "app-server"),
            extra_read_only=((pathlib.Path("/usr/bin/true"), pathlib.Path("/opt/codex")),),
            extra_read_write=((pathlib.Path("/tmp/auth"), pathlib.Path("/tmp/.codex/auth.json")),),
            extra_directories=(pathlib.Path("/tmp/.codex"),),
        )
        with mock.patch("grabowski_agent_sandbox.prepare_external_agent_command", return_value=fake) as prepare, \
             mock.patch("grabowski_agent_sandbox.minimal_sandbox_argv", return_value=["bounded-bwrap"]) as sandbox, \
             mock.patch("grabowski_agent_sandbox.runtime_sandbox_argv", side_effect=lambda x: x), \
             mock.patch.object(preflight, "_check_protocol", return_value={"status": "metadata_accepted"}) as rpc:
            self.assertEqual(
                {"status": "metadata_accepted"},
                preflight.require_codex_review_preflight(self.command, self.route),
            )
        self.assertEqual(["codex", "--model", "gpt-5.6-sol", "app-server"], prepare.call_args.args[0])
        self.assertFalse(sandbox.call_args.kwargs["workspace_writable"])
        self.assertEqual(fake.extra_read_write, sandbox.call_args.kwargs["extra_read_write"])
        self.assertEqual(["bounded-bwrap"], rpc.call_args.args[0])

    def test_missing_private_auth_fails_closed_without_host_login(self):
        from grabowski_agent_sandbox import AgentSandboxError
        with mock.patch("grabowski_agent_sandbox.prepare_external_agent_command", side_effect=AgentSandboxError("private auth missing")):
            with self.assertRaises(preflight.CodexPreflightDenied) as caught:
                preflight.require_codex_review_preflight(self.command, self.route)
        self.assertEqual("sandbox_unavailable", caught.exception.code)

    def test_unexpected_sandbox_api_type_error_is_still_auditable_denial(self):
        with mock.patch("grabowski_agent_sandbox.prepare_external_agent_command", side_effect=TypeError("untrusted output")):
            with self.assertRaises(preflight.CodexPreflightDenied) as caught:
                preflight.require_codex_review_preflight(self.command, self.route)
        self.assertEqual("sandbox_unavailable", caught.exception.code)


class CodexPreflightAdmissionTests(unittest.TestCase):
    """A failed credential/model preflight never registers an immutable review job."""

    def test_denial_is_audited_without_creating_job_directory(self):
        import tempfile
        from test_operator_contract import _load_operator_module
        operator = _load_operator_module()
        binding = {
            "schema_version": 1, "kind": "grabowski_decision_review_binding",
            "repo": "heimgewebe/grabowski", "pr": 1590,
            "head_sha": "a" * 40, "base_sha": "b" * 40,
            "diff_sha256": "c" * 64, "slot": "independent-codex",
        }
        args = ["python", "-I", "-m", "grabowski_agent_role",
                "--role", "review", "--", *CodexPreflightBindingTests.command]
        with tempfile.TemporaryDirectory() as temporary:
            jobs = pathlib.Path(temporary) / "jobs"
            jobs.mkdir()
            with mock.patch.object(operator, "_jobs_root", return_value=jobs), \
                 mock.patch.object(operator, "_validate_argv", return_value=args), \
                 mock.patch.object(operator, "_cleanup_stale_job_metadata_temps", return_value=[]), \
                 mock.patch.object(operator, "_job_directory", side_effect=AssertionError("job registered")) as created, \
                 mock.patch.object(operator, "_append_effect_audit", return_value="d"*64) as audit, \
                 mock.patch.object(operator.decision_reviews, "bind_job_review_role_argv", return_value=args), \
                 mock.patch.object(operator.decision_reviews, "review_role_provenance", return_value={"review_route": CodexPreflightBindingTests.route}), \
                 mock.patch.object(operator.decision_reviews, "normalize_binding", return_value=binding), \
                 mock.patch.object(preflight, "require_codex_review_preflight",
                                   side_effect=preflight.CodexPreflightDenied("invalid_rpc_reply")):
                with self.assertRaisesRegex(ValueError, "prelaunch admission denied: invalid_rpc_reply"):
                    operator._start_job(args, cwd=temporary, runtime_seconds=60,
                                        decision_review_binding=binding)
            created.assert_not_called()
            self.assertFalse(list(jobs.iterdir()))
            receipt = audit.call_args.args[0]
            self.assertEqual("refused", receipt["decision"])
            self.assertFalse(receipt["job_directory_created"])
            self.assertFalse(receipt["provider_thread_request_sent"])
            self.assertEqual("invalid_rpc_reply", receipt["failure_classification"])


    def test_openai_bound_role_non_codex_argv_rejected_before_job_directory(self):
        import tempfile
        from test_operator_contract import _load_operator_module
        operator = _load_operator_module()
        binding = {
            "schema_version": 1, "kind": "grabowski_decision_review_binding",
            "repo": "heimgewebe/grabowski", "pr": 1616,
            "head_sha": "a" * 40, "base_sha": "b" * 40,
            "diff_sha256": "c" * 64, "slot": "independent-codex",
        }
        args = ["python", "-I", "-m", "grabowski_agent_role",
                "--role", "review", "--", "renamed-openai-client"]
        with tempfile.TemporaryDirectory() as directory:
            jobs = pathlib.Path(directory) / "jobs"
            jobs.mkdir()
            with mock.patch.object(operator, "_jobs_root", return_value=jobs), \
                 mock.patch.object(operator, "_validate_argv", return_value=args), \
                 mock.patch.object(operator, "_cleanup_stale_job_metadata_temps", return_value=[]), \
                 mock.patch.object(operator, "_job_directory", side_effect=AssertionError("registered")) as created, \
                 mock.patch.object(operator, "_append_effect_audit", return_value="d"*64) as audit, \
                 mock.patch.object(operator.decision_reviews, "bind_job_review_role_argv", return_value=args), \
                 mock.patch.object(operator.decision_reviews, "review_role_provenance", return_value={
                     "review_route": {"provider_family": "openai", "model": "gpt-5.6-sol"}
                 }), \
                 mock.patch.object(operator.decision_reviews, "normalize_binding", return_value=binding):
                with self.assertRaisesRegex(ValueError, "prelaunch admission denied: not_codex"):
                    operator._start_job(args, cwd=directory, runtime_seconds=60,
                                        decision_review_binding=binding)
            created.assert_not_called()
            self.assertEqual([], list(jobs.iterdir()))
            self.assertEqual("not_codex", audit.call_args.args[0]["failure_classification"])

    def test_head_or_workspace_drift_after_metadata_blocks_job(self):
        import tempfile
        from test_operator_contract import _load_operator_module
        operator = _load_operator_module()
        binding = {"schema_version": 1, "kind": "grabowski_decision_review_binding",
                   "repo": "heimgewebe/grabowski", "pr": 1590,
                   "head_sha": "a"*40, "base_sha": "b"*40,
                   "diff_sha256": "c"*64, "slot": "independent-codex"}
        args = ["python", "-I", "-m", "grabowski_agent_role",
                "--role", "review", "--", *CodexPreflightBindingTests.command]
        with tempfile.TemporaryDirectory() as temporary:
            jobs = pathlib.Path(temporary) / "jobs"
            jobs.mkdir()
            with mock.patch.object(operator, "_jobs_root", return_value=jobs), \
                 mock.patch.object(operator, "_validate_argv", return_value=args), \
                 mock.patch.object(operator, "_cleanup_stale_job_metadata_temps", return_value=[]), \
                 mock.patch.object(operator, "_job_directory", side_effect=AssertionError("registered")) as created, \
                 mock.patch.object(operator, "_append_effect_audit", return_value="d"*64) as audit, \
                 mock.patch.object(operator.decision_reviews, "bind_job_review_role_argv",
                                   side_effect=[args, ValueError("workspace SHA mismatch")]), \
                 mock.patch.object(operator.decision_reviews, "review_role_provenance", return_value={"review_route": CodexPreflightBindingTests.route}), \
                 mock.patch.object(operator.decision_reviews, "normalize_binding", return_value=binding), \
                 mock.patch.object(preflight, "require_codex_review_preflight",
                                   return_value={"status": "metadata_accepted", "model": "gpt-5.6-sol"}):
                with self.assertRaisesRegex(ValueError, "prelaunch admission denied: workspace_identity_drift"):
                    operator._start_job(args, cwd=temporary, runtime_seconds=60,
                                        decision_review_binding=binding)
            created.assert_not_called()
            self.assertFalse(list(jobs.iterdir()))
            self.assertEqual("workspace_identity_drift", audit.call_args.args[0]["failure_classification"])


if __name__ == "__main__":
    unittest.main()