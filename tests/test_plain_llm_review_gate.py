from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40
BASE = "b" * 40
DIFF_SHA = "0" * 64
REVIEW_FOCUS = [
    "correctness",
    "regression_risk",
    "tests",
    "security",
    "integration",
]
PLAIN_REVIEW_TEXT = '{"verdict":"PASS","finding_count":0,"findings":[]}'
PLAIN_ARTIFACT_ROOT: Path
PLAIN_RAW_REVIEW_PATH: Path
_PLAIN_ARTIFACT_DIRECTORY = None


def setUpModule() -> None:
    global _PLAIN_ARTIFACT_DIRECTORY
    global PLAIN_ARTIFACT_ROOT
    global PLAIN_RAW_REVIEW_PATH
    _PLAIN_ARTIFACT_DIRECTORY = tempfile.TemporaryDirectory()
    PLAIN_ARTIFACT_ROOT = Path(_PLAIN_ARTIFACT_DIRECTORY.name)
    PLAIN_RAW_REVIEW_PATH = PLAIN_ARTIFACT_ROOT / "review.txt"
    PLAIN_RAW_REVIEW_PATH.write_text(PLAIN_REVIEW_TEXT, encoding="utf-8")
    PLAIN_RAW_REVIEW_PATH.chmod(0o600)


def tearDownModule() -> None:
    if _PLAIN_ARTIFACT_DIRECTORY is not None:
        _PLAIN_ARTIFACT_DIRECTORY.cleanup()


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "plain_llm_review_gate_test",
        ROOT / "tools" / "pr_review_gate.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _evaluate_review_gate(state, **kwargs):
    kwargs.setdefault(
        "external_review_artifact_root",
        PLAIN_ARTIFACT_ROOT,
    )
    return gate.evaluate_review_gate(state, **kwargs)


def _state() -> dict[str, object]:
    return {
        "repoName": "heimgewebe/grabowski",
        "pr_diff_sha256": DIFF_SHA,
        "pr_diff_text": "diff --git a/x b/x\n+changed\n",
        "pr": {
            "number": 7,
            "title": "test change",
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": "CLEAN",
            "mergeable": "MERGEABLE",
            "headRefOid": HEAD,
            "baseRefOid": BASE,
            "changedFiles": 1,
            "additions": 1,
            "deletions": 0,
            "files": [{"path": "tools/pr_review_gate.py"}],
        },
        "checks": [
            {"name": "validate (3.10)", "bucket": "pass"},
            {"name": "validate (3.12)", "bucket": "pass"},
        ],
    }


def _self_review() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "grabowski_self_review",
        "review_mode": "critical_diff_review",
        "reviewer": "grabowski-self",
        "repo": "heimgewebe/grabowski",
        "pr": 7,
        "head_sha": HEAD,
        "base_sha": BASE,
        "diff_sha256": DIFF_SHA,
        "diff_reviewed": True,
        "reviewed_files": ["tools/pr_review_gate.py"],
        "review_focus": REVIEW_FOCUS,
        "verdict": "PASS",
        "review_iterations": [
            {
                "n": n,
                "summary": f"distinct review pass {n}",
                "material_findings": 0,
            }
            for n in range(1, 5)
        ],
        "all_findings_triaged": True,
        "findings": [],
        "material_findings_remaining": 0,
        "material_findings_after_first_review": 0,
        "uncertainty": 0.1,
        "stop_reason": "clean_pass",
        "residual_risk": {"accepted": False, "reason": ""},
    }


def _plain_external_evidence(
    state: dict[str, object],
    *,
    provider: str = "grok",
    model: str = "grok-4.6",
) -> dict[str, object]:
    diff_filename = f"pr-7-{HEAD[:12]}.diff"
    packet_prompt = gate.build_external_review_prompt(
        state, diff_filename, DIFF_SHA
    )
    prompt_nonce = "1" * 32
    prompt = gate.build_plain_llm_review_prompt(
        packet_prompt, str(state["pr_diff_text"]), prompt_nonce
    )
    prompt_sha256 = gate._sha256_text(prompt)
    packet_prompt_sha256 = gate._sha256_text(packet_prompt)
    response_sha256 = gate._sha256_text(PLAIN_REVIEW_TEXT)
    prompt_path = PLAIN_ARTIFACT_ROOT / "prompt.txt"
    prompt_path.write_text(prompt, encoding="utf-8")
    prompt_path.chmod(0o600)
    parsed_review_sha256 = gate.plain_llm_review_payload_sha256(
        verdict="PASS",
        finding_count=0,
        findings=[],
    )
    provider_argv = None
    argv_sha256 = "3" * 64
    if provider == "ox-alpha":
        provider_argv = [
            "/private/ox-alpha",
            "run",
            "--pure",
            "--agent",
            gate.PLAIN_LLM_OX_ALPHA_AGENT,
            "--model",
            gate.PLAIN_LLM_OX_ALPHA_MODEL,
            "--file",
            "/private/plain-review-prompt.txt",
            gate.PLAIN_LLM_OX_ALPHA_PROMPT_MESSAGE,
        ]
        argv_sha256 = hashlib.sha256(
            json.dumps(
                provider_argv,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    return {
        "schema_version": 1,
        "kind": "external_review",
        "repo": "heimgewebe/grabowski",
        "pr": 7,
        "head_sha": HEAD,
        "diff_sha256": DIFF_SHA,
        "prompt_sha256": prompt_sha256,
        "prompt_includes_diff": True,
        "prompt_transmitted": True,
        "review_input": {
            "mode": gate.PLAIN_LLM_REVIEW_INPUT_MODE,
            "repo": "heimgewebe/grabowski",
            "pr": 7,
            "head_sha": HEAD,
            "diff_sha256": DIFF_SHA,
            "transport": (
                "prompt_file"
                if provider in {"grok", "ox-alpha"}
                else "argv"
            ),
            "account_transport": "account_cli",
            "provider": provider,
            "requested_model": model,
            "model_identity_attestation": (
                "requested_not_provider_attested"
            ),
            "executable": f"/private/{provider}",
            "requested_executable": provider,
            "executable_identity": (
                "canonical_native_owner_controlled"
                if provider == "grok"
                else "owner_regular_executable_not_group_world_writable"
            ),
            "packet_prompt_sha256": packet_prompt_sha256,
            "prompt_sha256": prompt_sha256,
            "prompt_nonce": prompt_nonce,
            "prompt_argument_exposure": provider == "gemini",
            "ephemeral_prompt_file": provider in {"grok", "ox-alpha"},
            "context_attestation": (
                "public-context" if provider == "ox-alpha" else None
            ),
            "paid_fallback_policy": (
                gate.PLAIN_LLM_OX_ALPHA_PAID_FALLBACK_POLICY
                if provider == "ox-alpha"
                else "not_established_by_adapter"
            ),
            "provider_argv": provider_argv,
            "runtime_isolation": (
                gate.PLAIN_LLM_OX_ALPHA_RUNTIME_ISOLATION
                if provider == "ox-alpha"
                else None
            ),
            "agent_name": (
                gate.PLAIN_LLM_OX_ALPHA_AGENT if provider == "ox-alpha" else None
            ),
            "agent_config_sha256": (
                gate.PLAIN_LLM_OX_ALPHA_AGENT_CONFIG_SHA256
                if provider == "ox-alpha"
                else None
            ),
            "account_auth_copy_policy": (
                gate.PLAIN_LLM_OX_ALPHA_AUTH_COPY_POLICY
                if provider == "ox-alpha"
                else None
            ),
            "transmitted_prompt_bytes": len(prompt.encode("utf-8")),
            "transmitted_prompt_path": str(prompt_path),
            "raw_review_path": str(PLAIN_RAW_REVIEW_PATH),
            "isolated_working_directory": True,
            "local_repository_context_provided": False,
            "web_search_policy": (
                "disabled_by_cli"
                if provider == "grok"
                else "forbidden_by_prompt_unverified"
            ),
            "memory_policy": (
                "disabled_by_cli"
                if provider == "grok"
                else "new_single_turn_no_resume"
            ),
            "quota_attestation": "not_established_by_adapter",
            "review_gate_authority": gate.PLAIN_LLM_REVIEW_GATE_AUTHORITY,
            "environment_policy": gate.PLAIN_LLM_ENVIRONMENT_POLICY,
            "environment_passed_keys": sorted(
                gate.PLAIN_LLM_REQUIRED_ENVIRONMENT_KEYS
            ),
            "session_environment_removed": [],
            "session_bus_exposed": False,
            "stdin_policy": "null_device",
            "process_group_isolated": True,
            "provider_output_limit_enforcement": "kill_process_group",
            "workspace_readback": "unchanged",
            "billable_api_environment_removed": [],
            "git_context_environment_removed": [],
        },
        "reviews": [
            {
                "source": f"plain-llm:{provider}:{model}",
                "provider": provider,
                "model": model,
                "transport": "account_cli",
                "execution_mode": "single_turn",
                "tool_policy": (
                    "empty_tools_plan_mode"
                    if provider == "grok"
                    else (
                        gate.PLAIN_LLM_OX_ALPHA_TOOL_POLICY
                        if provider == "ox-alpha"
                        else "sandboxed_plan_mode"
                    )
                ),
                "argv_sha256": argv_sha256,
                "stdout_sha256": response_sha256,
                "stderr_sha256": "4" * 64,
                "review_sha256": response_sha256,
                "parsed_review_sha256": parsed_review_sha256,
                "verdict": "PASS",
                "finding_count": 0,
                "findings": [],
            }
        ],
        "external_reviews_triaged": True,
        "findings": [],
    }


def _claude_external_evidence(
    state: dict[str, object],
) -> dict[str, object]:
    diff_filename = f"pr-7-{HEAD[:12]}.diff"
    packet_prompt = gate.build_external_review_prompt(
        state, diff_filename, DIFF_SHA
    )
    prompt_nonce = "5" * 32
    prompt = gate.build_claude_review_prompt(
        packet_prompt, str(state["pr_diff_text"]), prompt_nonce
    )
    prompt_sha256 = gate._sha256_text(prompt)
    return {
        "schema_version": 1,
        "kind": "external_review",
        "repo": "heimgewebe/grabowski",
        "pr": 7,
        "head_sha": HEAD,
        "diff_sha256": DIFF_SHA,
        "prompt_sha256": prompt_sha256,
        "prompt_includes_diff": True,
        "prompt_transmitted": True,
        "review_input": {
            "mode": gate.CLAUDE_CLI_REVIEW_INPUT_MODE,
            "repo": "heimgewebe/grabowski",
            "pr": 7,
            "head_sha": HEAD,
            "diff_sha256": DIFF_SHA,
            "packet_prompt_sha256": gate._sha256_text(packet_prompt),
            "prompt_nonce": prompt_nonce,
            "prompt_sha256": prompt_sha256,
            "transport": "stdin",
        },
        "reviews": [
            {
                "source": gate.CLAUDE_CLI_REVIEW_SOURCE,
                "tool": "claude-code",
                "tool_version": "test",
                "command": [
                    "claude",
                    "-p",
                    "--output-format",
                    "json",
                    "--json-schema",
                    json.dumps(gate.CLAUDE_PACKET_REVIEW_SCHEMA),
                    "--tools=",
                    "--permission-mode",
                    "plan",
                    "--no-session-persistence",
                    "--safe-mode",
                    "--model",
                    "opus",
                    "--effort",
                    "high",
                    "--max-budget-usd",
                    "1",
                ],
                "stdin_sha256": prompt_sha256,
                "model": "opus",
                "effort": "high",
                "exit_code": 0,
                "json_ok": True,
                "review_sha256": "6" * 64,
                "verdict": "PASS",
                "finding_count": 0,
            }
        ],
        "external_reviews_triaged": True,
        "findings": [],
    }


def _warnings(result: dict[str, object]) -> str:
    return "\n".join(str(item) for item in result.get("warnings", []))


class PlainLlmReviewGateTests(unittest.TestCase):
    def test_valid_grok_evidence_is_independently_bound(self) -> None:
        state = _state()
        result = _evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=_plain_external_evidence(state),
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertNotIn(
            "Optional external review evidence invalid", _warnings(result)
        )

    def test_valid_gemini_evidence_is_independently_bound(self) -> None:
        state = _state()
        result = _evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=_plain_external_evidence(
                state,
                provider="gemini",
                model="Gemini 3.1 Pro (Low)",
            ),
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertNotIn(
            "Optional external review evidence invalid", _warnings(result)
        )

    def test_valid_ox_alpha_evidence_is_independently_bound(self) -> None:
        state = _state()
        result = _evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=_plain_external_evidence(
                state,
                provider="ox-alpha",
                model=gate.PLAIN_LLM_OX_ALPHA_MODEL,
            ),
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertNotIn(
            "Optional external review evidence invalid", _warnings(result)
        )

    def test_ox_alpha_evidence_fails_closed_on_unsafe_provider_policy(self) -> None:
        state = _state()
        evidence = _plain_external_evidence(
            state,
            provider="ox-alpha",
            model=gate.PLAIN_LLM_OX_ALPHA_MODEL,
        )
        evidence["review_input"]["context_attestation"] = "private-context"
        evidence["review_input"]["paid_fallback_policy"] = "not_established_by_adapter"
        result = _evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=evidence,
        )
        warnings = _warnings(result)
        self.assertIn(
            "review_input.context_attestation is unsafe for Ox Alpha", warnings
        )
        self.assertIn(
            "review_input.paid_fallback_policy is unsafe for Ox Alpha", warnings
        )

    def test_ox_alpha_evidence_rejects_runtime_or_argv_drift(self) -> None:
        state = _state()
        evidence = _plain_external_evidence(
            state,
            provider="ox-alpha",
            model=gate.PLAIN_LLM_OX_ALPHA_MODEL,
        )
        evidence["review_input"]["runtime_isolation"] = "shared-user-config"
        evidence["review_input"]["agent_config_sha256"] = "f" * 64
        evidence["review_input"]["provider_argv"][4] = "plan"
        result = _evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=evidence,
        )
        warnings = _warnings(result)
        self.assertIn(
            "review_input.runtime_isolation is unsafe for Ox Alpha", warnings
        )
        self.assertIn(
            "review_input.agent_config_sha256 mismatch for Ox Alpha", warnings
        )
        self.assertIn(
            "review_input.provider_argv policy mismatch for Ox Alpha", warnings
        )
        self.assertIn(
            "argv_sha256 does not match Ox Alpha provider_argv", warnings
        )

    def test_prompt_hash_is_reconstructed_not_trusted(self) -> None:
        state = _state()
        evidence = _plain_external_evidence(state)
        evidence["prompt_sha256"] = "f" * 64
        evidence["review_input"]["prompt_sha256"] = "f" * 64
        result = _evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn(
            "does not match independently reconstructed plain-LLM prompt",
            _warnings(result),
        )

    def test_prompt_byte_count_is_reconstructed_not_trusted(self) -> None:
        state = _state()
        evidence = _plain_external_evidence(state)
        evidence["review_input"]["transmitted_prompt_bytes"] += 1
        result = _evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn(
            "transmitted_prompt_bytes does not match independently "
            "reconstructed plain-LLM prompt",
            _warnings(result),
        )

    def test_retained_transmitted_prompt_must_exist(self) -> None:
        state = _state()
        evidence = _plain_external_evidence(state)
        with tempfile.TemporaryDirectory() as directory:
            artifact_root = Path(directory)
            raw_review = artifact_root / "review.txt"
            raw_review.write_text(PLAIN_REVIEW_TEXT, encoding="utf-8")
            raw_review.chmod(0o600)
            evidence["review_input"]["raw_review_path"] = str(raw_review)
            evidence["review_input"]["transmitted_prompt_path"] = str(
                artifact_root / "missing-prompt.txt"
            )
            result = _evaluate_review_gate(
                state,
                self_review=_self_review(),
                external_review_evidence=evidence,
                external_review_artifact_root=artifact_root,
            )
        self.assertIn(
            "cannot read retained transmitted prompt artifact",
            _warnings(result),
        )

    def test_retained_transmitted_prompt_is_reconstructed_and_bound(
        self,
    ) -> None:
        state = _state()
        evidence = _plain_external_evidence(state)
        expected_prompt = (PLAIN_ARTIFACT_ROOT / "prompt.txt").read_text(
            encoding="utf-8"
        )
        with tempfile.TemporaryDirectory() as directory:
            artifact_root = Path(directory)
            raw_review = artifact_root / "review.txt"
            raw_review.write_text(PLAIN_REVIEW_TEXT, encoding="utf-8")
            raw_review.chmod(0o600)
            prompt = artifact_root / "prompt.txt"
            prompt.write_text(expected_prompt + "tampered", encoding="utf-8")
            prompt.chmod(0o600)
            evidence["review_input"]["raw_review_path"] = str(raw_review)
            evidence["review_input"]["transmitted_prompt_path"] = str(prompt)
            result = _evaluate_review_gate(
                state,
                self_review=_self_review(),
                external_review_evidence=evidence,
                external_review_artifact_root=artifact_root,
            )
        warnings = _warnings(result)
        self.assertIn(
            "prompt_sha256 does not match retained transmitted prompt artifact",
            warnings,
        )
        self.assertIn(
            "transmitted_prompt_bytes does not match retained transmitted "
            "prompt artifact",
            warnings,
        )
        self.assertIn(
            "retained transmitted prompt artifact does not match "
            "independently reconstructed plain-LLM prompt",
            warnings,
        )

    def test_source_and_tool_policy_are_provider_bound(self) -> None:
        state = _state()
        evidence = _plain_external_evidence(state)
        review = evidence["reviews"][0]
        review["source"] = "plain-llm:gemini:grok-4.6"
        review["tool_policy"] = "sandboxed_plan_mode"
        result = _evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=evidence,
        )
        warnings = _warnings(result)
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn(
            "source does not match provider and requested model", warnings
        )
        self.assertIn(
            "tool_policy does not match provider contract", warnings
        )

    def test_parsed_review_fields_are_bound_to_retained_raw_response(
        self,
    ) -> None:
        evidence = _plain_external_evidence(_state())
        review = evidence["reviews"][0]
        review.update(
            verdict="BLOCK",
            finding_count=1,
            findings=[
                {
                    "severity": "high",
                    "summary": "Original concrete issue",
                    "file": "tools/example.py",
                    "line": 7,
                    "fix": "Repair the issue",
                }
            ],
        )
        review["findings"][0]["summary"] = "Edited after retention"
        review["parsed_review_sha256"] = (
            gate.plain_llm_review_payload_sha256(
                verdict=review["verdict"],
                finding_count=review["finding_count"],
                findings=review["findings"],
            )
        )
        self.assertEqual(
            gate._plain_llm_external_review_failures(
                review,
                evidence["review_input"],
                retained_review_sha256=gate._sha256_text(
                    PLAIN_REVIEW_TEXT
                ),
                retained_review={
                    "verdict": "PASS",
                    "finding_count": 0,
                    "findings": [],
                },
                retained_review_failure=None,
            ),
            [
                "structured review payload does not match retained raw "
                "review artifact"
            ],
        )

    def test_retained_raw_review_hash_is_recomputed(self) -> None:
        state = _state()
        evidence = _plain_external_evidence(state)
        with tempfile.TemporaryDirectory() as directory:
            artifact_root = Path(directory)
            raw_review = artifact_root / "review.txt"
            raw_review.write_text(PLAIN_REVIEW_TEXT + "\n", encoding="utf-8")
            raw_review.chmod(0o600)
            evidence["review_input"]["raw_review_path"] = str(raw_review)
            result = _evaluate_review_gate(
                state,
                self_review=_self_review(),
                external_review_evidence=evidence,
                external_review_artifact_root=artifact_root,
            )
        self.assertIn(
            "stdout_sha256 does not match retained raw review artifact",
            _warnings(result),
        )

    def test_retained_raw_review_cannot_escape_explicit_root(self) -> None:
        state = _state()
        evidence = _plain_external_evidence(state)
        with tempfile.TemporaryDirectory() as directory:
            result = _evaluate_review_gate(
                state,
                self_review=_self_review(),
                external_review_evidence=evidence,
                external_review_artifact_root=Path(directory),
            )
        self.assertIn(
            "retained raw review artifact path escapes artifact root",
            _warnings(result),
        )

    def test_retained_raw_review_rejects_symlink_and_public_file(
        self,
    ) -> None:
        state = _state()
        for unsafe_kind in ("symlink", "public"):
            with (
                self.subTest(unsafe_kind=unsafe_kind),
                tempfile.TemporaryDirectory() as directory,
            ):
                artifact_root = Path(directory)
                raw_review = artifact_root / "review.txt"
                if unsafe_kind == "symlink":
                    target = artifact_root / "target.txt"
                    target.write_text(PLAIN_REVIEW_TEXT, encoding="utf-8")
                    target.chmod(0o600)
                    raw_review.symlink_to(target.name)
                else:
                    raw_review.write_text(PLAIN_REVIEW_TEXT, encoding="utf-8")
                    raw_review.chmod(0o644)
                evidence = _plain_external_evidence(state)
                evidence["review_input"]["raw_review_path"] = str(raw_review)
                result = _evaluate_review_gate(
                    state,
                    self_review=_self_review(),
                    external_review_evidence=evidence,
                    external_review_artifact_root=artifact_root,
                )
            self.assertIn(
                "retained raw review artifact is invalid",
                _warnings(result),
            )

    def test_reserved_source_cannot_downgrade_to_legacy_input_mode(
        self,
    ) -> None:
        state = _state()
        for tampered_mode in (None, "legacy-external-review-v1"):
            with self.subTest(tampered_mode=tampered_mode):
                evidence = _plain_external_evidence(state)
                review_input = evidence["review_input"]
                if tampered_mode is None:
                    review_input.pop("mode")
                else:
                    review_input["mode"] = tampered_mode
                result = _evaluate_review_gate(
                    state,
                    self_review=_self_review(),
                    external_review_evidence=evidence,
                )
                self.assertEqual(result["verdict"], "PASS")
                self.assertIn(
                    "review_input.mode is not "
                    f"{gate.PLAIN_LLM_REVIEW_INPUT_MODE}",
                    _warnings(result),
                )

    def test_reserved_claude_source_cannot_skip_prompt_binding(
        self,
    ) -> None:
        state = _state()
        valid = _evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=_claude_external_evidence(state),
        )
        self.assertNotIn(
            "Optional external review evidence invalid", _warnings(valid)
        )

        for tampered_mode in (None, "legacy-external-review-v1"):
            with self.subTest(tampered_mode=tampered_mode):
                evidence = _claude_external_evidence(state)
                review_input = evidence["review_input"]
                if tampered_mode is None:
                    review_input.pop("mode")
                else:
                    review_input["mode"] = tampered_mode
                result = _evaluate_review_gate(
                    state,
                    self_review=_self_review(),
                    external_review_evidence=evidence,
                )
                self.assertEqual(result["verdict"], "PASS")
                self.assertIn(
                    "review_input.mode is not "
                    f"{gate.CLAUDE_CLI_REVIEW_INPUT_MODE}",
                    _warnings(result),
                )

    def test_model_identity_cannot_be_overclaimed(self) -> None:
        state = _state()
        evidence = _plain_external_evidence(state)
        evidence["review_input"]["model_identity_attestation"] = (
            "provider_verified"
        )
        result = _evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn("overclaims provider identity", _warnings(result))

    def test_nonce_is_required_for_reconstruction(self) -> None:
        state = _state()
        evidence = _plain_external_evidence(state)
        evidence["review_input"]["prompt_nonce"] = "invalid"
        result = _evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=evidence,
        )
        warnings = _warnings(result)
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn("prompt_nonce is missing or invalid", warnings)
        self.assertIn("expected transmitted prompt sha256 is unavailable", warnings)

    def test_runtime_isolation_claims_are_strictly_bound(self) -> None:
        state = _state()
        evidence = _plain_external_evidence(state)
        review_input = evidence["review_input"]
        review_input["review_gate_authority"] = "satisfies_review_gate"
        review_input["environment_passed_keys"].append("SSH_AUTH_SOCK")
        review_input["session_bus_exposed"] = True
        review_input["workspace_readback"] = "not_checked"
        result = _evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=evidence,
        )
        warnings = _warnings(result)
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn("review_gate_authority is not advisory-only", warnings)
        self.assertIn("contains forbidden keys", warnings)
        self.assertIn("session_bus_exposed is not false", warnings)
        self.assertIn("workspace_readback is not unchanged", warnings)


if __name__ == "__main__":
    unittest.main()
