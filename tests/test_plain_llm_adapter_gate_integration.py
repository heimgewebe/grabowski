from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40
BASE = "b" * 40


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load(
    ROOT / "tools" / "pr_review_gate.py",
    "plain_llm_adapter_gate_test_gate",
)
plain = _load(
    ROOT / "tools" / "external_review_plain.py",
    "plain_llm_adapter_gate_test_adapter",
)


def _state(diff: bytes) -> dict[str, object]:
    return {
        "repoName": "heimgewebe/grabowski",
        "pr_diff_sha256": gate._sha256_bytes(diff),
        "pr_diff_text": diff.decode("utf-8"),
        "pr": {
            "number": 7,
            "title": "plain review integration",
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


def _self_review(diff_sha256: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "grabowski_self_review",
        "review_mode": "critical_diff_review",
        "reviewer": "grabowski-self",
        "repo": "heimgewebe/grabowski",
        "pr": 7,
        "head_sha": HEAD,
        "diff_sha256": diff_sha256,
        "diff_reviewed": True,
        "reviewed_files": ["tools/pr_review_gate.py"],
        "review_focus": [
            "correctness",
            "regression_risk",
            "tests",
            "security",
            "integration",
        ],
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


class PlainLlmAdapterGateIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._account_home = tempfile.TemporaryDirectory()
        self.addCleanup(self._account_home.cleanup)
        account_home = Path(self._account_home.name)
        account_home.chmod(0o700)
        self._account_home_patch = mock.patch.dict(
            os.environ,
            {"HOME": str(account_home)},
        )
        self._account_home_patch.start()
        self.addCleanup(self._account_home_patch.stop)

    def test_adapter_output_passes_independent_gate_reconstruction(self) -> None:
        diff = b"diff --git a/x b/x\n+changed\n"
        state = _state(diff)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            packet = gate.write_external_review_packet(
                root / "packet", state, diff
            )
            output = root / "grok-evidence.json"

            def fake_run(argv, **kwargs):
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    '{"verdict":"PASS","finding_count":0,"findings":[]}',
                    "",
                )

            with (
                mock.patch.object(
                    plain,
                    "run_bounded_process",
                    side_effect=fake_run,
                ),
                mock.patch.object(
                    plain,
                    "resolve_provider_executable",
                    return_value="/private/grok",
                ),
                mock.patch.object(
                    plain.secrets,
                    "token_hex",
                    return_value="1" * 32,
                ),
            ):
                evidence = plain.run_from_manifest(
                    manifest_path=Path(packet["manifest_path"]),
                    output_path=output,
                    raw_review_path=None,
                    transmitted_prompt_path=None,
                    provider="grok",
                    executable="grok",
                    model="grok-4.5",
                    timeout_seconds=300,
                    max_prompt_bytes=100_000,
                )

            result = gate.evaluate_review_gate(
                state,
                self_review=_self_review(state["pr_diff_sha256"]),
                external_review_evidence=evidence,
                external_review_artifact_root=root,
            )
            self.assertEqual(result["verdict"], "PASS")
            warnings = "\n".join(result["warnings"])
            self.assertNotIn(
                "Optional external review evidence invalid", warnings
            )


if __name__ == "__main__":
    unittest.main()
