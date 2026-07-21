from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


schemas = _load_module(
    "review_evidence_schemas",
    ROOT / "tools" / "review_evidence_schemas.py",
)
gate = _load_module(
    "grabowski_pr_review_gate_schema_test",
    ROOT / "tools" / "pr_review_gate.py",
)


def _self_review() -> dict:
    return {
        "schema_version": 1,
        "kind": "grabowski_self_review",
        "review_mode": "critical_diff_review",
        "repo": "heimgewebe/grabowski",
        "pr": 42,
        "head_sha": "a" * 40,
        "diff_sha256": "b" * 64,
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
            {"n": 1, "summary": "checked schema boundaries", "material_findings": 0}
        ],
        "all_findings_triaged": True,
        "findings": [],
        "material_findings_remaining": 0,
        "material_findings_after_first_review": 0,
        "uncertainty": 0.1,
        "stop_reason": "clean_pass",
    }


def _external_review() -> dict:
    return {
        "schema_version": 1,
        "kind": "external_review",
        "repo": "heimgewebe/grabowski",
        "pr": 42,
        "head_sha": "a" * 40,
        "diff_sha256": "b" * 64,
        "prompt_sha256": "c" * 64,
        "prompt_includes_diff": True,
        "reviews": [],
        "external_reviews_triaged": True,
        "findings": [],
    }


def _claude_evidence() -> dict:
    return {
        "schema_version": 1,
        "kind": "claude_ultrareview",
        "repo": "heimgewebe/grabowski",
        "pr": 42,
        "head_sha": "a" * 40,
        "expected_head_sha": "a" * 40,
        "tool": "claude-code",
        "tool_version": "2.1.197",
        "command": ["claude", "ultrareview", "42", "--json", "--timeout", "30"],
        "exit_code": 0,
        "json_ok": True,
        "verdict": "PASS",
        "finding_count": 0,
        "findings_triaged": True,
        "stdout_sha256": "d" * 64,
        "stderr_sha256": "e" * 64,
    }


class ReviewEvidenceSchemaTests(unittest.TestCase):
    def test_valid_schema_version_1_payloads_validate(self) -> None:
        cases = {
            "self-review": _self_review(),
            "external review evidence": _external_review(),
            "Claude evidence": _claude_evidence(),
        }
        for label, payload in cases.items():
            with self.subTest(label=label):
                self.assertEqual(schemas.validate_evidence(payload, label=label), ())

    def test_missing_required_field_is_rejected(self) -> None:
        payload = _self_review()
        payload.pop("schema_version")
        self.assertEqual(
            schemas.validate_evidence(payload, label="self-review"),
            ("missing required field(s): schema_version",),
        )

    def test_integer_fields_reject_bool(self) -> None:
        payload = _claude_evidence()
        payload["pr"] = True
        self.assertIn(
            "field pr must be an integer",
            schemas.validate_evidence(payload, label="Claude evidence"),
        )

    def test_unknown_fields_are_rejected(self) -> None:
        payload = _external_review()
        payload["surprise"] = "not part of v1"
        self.assertEqual(
            schemas.validate_evidence(payload, label="external review evidence"),
            ("unknown field(s): surprise",),
        )

    def test_schema_models_emit_strict_json_schema(self) -> None:
        document = schemas.json_schema_for("Claude evidence")
        self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(document["additionalProperties"])
        self.assertEqual(document["properties"]["schema_version"]["const"], 1)
        self.assertIn("expected_head_sha", document["required"])

    def test_self_review_loader_uses_schema_layer(self) -> None:
        payload = _self_review()
        payload["pr"] = "42"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "self-review.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                gate.GateInputError,
                "self-review schema validation failed: field pr must be an integer",
            ):
                gate.load_self_review(path)

    def test_optional_external_review_schema_failure_remains_advisory(self) -> None:
        payload = _external_review()
        payload["unknown"] = True
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "external-review.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = gate.load_external_review_evidence(path)
        self.assertEqual(loaded, payload)
        failures = gate._external_review_failures(
            {"pr_diff_sha256": "b" * 64},
            {"number": 42, "headRefOid": "a" * 40},
            loaded,
            required=False,
            repo_name="heimgewebe/grabowski",
        )
        self.assertIn(
            "schema validation failed: unknown field(s): unknown", failures
        )

    def test_claude_loader_keeps_v1_payload_compatible(self) -> None:
        payload = _claude_evidence()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "claude.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(gate.load_claude_evidence(path), payload)

    def test_stale_head_and_diff_binding_remain_gate_policy_checks(self) -> None:
        state = {
            "repoName": "heimgewebe/grabowski",
            "pr_diff_sha256": "f" * 64,
            "pr": {
                "number": 42,
                "state": "OPEN",
                "isDraft": False,
                "mergeStateStatus": "CLEAN",
                "mergeable": "MERGEABLE",
                "headRefOid": "c" * 40,
                "baseRefOid": "d" * 40,
                "changedFiles": 1,
                "additions": 1,
                "deletions": 0,
                "files": [{"path": "docs/note.md"}],
            },
            "checks": [
                {"bucket": "pass", "name": "validate (3.10)"},
                {"bucket": "pass", "name": "validate (3.12)"},
            ],
        }
        payload = _self_review()
        payload.update(
            {
                "pr": 42,
                "repo": "heimgewebe/grabowski",
                "head_sha": "a" * 40,
                "diff_sha256": "b" * 64,
                "reviewed_files": ["docs/note.md"],
            }
        )
        result = gate.evaluate_review_gate(state, self_review=payload)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("self-review head_sha mismatch", result["failures"])
        self.assertIn("self-review diff_sha256 mismatch", result["failures"])


if __name__ == "__main__":
    unittest.main()
