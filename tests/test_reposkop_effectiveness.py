from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types


import grabowski_reposkop_effectiveness as effectiveness


def _ref(character: str) -> str:
    return "audit-record-sha256:" + character * 64


def _event(
    operation: str,
    evaluation: str,
    character: str,
    **extra,
) -> dict[str, object]:
    return {
        "operation": operation,
        "evaluation_id": evaluation,
        "transaction_id": evaluation,
        "timestamp_unix": extra.pop("timestamp_unix", 100),
        "effect_profile": extra.pop("effect_profile", "workspace_write"),
        "reposkop_policy": extra.pop("reposkop_policy", "required"),
        "surface": extra.pop("surface", "task_start"),
        "agent_executable": extra.pop("agent_executable", "codex"),
        "policy_version": extra.pop("policy_version", 2),
        "_audit_ref": _ref(character),
        **extra,
    }


class ReposkopEffectivenessTests(unittest.TestCase):
    def test_agent_effect_classification_covers_supported_writers(self) -> None:
        cases = {
            "codex": ["exec", "--sandbox", "workspace-write"],
            "claude": ["--permission-mode", "acceptEdits"],
            "agy": ["--model", "gemini-3.1-pro-high"],
            "grok": ["--model", "grok-4.5"],
            "grok-cli": ["--model", "grok-4.5"],
        }
        for executable, tail in cases.items():
            with self.subTest(executable=executable):
                result = effectiveness.classify_task_effect(
                    transport="local",
                    argv=[f"/opt/{executable}", *tail],
                    mutating_workspace="/repo",
                )
                self.assertEqual(result["effect_profile"], "workspace_write")
                self.assertEqual(result["reposkop_policy"], "required")
                self.assertEqual(result["agent_executable"], executable)

    def test_prospective_policy_splits_only_admitted_workspace_writers(self) -> None:
        base = effectiveness.classify_task_effect(
            transport="local",
            argv=["/opt/codex", "exec", "--sandbox", "workspace-write"],
            mutating_workspace="/repo",
        )
        self.assertEqual(base["reposkop_cohort"], "risk_required")
        not_admitted = effectiveness.select_prospective_policy(
            base, sampling_key="not-admitted", admission_verified=False
        )
        self.assertEqual(not_admitted["reposkop_policy"], "required")
        self.assertEqual(not_admitted["reposkop_cohort"], "risk_required")

        assignments = [
            effectiveness.select_prospective_policy(
                base, sampling_key=f"task-{index}", admission_verified=True
            )
            for index in range(32)
        ]
        cohorts = {item["reposkop_cohort"] for item in assignments}
        self.assertEqual(cohorts, {"prospective_sample", "prospective_control"})
        control = next(
            item for item in assignments if item["reposkop_cohort"] == "prospective_control"
        )
        sample = next(
            item for item in assignments if item["reposkop_cohort"] == "prospective_sample"
        )
        self.assertEqual(control["reposkop_policy"], "not_required")
        self.assertEqual(sample["reposkop_policy"], "required")
        self.assertEqual(control["sampling_modulus"], 4)
        replay = effectiveness.select_prospective_policy(
            base, sampling_key="task-1", admission_verified=True
        )
        self.assertEqual(
            replay,
            effectiveness.select_prospective_policy(
                base, sampling_key="task-1", admission_verified=True
            ),
        )

    def test_repository_write_never_enters_prospective_control(self) -> None:
        base = effectiveness.classify_task_effect(
            transport="local",
            argv=["/opt/codex", "exec", "--sandbox", "workspace-write"],
            mutating_workspace="/repo",
            explicit_effect_profile="repository_write",
        )
        selected = effectiveness.select_prospective_policy(
            base, sampling_key="repository-write", admission_verified=True
        )
        self.assertEqual(selected["reposkop_policy"], "required")
        self.assertEqual(selected["reposkop_cohort"], "repository_write_required")
        self.assertIsNone(selected["sampling_bucket"])

    def test_agent_read_only_modes_do_not_require_reposkop(self) -> None:
        cases = [
            ["/opt/codex", "exec", "--sandbox", "read-only"],
            ["/opt/claude", "--permission-mode", "read-only"],
            ["/opt/agy", "--read-only"],
            ["/opt/grok", "--read-only"],
            ["/opt/grok-cli", "--read-only"],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                result = effectiveness.classify_task_effect(
                    transport="local",
                    argv=argv,
                    mutating_workspace=None,
                )
                self.assertEqual(result["effect_profile"], "read_only")
                self.assertEqual(result["reposkop_policy"], "not_required")

    def test_explicit_effect_profile_validation_is_fail_closed(self) -> None:
        explicit = effectiveness.classify_task_effect(
            transport="local",
            argv=["/usr/bin/make", "validate"],
            mutating_workspace=None,
            explicit_effect_profile="host_write",
        )
        self.assertEqual(explicit["effect_profile"], "host_write")
        self.assertEqual(explicit["reposkop_policy"], "not_required")
        with self.assertRaisesRegex(ValueError, "effect_profile must be one of"):
            effectiveness.classify_task_effect(
                transport="local",
                argv=["/usr/bin/make"],
                mutating_workspace=None,
                explicit_effect_profile="write_everywhere",
            )
        with self.assertRaisesRegex(ValueError, "may not use effect_profile=unknown"):
            effectiveness.classify_task_effect(
                transport="local",
                argv=["/opt/codex", "exec", "--sandbox", "workspace-write"],
                mutating_workspace="/repo",
                explicit_effect_profile="unknown",
            )
        with self.assertRaisesRegex(ValueError, "conflicts with read-only agent mode"):
            effectiveness.classify_task_effect(
                transport="local",
                argv=["/opt/claude", "--permission-mode", "read-only"],
                mutating_workspace=None,
                explicit_effect_profile="workspace_write",
            )

    def test_remote_agent_is_classified_without_local_reposkop_claim(self) -> None:
        result = effectiveness.classify_task_effect(
            transport="ssh",
            argv=["/opt/grok", "--model", "grok-4.5"],
            mutating_workspace=None,
        )
        self.assertEqual(result["effect_profile"], "remote_write")
        self.assertEqual(result["reposkop_policy"], "not_required")

    def test_evaluation_identity_is_deterministic_and_bound(self) -> None:
        common = {
            "task_id": "a" * 24,
            "execution_identity_sha256": "b" * 64,
            "checkout_binding_sha256": "c" * 64,
            "argv_sha256": "d" * 64,
        }
        first = effectiveness.evaluation_id(**common)
        second = effectiveness.evaluation_id(**common)
        changed = effectiveness.evaluation_id(
            **{**common, "checkout_binding_sha256": "e" * 64}
        )
        self.assertEqual(first, second)
        self.assertNotEqual(first, changed)
        self.assertRegex(first, r"^[0-9a-f]{64}$")

    def test_finding_taxonomy_projects_only_bounded_reason_codes(self) -> None:
        report = {
            "observation": {
                "errors": ["private raw detail"],
                "git": {
                    "dirty": True,
                    "staged": False,
                    "unstaged": True,
                    "untracked": True,
                    "operation_state": ["rebase"],
                    "detached": False,
                    "alternates_configured": False,
                    "gitmodules_present": True,
                    "ahead": 2,
                    "behind": 1,
                    "upstream": None,
                    "upstream_freshness": "locally_available_only",
                },
                "role": {"value": "canonical_checkout"},
            },
            "projection": {
                "state": "inconclusive",
                "reasons": ["lifecycle_evidence_missing", "secret internal reason"],
                "active_bindings": [{"private": "value"}],
                "observation_validation": {"valid": True},
            },
        }
        summary = effectiveness.finding_summary(report)
        self.assertEqual(summary["finding_taxonomy_status"], "available_v2")
        self.assertEqual(summary["finding_taxonomy_version"], 2)
        self.assertEqual(summary["projection_state"], "inconclusive")
        self.assertEqual(summary["advisory_posture"], "attention")
        self.assertGreater(summary["finding_counts"]["error"], 0)
        self.assertEqual(summary["finding_counts"]["warning"], 3)
        self.assertEqual(summary["finding_categories"]["working_tree_state"], 2)
        self.assertIn("working_tree_dirty", summary["finding_reason_codes"])
        self.assertIn("projection_reason_other", summary["finding_reason_codes"])
        self.assertNotIn("secret internal reason", summary["finding_reason_codes"])
        self.assertNotIn("private raw detail", json.dumps(summary))

    def test_local_authority_v3_ignores_foreign_authority_noise(self) -> None:
        report = {
            "schema_version": 3,
            "observation": {
                "errors": [],
                "git": {
                    "dirty": False,
                    "staged": False,
                    "unstaged": False,
                    "untracked": False,
                    "operation_state": [],
                    "detached": False,
                    "alternates_configured": False,
                    "gitmodules_present": False,
                    "ahead": 0,
                    "behind": 7,
                    "upstream": None,
                    "upstream_freshness": "locally_available_only",
                },
                "role": {"value": "linked_worktree"},
            },
            "projection": {
                "schema_version": 2,
                "state": "local_coherent",
                "reasons": [
                    "local_checkout_observation_complete",
                    "managed_role:linked_worktree",
                ],
                "active_bindings": ["task:foreign"],
                "foreign_authority_gaps": [
                    "lifecycle_evidence_missing",
                    "remote_freshness_unverified",
                ],
                "observation_validation": {"valid": True},
            },
        }
        summary = effectiveness.finding_summary(report)
        self.assertEqual(summary["projection_state"], "local_coherent")
        self.assertEqual(summary["advisory_posture"], "clean")
        self.assertEqual(summary["finding_count"], 0)
        self.assertNotIn("remote_freshness", summary["finding_categories"])
        self.assertNotIn("lifecycle_evidence", summary["finding_categories"])
        self.assertNotIn("projection_state_other", summary["finding_reason_codes"])

    def test_local_authority_v3_keeps_local_inconclusive_signal(self) -> None:
        report = {
            "schema_version": 3,
            "observation": {
                "errors": [],
                "git": {
                    "dirty": False,
                    "staged": False,
                    "unstaged": False,
                    "untracked": False,
                    "operation_state": [],
                    "detached": False,
                    "alternates_configured": False,
                    "gitmodules_present": False,
                    "ahead": 0,
                    "behind": 9,
                    "upstream": None,
                    "upstream_freshness": "locally_available_only",
                },
                "role": {"value": "linked_worktree"},
            },
            "projection": {
                "schema_version": 2,
                "state": "inconclusive",
                "reasons": ["git_observation_incomplete"],
                "active_bindings": [],
                "foreign_authority_gaps": ["lifecycle_evidence_missing"],
                "observation_validation": {"valid": True},
            },
        }
        summary = effectiveness.finding_summary(report)
        self.assertEqual(summary["projection_state"], "inconclusive")
        self.assertEqual(summary["advisory_posture"], "informational")
        self.assertIn("git_observation_incomplete", summary["finding_reason_codes"])
        self.assertIn("projection_state_inconclusive", summary["finding_reason_codes"])
        self.assertNotIn("upstream_unbound", summary["finding_reason_codes"])
        self.assertNotIn("upstream_behind", summary["finding_reason_codes"])

    def test_failure_summary_uses_stable_categories_without_raw_error(self) -> None:
        result = effectiveness.failure_summary(
            ValueError("Reposkop observation must be complete: /private/path")
        )
        self.assertEqual(result["failure_category"], "observation_incomplete")
        self.assertEqual(
            result["decision_reason_codes"],
            ["observation_incomplete", "reposkop_evaluation_failed"],
        )
        self.assertNotIn("private", json.dumps(result))

    def test_review_classification_is_create_only_replayable_and_revisable(self) -> None:
        evaluation = "a" * 64
        decision_ref = _ref("d")
        records: list[dict[str, object]] = [
            _event("reposkop-evaluation-requested", evaluation, "1", task_id="task-1"),
            _event(
                "reposkop-decision-applied",
                evaluation,
                "d",
                task_id="task-1",
                final_decision="block",
                decision_changed=True,
            ),
            _event(
                "reposkop-execution-attestation-blocked",
                evaluation,
                "b",
                task_id="task-1",
            ),
        ]
        parameters = {
            "evaluation_id": evaluation,
            "classification": "operational_failure",
            "reviewer": "operator:reviewer",
            "scope": "technical",
            "detectable_category": "observation_completeness",
            "reason_codes": ["observation_incomplete"],
            "evidence_refs": [decision_ref, _ref("b")],
            "expected_decision_audit_ref": decision_ref,
            "supersedes_review_audit_ref": "",
        }
        appended: list[dict[str, object]] = []

        def raw_records(**_kwargs):
            return list(records), {"chain_content_sha256": "f" * 64}

        def append(record):
            appended.append(record)
            reference = _ref("e") if len(appended) == 1 else _ref("f")
            records.insert(0, {**record, "_audit_ref": reference})
            return reference

        with patch.object(effectiveness, "_review_records", side_effect=raw_records), patch.object(
            effectiveness, "append_event", side_effect=append
        ), patch.object(effectiveness.time, "time", return_value=123):
            first = effectiveness.record_review_classification(parameters)
            replay = effectiveness.record_review_classification(parameters)
            with self.assertRaises(effectiveness.ReposkopReviewConflictError):
                effectiveness.record_review_classification(
                    {**parameters, "classification": "false_positive"}
                )
            revised = effectiveness.record_review_classification(
                {
                    **parameters,
                    "classification": "false_positive",
                    "reason_codes": ["block_not_material"],
                    "supersedes_review_audit_ref": first["audit_ref"],
                }
            )
        self.assertFalse(first["replayed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(revised["review_sequence"], 2)
        self.assertEqual(len(appended), 2)
        self.assertNotIn("reviewer", appended[0])
        self.assertRegex(appended[0]["reviewer_sha256"], r"^[0-9a-f]{64}$")

    def test_material_review_requires_corroborating_evidence(self) -> None:
        evaluation = "c" * 64
        decision_ref = _ref("d")
        parameters = {
            "evaluation_id": evaluation,
            "classification": "operational_failure",
            "reviewer": "operator:reviewer",
            "scope": "technical",
            "detectable_category": "observation_completeness",
            "reason_codes": ["observation_incomplete"],
            "evidence_refs": [decision_ref],
            "expected_decision_audit_ref": decision_ref,
            "supersedes_review_audit_ref": "",
        }
        with self.assertRaisesRegex(
            effectiveness.ReposkopReviewInputError,
            "corroborating evidence",
        ):
            effectiveness.record_review_classification(parameters)

    def test_review_classification_rejects_unverified_corroborating_audit_ref(self) -> None:
        evaluation = "9" * 64
        decision_ref = _ref("d")
        records = [
            _event(
                "reposkop-evaluation-requested",
                evaluation,
                "1",
                task_id="task-9",
            ),
            _event(
                "reposkop-decision-applied",
                evaluation,
                "d",
                task_id="task-9",
                final_decision="block",
            ),
        ]
        parameters = {
            "evaluation_id": evaluation,
            "classification": "operational_failure",
            "reviewer": "operator:reviewer",
            "scope": "technical",
            "detectable_category": "observation_completeness",
            "reason_codes": ["observation_incomplete"],
            "evidence_refs": [decision_ref, _ref("f")],
            "expected_decision_audit_ref": decision_ref,
            "supersedes_review_audit_ref": "",
        }
        with patch.object(
            effectiveness,
            "_review_records",
            return_value=(records, {}),
        ), self.assertRaisesRegex(
            effectiveness.ReposkopReviewIntegrityError,
            "unavailable in the verified audit window",
        ):
            effectiveness.record_review_classification(parameters)


    def test_review_scan_retains_only_bound_records(self) -> None:
        from types import SimpleNamespace

        evaluation = "4" * 64
        wanted_ref = _ref("d")
        records = [
            {
                "operation": "reposkop-evaluation-requested",
                "evaluation_id": evaluation,
                "record_sha256": "1" * 64,
            },
            {
                "operation": "unrelated",
                "evaluation_id": "3" * 64,
                "record_sha256": "2" * 64,
            },
            {
                "operation": "external-evidence",
                "record_sha256": "d" * 64,
            },
        ]
        payload = b"".join(
            (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
            for record in records
        )
        segment = SimpleNamespace(records=len(records))
        snapshot = SimpleNamespace(
            segments=(segment,),
            total_records=len(records),
            chain_content_sha256="a" * 64,
            chain_materialization_sha256="b" * 64,
        )
        with patch.object(
            effectiveness.audit_query,
            "capture_verified_audit_snapshot",
            return_value=snapshot,
        ), patch.object(
            effectiveness.audit_query,
            "_load_snapshot_segment",
            return_value=payload,
        ):
            selected, source = effectiveness._review_records(
                evaluation=evaluation,
                evidence_refs={wanted_ref},
                scan_limit=10,
            )
        self.assertEqual(source["scanned_records"], 3)
        self.assertEqual(source["retained_records"], 2)
        self.assertEqual(
            {record["operation"] for record in selected},
            {"reposkop-evaluation-requested", "external-evidence"},
        )


    def test_review_classification_rejects_truncated_audit_window(self) -> None:
        parameters = {
            "evaluation_id": "5" * 64,
            "classification": "unresolved",
            "reviewer": "operator:reviewer",
            "scope": "technical",
            "detectable_category": "not_applicable",
            "reason_codes": ["awaiting_evidence"],
            "evidence_refs": [_ref("d")],
            "expected_decision_audit_ref": _ref("d"),
            "supersedes_review_audit_ref": "",
        }
        with patch.object(
            effectiveness,
            "_review_records",
            return_value=([], {"scan_truncated": True}),
        ), self.assertRaisesRegex(
            effectiveness.ReposkopReviewIntegrityError,
            "exceeds the bounded Reposkop review scan",
        ):
            effectiveness.record_review_classification(parameters)


    def test_neutral_review_requires_correlated_outcome_evidence(self) -> None:
        evaluation = "6" * 64
        decision_ref = _ref("d")
        outcome_ref = _ref("e")
        records = [
            _event(
                "reposkop-evaluation-requested",
                evaluation,
                "1",
                task_id="task-6",
            ),
            _event(
                "reposkop-decision-applied",
                evaluation,
                "d",
                task_id="task-6",
                final_decision="allow",
            ),
            _event(
                "reposkop-task-outcome-observed",
                evaluation,
                "e",
                task_id="task-6",
                terminal_state="completed",
            ),
        ]
        base = {
            "evaluation_id": evaluation,
            "classification": "neutral",
            "reviewer": "operator:reviewer",
            "scope": "technical",
            "detectable_category": "not_applicable",
            "reason_codes": ["no_confirmed_decision_value"],
            "expected_decision_audit_ref": decision_ref,
            "supersedes_review_audit_ref": "",
        }
        with patch.object(
            effectiveness,
            "_review_records",
            return_value=(records, {}),
        ), self.assertRaisesRegex(
            effectiveness.ReposkopReviewInputError,
            "corroborating evidence beyond the decision",
        ):
            effectiveness.record_review_classification(
                {**base, "evidence_refs": [decision_ref]}
            )
        appended: list[dict[str, object]] = []
        with patch.object(
            effectiveness,
            "_review_records",
            return_value=(records, {}),
        ), patch.object(
            effectiveness,
            "append_event",
            side_effect=lambda event: appended.append(event) or _ref("r"),
        ):
            result = effectiveness.record_review_classification(
                {**base, "evidence_refs": [decision_ref, outcome_ref]}
            )
        self.assertEqual(result["classification"], "neutral")
        self.assertEqual(len(appended), 1)


    def test_review_classification_rejects_unrelated_corroborating_audit_ref(self) -> None:
        evaluation = "8" * 64
        decision_ref = _ref("d")
        unrelated_ref = _ref("f")
        records = [
            _event(
                "reposkop-evaluation-requested",
                evaluation,
                "1",
                task_id="task-8",
            ),
            _event(
                "reposkop-decision-applied",
                evaluation,
                "d",
                task_id="task-8",
                final_decision="block",
            ),
            {
                "operation": "task-start",
                "task_id": "different-task",
                "transaction_id": "7" * 64,
                "_audit_ref": unrelated_ref,
            },
        ]
        parameters = {
            "evaluation_id": evaluation,
            "classification": "operational_failure",
            "reviewer": "operator:reviewer",
            "scope": "technical",
            "detectable_category": "observation_completeness",
            "reason_codes": ["observation_incomplete"],
            "evidence_refs": [decision_ref, unrelated_ref],
            "expected_decision_audit_ref": decision_ref,
            "supersedes_review_audit_ref": "",
        }
        with patch.object(
            effectiveness,
            "_review_records",
            return_value=(records, {}),
        ), self.assertRaisesRegex(
            effectiveness.ReposkopReviewIntegrityError,
            "not bound to the reviewed evaluation or task",
        ):
            effectiveness.record_review_classification(parameters)


    def test_review_classification_rejects_semantically_impossible_claim(self) -> None:
        evaluation = "b" * 64
        decision_ref = _ref("c")
        records = [
            _event("reposkop-evaluation-requested", evaluation, "1", task_id="task-2"),
            _event(
                "reposkop-decision-applied",
                evaluation,
                "c",
                task_id="task-2",
                final_decision="block",
            ),
            _event(
                "reposkop-task-outcome-observed",
                evaluation,
                "e",
                task_id="task-2",
                terminal_state="completed",
            ),
        ]
        parameters = {
            "evaluation_id": evaluation,
            "classification": "false_negative",
            "reviewer": "operator:reviewer",
            "scope": "repository",
            "detectable_category": "foreign_dirty_state",
            "reason_codes": ["later_conflict"],
            "evidence_refs": [decision_ref, _ref("e")],
            "expected_decision_audit_ref": decision_ref,
            "supersedes_review_audit_ref": "",
        }
        with patch.object(
            effectiveness,
            "_review_records",
            return_value=(records, {}),
        ), self.assertRaisesRegex(
            effectiveness.ReposkopReviewInputError,
            "requires an allowed evaluation",
        ):
            effectiveness.record_review_classification(parameters)


    def test_projection_separates_verified_blocked_missing_and_legacy(self) -> None:
        verified = "a" * 64
        blocked = "b" * 64
        records = [
            _event("reposkop-evaluation-requested", verified, "1"),
            _event(
                "reposkop-evaluation-completed",
                verified,
                "2",
                duration_ms=100,
                status="verified",
            ),
            _event(
                "reposkop-decision-applied",
                verified,
                "3",
                final_decision="allow",
            ),
            _event(
                "reposkop-task-outcome-observed",
                verified,
                "4",
                terminal_state="completed",
            ),
            _event("reposkop-evaluation-requested", blocked, "5"),
            _event(
                "reposkop-decision-applied",
                blocked,
                "6",
                final_decision="block",
            ),
            _event(
                "reposkop-execution-attestation-blocked",
                blocked,
                "7",
            ),
            {
                "operation": "task-start",
                "task_id": "missing",
                "effect_profile": "workspace_write",
                "reposkop_policy": "required",
                "surface": "task_start",
                "agent_executable": "grok",
                "policy_version": 2,
                "_audit_ref": _ref("8"),
            },
            {
                "operation": "task-start",
                "task_id": "read-only",
                "effect_profile": "read_only",
                "reposkop_policy": "not_required",
                "surface": "task_start",
                "agent_executable": "codex",
                "policy_version": 2,
                "_audit_ref": _ref("9"),
            },
            {
                "operation": "task-start",
                "task_id": "legacy",
                "_audit_ref": _ref("a"),
            },
        ]
        result = effectiveness.project_records(records)
        self.assertEqual(result["classified_task_starts"], 2)
        self.assertEqual(result["legacy_unclassified_task_starts"], 1)
        self.assertEqual(result["required_task_starts"], 3)
        self.assertEqual(result["required_verified"], 1)
        self.assertEqual(result["required_blocked"], 1)
        self.assertEqual(result["required_missing"], 1)
        self.assertAlmostEqual(result["coverage_ratio"], 2 / 3)
        self.assertEqual(result["terminal_outcomes"], 1)
        self.assertEqual(result["terminal_successes"], 1)
        self.assertEqual(result["terminal_failures"], 0)
        self.assertEqual(result["duration_ms"], {"sample_size": 1, "p50": 100, "p95": 100})
        self.assertEqual(result["groups"]["agent"]["grok"], 1)
        candidates = {item["metric"]: item for item in result["improvement_candidates"]}
        self.assertEqual(candidates["missing_required_attestation"]["status"], "active")
        self.assertEqual(candidates["repeated_operational_failure"]["status"], "insufficient_sample")

    def test_projection_uses_latest_review_and_computes_quality_metrics(self) -> None:
        confirmed = "1" * 64
        false_positive = "2" * 64
        false_negative = "3" * 64
        records: list[dict[str, object]] = []
        for evaluation, decision, classification, character in (
            (confirmed, "block", "confirmed_prevention", "a"),
            (false_positive, "block", "false_positive", "b"),
            (false_negative, "allow", "false_negative", "c"),
        ):
            records.append(_event("reposkop-evaluation-requested", evaluation, character))
            if decision == "allow":
                records.append(
                    _event(
                        "reposkop-evaluation-completed",
                        evaluation,
                        character,
                        duration_ms=10,
                        finding_counts={
                            "critical": 0,
                            "error": 0,
                            "warning": 1,
                            "information": 0,
                        },
                        finding_categories={"working_tree_state": 1},
                        finding_reason_codes=["working_tree_dirty"],
                        projection_state="inconclusive",
                    )
                )
            records.append(
                _event(
                    "reposkop-decision-applied",
                    evaluation,
                    character,
                    final_decision=decision,
                    decision_changed=decision == "block",
                )
            )
            if decision == "block":
                records.append(
                    _event(
                        "reposkop-execution-attestation-blocked",
                        evaluation,
                        character,
                    )
                )
            records.append(
                _event(
                    "reposkop-review-classification-recorded",
                    evaluation,
                    character,
                    classification=classification,
                    reason_codes=["shared_reason"],
                    review_sequence=1,
                )
            )
        result = effectiveness.project_records(records)
        review = result["review"]
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(review["reviewed_evaluations"], 3)
        self.assertEqual(review["confirmed_preventions"], 1)
        self.assertEqual(review["false_positives"], 1)
        self.assertEqual(review["false_negatives"], 1)
        self.assertEqual(review["precision"], 0.5)
        self.assertEqual(review["false_negative_ratio"], 0.5)
        self.assertEqual(review["unreviewed_decision_changes"], 0)
        self.assertEqual(
            result["findings"]["severity_counts"]["warning"], 1
        )
        candidates = {item["metric"]: item for item in result["improvement_candidates"]}
        self.assertEqual(candidates["unreviewed_decision_change"]["status"], "clear")
        self.assertEqual(candidates["false_positive_cluster"]["status"], "insufficient_sample")
        self.assertEqual(candidates["false_negative_cluster"]["status"], "clear")


    def test_prospective_control_rejects_impossible_positive_review(self) -> None:
        evaluation = "e" * 64
        decision_ref = _ref("d")
        outcome_ref = _ref("e")
        records = [
            _event(
                "reposkop-decision-applied",
                evaluation,
                "d",
                task_id="task-control",
                reposkop_policy="not_required",
                reposkop_cohort="prospective_control",
                final_decision="allow",
                decision_changed=False,
                reposkop_execution_skipped=True,
            ),
            _event(
                "reposkop-task-outcome-observed",
                evaluation,
                "e",
                task_id="task-control",
                reposkop_policy="not_required",
                reposkop_cohort="prospective_control",
                terminal_state="completed",
            ),
        ]
        base = {
            "evaluation_id": evaluation,
            "reviewer": "operator:reviewer",
            "scope": "repository",
            "detectable_category": "not_applicable",
            "reason_codes": ["prospective_control"],
            "evidence_refs": [decision_ref, outcome_ref],
            "expected_decision_audit_ref": decision_ref,
            "supersedes_review_audit_ref": "",
        }
        with patch.object(
            effectiveness, "_review_records", return_value=(records, {})
        ), self.assertRaisesRegex(
            effectiveness.ReposkopReviewInputError,
            "prospective control decisions",
        ):
            effectiveness.record_review_classification(
                {**base, "classification": "beneficial_context"}
            )

    def test_projection_counts_prospective_control_false_negative(self) -> None:
        sample = "4" * 64
        control = "5" * 64
        records = [
            _event(
                "reposkop-evaluation-requested",
                sample,
                "1",
                reposkop_cohort="prospective_sample",
                policy_version=3,
            ),
            _event(
                "reposkop-evaluation-completed",
                sample,
                "2",
                reposkop_cohort="prospective_sample",
                policy_version=3,
                duration_ms=10,
            ),
            _event(
                "reposkop-decision-applied",
                sample,
                "3",
                reposkop_cohort="prospective_sample",
                policy_version=3,
                final_decision="allow",
            ),
            _event(
                "reposkop-decision-applied",
                control,
                "4",
                reposkop_policy="not_required",
                reposkop_cohort="prospective_control",
                policy_version=3,
                final_decision="allow",
                reposkop_execution_skipped=True,
            ),
            _event(
                "reposkop-task-outcome-observed",
                control,
                "5",
                reposkop_policy="not_required",
                reposkop_cohort="prospective_control",
                policy_version=3,
                terminal_state="failed",
            ),
            _event(
                "reposkop-review-classification-recorded",
                control,
                "6",
                reposkop_policy="not_required",
                reposkop_cohort="prospective_control",
                policy_version=3,
                classification="false_negative",
                detectable_category="working_tree_state",
                reason_codes=["later_repository_failure"],
                review_sequence=1,
            ),
        ]
        result = effectiveness.project_records(records)
        self.assertEqual(result["prospective"]["sample_required"], 1)
        self.assertEqual(result["prospective"]["control_allowed_without_reposkop"], 1)
        self.assertEqual(result["prospective"]["control_reviewed"], 1)
        self.assertEqual(result["prospective"]["control_false_negatives"], 1)
        self.assertEqual(result["prospective"]["control_terminal_outcomes"], 1)
        self.assertEqual(result["review"]["false_negatives"], 1)
        self.assertEqual(result["review"]["reviewed_evaluations"], 1)
        self.assertEqual(result["review"]["unreviewed_evaluations"], 1)

    def test_projection_counts_checkout_shadow_without_inferred_unique_value(self) -> None:
        first = "6" * 64
        second = "7" * 64
        records = [
            _event(
                "reposkop-checkout-shadow-before-observed",
                first,
                "1",
                task_id="shadow-completed",
                shadow_phase="before",
                shadow_status="completed",
                decision_effect=False,
            ),
            _event(
                "reposkop-checkout-shadow-terminal-observed",
                first,
                "2",
                task_id="shadow-completed",
                shadow_phase="terminal",
                shadow_status="completed",
                continuity_state="identity_break",
                measurement_class="identity_break",
                decision_effect=False,
            ),
            _event(
                "reposkop-checkout-shadow-before-observed",
                second,
                "3",
                task_id="shadow-unavailable",
                shadow_phase="before",
                shadow_status="unavailable",
                measurement_class="inconclusive/unavailable",
                decision_effect=False,
            ),
            _event(
                "reposkop-checkout-shadow-terminal-observed",
                second,
                "4",
                task_id="shadow-unavailable",
                shadow_phase="terminal",
                shadow_status="unavailable",
                continuity_state="inconclusive",
                measurement_class="inconclusive/unavailable",
                decision_effect=False,
            ),
        ]

        result = effectiveness.project_records(records)

        shadow_projection = result["checkout_continuity_shadow"]
        self.assertEqual(shadow_projection["attempted"], 2)
        self.assertEqual(shadow_projection["completed"], 1)
        self.assertEqual(shadow_projection["unavailable"], 1)
        self.assertEqual(
            shadow_projection["continuity_state_counts"],
            {"identity_break": 1, "inconclusive": 1},
        )
        self.assertEqual(
            shadow_projection["measurement_class_counts"],
            {"identity_break": 1, "inconclusive/unavailable": 1},
        )
        self.assertEqual(shadow_projection["confirmed_unique_value"], 0)
        self.assertEqual(
            shadow_projection["confirmed_unique_value_source"],
            "semantic_review_only",
        )

    def test_confirmed_unique_value_requires_explicit_bound_semantic_review(self) -> None:
        evaluation = "8" * 64
        decision_ref = _ref("5")
        shadow_ref = _ref("6")
        records = [
            _event(
                "reposkop-decision-applied",
                evaluation,
                "5",
                task_id="task-unique-value",
                reposkop_policy="not_required",
                reposkop_cohort="prospective_control",
                final_decision="allow",
                decision_changed=False,
                reposkop_execution_skipped=True,
            ),
            _event(
                "reposkop-checkout-shadow-terminal-observed",
                evaluation,
                "6",
                task_id="task-unique-value",
                reposkop_policy="not_required",
                reposkop_cohort="prospective_control",
                shadow_status="completed",
                continuity_state="identity_break",
                measurement_class="identity_break",
                decision_effect=False,
            ),
        ]
        parameters = {
            "evaluation_id": evaluation,
            "classification": "confirmed_unique_value",
            "reviewer": "operator:reviewer",
            "scope": "repository",
            "detectable_category": "checkout_identity",
            "reason_codes": ["semantic_checkout_identity_break"],
            "evidence_refs": [decision_ref, shadow_ref],
            "expected_decision_audit_ref": decision_ref,
            "supersedes_review_audit_ref": "",
        }

        with patch.object(
            effectiveness, "_review_records", return_value=(records, {})
        ), patch.object(
            effectiveness, "append_event", return_value=_ref("7")
        ):
            result = effectiveness.record_review_classification(parameters)

        self.assertEqual(result["classification"], "confirmed_unique_value")
        self.assertIs(result["replayed"], False)

    def test_confirmed_unique_value_rejects_unrelated_identity_break_shadow(self) -> None:
        evaluation = "9" * 64
        unrelated_evaluation = "a" * 64
        decision_ref = _ref("5")
        outcome_ref = _ref("6")
        unrelated_shadow_ref = _ref("7")
        records = [
            _event(
                "reposkop-decision-applied",
                evaluation,
                "5",
                task_id="task-reviewed",
                reposkop_policy="not_required",
                reposkop_cohort="prospective_control",
                final_decision="allow",
                decision_changed=False,
                reposkop_execution_skipped=True,
            ),
            _event(
                "reposkop-task-outcome-observed",
                evaluation,
                "6",
                task_id="task-reviewed",
                terminal_state="completed",
            ),
            _event(
                "reposkop-checkout-shadow-terminal-observed",
                unrelated_evaluation,
                "7",
                task_id="task-unrelated",
                reposkop_policy="not_required",
                reposkop_cohort="prospective_control",
                shadow_status="completed",
                continuity_state="identity_break",
                measurement_class="identity_break",
                decision_effect=False,
            ),
        ]
        parameters = {
            "evaluation_id": evaluation,
            "classification": "confirmed_unique_value",
            "reviewer": "operator:reviewer",
            "scope": "repository",
            "detectable_category": "checkout_identity",
            "reason_codes": ["semantic_checkout_identity_break"],
            "evidence_refs": [decision_ref, outcome_ref, unrelated_shadow_ref],
            "expected_decision_audit_ref": decision_ref,
            "supersedes_review_audit_ref": "",
        }

        with patch.object(
            effectiveness, "_review_records", return_value=(records, {})
        ), self.assertRaisesRegex(
            effectiveness.ReposkopReviewIntegrityError,
            "confirmed_unique_value requires a reviewed, completed identity-break shadow artifact",
        ):
            effectiveness.record_review_classification(parameters)

    def test_false_positive_cluster_requires_same_detectable_category(self) -> None:
        records: list[dict[str, object]] = []
        for index, category in enumerate(("checkout_identity", "remote_freshness", "working_tree_state"), 1):
            evaluation = f"{index:064x}"
            records.extend(
                [
                    _event("reposkop-evaluation-requested", evaluation, "1"),
                    _event(
                        "reposkop-decision-applied",
                        evaluation,
                        "2",
                        final_decision="block",
                        decision_changed=True,
                    ),
                    _event(
                        "reposkop-execution-attestation-blocked",
                        evaluation,
                        "3",
                    ),
                    _event(
                        "reposkop-review-classification-recorded",
                        evaluation,
                        "4",
                        classification="false_positive",
                        detectable_category=category,
                        reason_codes=["shared_reason"],
                        review_sequence=1,
                    ),
                ]
            )
        result = effectiveness.project_records(records)
        candidates = {
            item["metric"]: item
            for item in result["improvement_candidates"]
        }
        candidate = candidates["false_positive_cluster"]
        self.assertEqual(candidate["status"], "clear")
        self.assertEqual(candidate["observed"]["max_category_count"], 1)
        self.assertEqual(
            result["review"]["detectable_category_counts"]["false_positive"],
            {
                "checkout_identity": 1,
                "remote_freshness": 1,
                "working_tree_state": 1,
            },
        )


    def test_runtime_regression_candidate_uses_sufficient_sample(self) -> None:
        records: list[dict[str, object]] = []
        for index in range(60):
            evaluation = f"{index + 1:064x}"
            records.extend(
                [
                    _event(
                        "reposkop-evaluation-requested",
                        evaluation,
                        "1",
                        timestamp_unix=index,
                    ),
                    _event(
                        "reposkop-evaluation-completed",
                        evaluation,
                        "2",
                        timestamp_unix=index,
                        duration_ms=100 if index < 30 else 1000,
                    ),
                    _event(
                        "reposkop-decision-applied",
                        evaluation,
                        "3",
                        timestamp_unix=index,
                        final_decision="allow",
                    ),
                ]
            )
        result = effectiveness.project_records(records)
        candidates = {item["metric"]: item for item in result["improvement_candidates"]}
        runtime = candidates["p95_runtime_regression"]
        self.assertEqual(runtime["status"], "active")
        self.assertEqual(runtime["sample_size"], 60)
        self.assertEqual(runtime["threshold"]["baseline_p95_ms"], 100)
        self.assertEqual(runtime["observed"]["recent_p95_ms"], 1000)

    def test_outcome_record_is_idempotent_and_digest_bound(self) -> None:
        attestation = {
            "evaluation_id": "f" * 64,
            "effect_profile": "workspace_write",
            "reposkop_policy": "required",
            "surface": "task_start",
            "agent_executable": "agy",
            "policy_version": 2,
        }
        with tempfile.TemporaryDirectory() as directory:
            marker_root = Path(directory) / "markers"
            calls: list[dict[str, object]] = []

            def append(record):
                calls.append(record)
                return _ref("e")

            with patch.object(effectiveness, "append_event", side_effect=append), patch.object(
                effectiveness, "_find_existing_outcome", return_value=None
            ) as find_existing:
                first = effectiveness.record_task_outcome(
                    marker_root=marker_root,
                    attestation=attestation,
                    task_id="a" * 24,
                    terminal_state="completed",
                    lifecycle_receipt_sha256="b" * 64,
                    terminalized_at_unix=123,
                    observation={
                        "properties": {
                            "Result": "success",
                            "ExecMainCode": "0",
                            "ExecMainStatus": "0",
                        }
                    },
                )
                second = effectiveness.record_task_outcome(
                    marker_root=marker_root,
                    attestation=attestation,
                    task_id="a" * 24,
                    terminal_state="completed",
                    lifecycle_receipt_sha256="b" * 64,
                    terminalized_at_unix=123,
                    observation={
                        "properties": {
                            "Result": "success",
                            "ExecMainCode": "0",
                            "ExecMainStatus": "0",
                        }
                    },
                )
            self.assertEqual(first, _ref("e"))
            self.assertEqual(second, first)
            self.assertEqual(len(calls), 1)
            find_existing.assert_not_called()
            marker = json.loads((marker_root / f"{'f' * 64}.json").read_text())
            self.assertEqual(marker["status"], "completed")
            self.assertEqual(marker["audit_ref"], _ref("e"))
            self.assertRegex(calls[0]["outcome_event_sha256"], r"^[0-9a-f]{64}$")

    def test_append_event_rejects_unbounded_or_sensitive_fields(self) -> None:
        for field in ("argv", "prompt", "raw_report", "stderr", "error"):
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, "forbidden fields"
            ):
                effectiveness.append_event(
                    {"operation": "reposkop-test", field: "sensitive"}
                )

    def test_projection_input_bounds_are_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "since_unix"):
            effectiveness.build_reposkop_effectiveness(since_unix=-1)
        with self.assertRaisesRegex(ValueError, "limit"):
            effectiveness.build_reposkop_effectiveness(limit=0)
        with self.assertRaisesRegex(ValueError, "limit"):
            effectiveness.build_reposkop_effectiveness(
                limit=effectiveness.MAX_SCAN_LIMIT + 1
            )


if __name__ == "__main__":
    unittest.main()
