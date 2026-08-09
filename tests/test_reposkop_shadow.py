from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_reposkop_shadow as shadow


def _sha256_json(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _rehash(value: dict[str, object], field: str) -> dict[str, object]:
    result = {key: item for key, item in value.items() if key != field}
    result[field] = _sha256_json(result)
    return result


def _observation(
    workspace: Path,
    purpose: str,
    *,
    identity: str,
    complete: bool = True,
) -> dict[str, object]:
    return _rehash(
        {
            "schema_version": 2,
            "kind": "reposkop_checkout_observation",
            "authority": {
                "producer": "reposkop",
                "domain": "local_checkout_identity",
                "claim": "canonical",
            },
            "target": {"path": str(workspace), "purpose": purpose},
            "role": {"value": "grabowski_workspace", "reasons": []},
            "exists": True,
            "is_git_checkout": complete,
            "observation_complete": complete,
            "errors": [] if complete else ["not_git_checkout"],
            "identities": {"checkout_identity_sha256": identity * 64},
        },
        "observation_sha256",
    )


def _continuity(
    before: dict[str, object],
    after: dict[str, object],
    *,
    state: str,
) -> dict[str, object]:
    anomaly_codes = ["identity.checkout_break"] if state == "identity_break" else []
    transition = _rehash(
        {
            "schema_version": 1,
            "kind": "reposkop_checkout_transition",
            "authority": {
                "producer": "reposkop",
                "domain": "local_checkout_transition",
                "claim": "canonical",
            },
            "before": before,
            "after": after,
            "before_observation_sha256": before["observation_sha256"],
            "after_observation_sha256": after["observation_sha256"],
            "identity_continuity": (
                "same_repository_different_checkout"
                if state == "identity_break"
                else "same_checkout"
            ),
            "identity_changes": {},
            "state_changes": {},
            "reason_codes": [],
            "anomaly_codes": anomaly_codes,
            "effect_authorized": False,
        },
        "transition_sha256",
    )
    return _rehash(
        {
            "schema_version": 1,
            "kind": "reposkop_checkout_continuity",
            "authority": {
                "producer": "reposkop",
                "domain": "local_checkout_continuity",
                "claim": "canonical",
            },
            "state": state,
            "reason_codes": anomaly_codes,
            "transition": transition,
            "transition_sha256": transition["transition_sha256"],
            "transition_validation": {"valid": True, "errors": []},
            "effect_authorized": False,
        },
        "continuity_sha256",
    )


class ReposkopCheckoutShadowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.workspace = self.root / "checkout"
        self.workspace.mkdir()
        (self.workspace / ".git").mkdir()
        self.evidence_root = self.root / "shadow"
        self.evidence_root.mkdir(mode=0o700)
        self.events: list[dict[str, object]] = []
        self.root_patch = patch.object(
            shadow, "_ensure_root", return_value=self.evidence_root
        )
        self.audit_patch = patch.object(
            shadow.reposkop_effectiveness,
            "append_event",
            side_effect=self._append_event,
        )
        self.root_patch.start()
        self.audit_patch.start()

    def tearDown(self) -> None:
        self.audit_patch.stop()
        self.root_patch.stop()
        self.temporary.cleanup()

    def _append_event(self, event: dict[str, object]) -> str:
        self.events.append(dict(event))
        return "audit-record-sha256:" + f"{len(self.events):064x}"

    def test_success_persists_bound_artifacts_and_exact_terminal_audit_once(self) -> None:
        task_id = "0123456789abcdef01234567"
        purpose = f"grabowski-task-shadow:{shadow._task_key(task_id)[:32]}"
        before = _observation(self.workspace, purpose, identity="1")
        after = _observation(self.workspace, purpose, identity="2")
        continuity = _continuity(before, after, state="identity_break")

        def run(
            command: str,
            target: Path,
            *,
            purpose: str,
            expected_artifact: Path | None = None,
        ) -> tuple[dict[str, object], str]:
            self.assertEqual(target, self.workspace)
            if command == "inspect":
                self.assertIsNone(expected_artifact)
                return before, "a" * 64
            self.assertEqual(command, "continuity")
            self.assertIsNotNone(expected_artifact)
            return continuity, "a" * 64

        with patch.object(shadow, "_run_reposkop", side_effect=run):
            before_result = shadow.capture_before_best_effort(
                task_id=task_id,
                workspace=str(self.workspace),
                evaluation_id="b" * 64,
                reposkop_cohort="prospective_control",
            )
            prepared = shadow.prepare_terminal_best_effort(
                task_id=task_id,
                before_summary=before_result,
            )
            terminal_artifact_path = shadow._paths(self.evidence_root, task_id)[
                "terminal_artifact"
            ]
            terminal_artifact_payload = terminal_artifact_path.read_bytes()
            self.assertEqual(json.loads(terminal_artifact_payload), continuity)
            self.assertEqual(
                prepared["artifact_file_sha256"],
                hashlib.sha256(terminal_artifact_payload).hexdigest(),
            )
            terminal_result = shadow.finalize_terminal_best_effort(
                task_id=task_id,
                terminalization_sha256="c" * 64,
                lifecycle_receipt_sha256="d" * 64,
                prepared=prepared,
            )
            replay = shadow.finalize_terminal_best_effort(
                task_id=task_id,
                terminalization_sha256="c" * 64,
                lifecycle_receipt_sha256="d" * 64,
                prepared=prepared,
            )

        self.assertEqual(before_result["status"], "completed")
        self.assertEqual(terminal_result["status"], "completed")
        terminal_binding_path = shadow._paths(self.evidence_root, task_id)[
            "terminal_binding"
        ]
        terminal_binding = json.loads(terminal_binding_path.read_text(encoding="utf-8"))
        self.assertEqual(
            terminal_binding["artifact_file_sha256"],
            prepared["artifact_file_sha256"],
        )
        self.assertEqual(replay["evidence_sha256"], terminal_result["evidence_sha256"])
        self.assertEqual(len(self.events), 2)
        terminal_event = self.events[-1]
        transition = continuity["transition"]
        self.assertEqual(terminal_event["task_id"], task_id)
        self.assertEqual(
            terminal_event["before_observation_sha256"],
            before["observation_sha256"],
        )
        self.assertEqual(
            terminal_event["after_observation_sha256"],
            after["observation_sha256"],
        )
        self.assertEqual(
            terminal_event["transition_sha256"],
            transition["transition_sha256"],
        )
        self.assertEqual(
            terminal_event["continuity_sha256"],
            continuity["continuity_sha256"],
        )
        self.assertEqual(
            terminal_event["artifact_file_sha256"],
            prepared["artifact_file_sha256"],
        )
        self.assertEqual(terminal_event["continuity_state"], "identity_break")
        self.assertEqual(terminal_event["measurement_class"], "identity_break")
        self.assertEqual(terminal_event["reason_codes"], ["identity.checkout_break"])
        self.assertEqual(terminal_event["anomaly_codes"], ["identity.checkout_break"])
        self.assertIs(terminal_event["decision_effect"], False)
        self.assertIs(terminal_event["effect_authorized"], False)
        self.assertNotIn("workspace", terminal_event)
        self.assertNotIn("error", terminal_event)

    def test_start_failure_is_unavailable_and_nonblocking(self) -> None:
        with patch.object(
            shadow,
            "_run_reposkop",
            side_effect=shadow.ReposkopShadowError(
                "missing inspect", category="capability_unavailable"
            ),
        ):
            result = shadow.capture_before_best_effort(
                task_id="start-failure",
                workspace=str(self.workspace),
                evaluation_id="1" * 64,
                reposkop_cohort="prospective_control",
            )

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["failure_category"], "capability_unavailable")
        self.assertIs(result["decision_effect"], False)
        self.assertEqual(self.events[-1]["shadow_status"], "unavailable")

    def test_terminal_failure_is_unavailable_and_nonblocking(self) -> None:
        task_id = "terminal-failure"
        purpose = f"grabowski-task-shadow:{shadow._task_key(task_id)[:32]}"
        before = _observation(self.workspace, purpose, identity="1")

        def run(
            command: str,
            target: Path,
            *,
            purpose: str,
            expected_artifact: Path | None = None,
        ) -> tuple[dict[str, object], str]:
            if command == "inspect":
                return before, "a" * 64
            raise shadow.ReposkopShadowError(
                "missing continuity", category="capability_unavailable"
            )

        with patch.object(shadow, "_run_reposkop", side_effect=run):
            before_result = shadow.capture_before_best_effort(
                task_id=task_id,
                workspace=str(self.workspace),
                evaluation_id="2" * 64,
                reposkop_cohort="prospective_sample",
            )
            prepared = shadow.prepare_terminal_best_effort(
                task_id=task_id,
                before_summary=before_result,
            )
            result = shadow.finalize_terminal_best_effort(
                task_id=task_id,
                terminalization_sha256="3" * 64,
                lifecycle_receipt_sha256="4" * 64,
                prepared=prepared,
            )

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["continuity_state"], "inconclusive")
        self.assertEqual(result["measurement_class"], "inconclusive/unavailable")
        self.assertIs(result["decision_effect"], False)
        self.assertEqual(self.events[-1]["failure_category"], "capability_unavailable")

    def test_terminal_prepare_storage_failure_is_audited_unavailable(self) -> None:
        task_id = "storage-failure"
        purpose = f"grabowski-task-shadow:{shadow._task_key(task_id)[:32]}"
        before = _observation(self.workspace, purpose, identity="1")

        with patch.object(
            shadow, "_run_reposkop", return_value=(before, "a" * 64)
        ):
            before_result = shadow.capture_before_best_effort(
                task_id=task_id,
                workspace=str(self.workspace),
                evaluation_id="9" * 64,
                reposkop_cohort="prospective_control",
            )

        with patch.object(
            shadow,
            "_ensure_root",
            side_effect=PermissionError("shadow root inaccessible"),
        ):
            prepared = shadow.prepare_terminal_best_effort(
                task_id=task_id,
                before_summary=before_result,
            )
            result = shadow.finalize_terminal_best_effort(
                task_id=task_id,
                terminalization_sha256="3" * 64,
                lifecycle_receipt_sha256="4" * 64,
                prepared=prepared,
            )

        self.assertEqual(prepared["status"], "unavailable")
        self.assertEqual(prepared["failure_category"], "permission_unavailable")
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "unavailable")
        terminal_event = self.events[-1]
        self.assertEqual(terminal_event["operation"], shadow.TERMINAL_OPERATION)
        self.assertEqual(terminal_event["shadow_status"], "unavailable")
        self.assertIs(terminal_event["attempted"], True)
        self.assertEqual(
            terminal_event["failure_category"], "permission_unavailable"
        )
        self.assertIs(terminal_event["decision_effect"], False)
        self.assertIs(terminal_event["effect_authorized"], False)

    def test_terminal_artifact_tamper_after_prepare_is_audited_unavailable(self) -> None:
        task_id = "terminal-artifact-tamper"
        purpose = f"grabowski-task-shadow:{shadow._task_key(task_id)[:32]}"
        before = _observation(self.workspace, purpose, identity="1")
        after = _observation(self.workspace, purpose, identity="1")
        continuity = _continuity(before, after, state="intact")

        def run(
            command: str,
            target: Path,
            *,
            purpose: str,
            expected_artifact: Path | None = None,
        ) -> tuple[dict[str, object], str]:
            if command == "inspect":
                return before, "a" * 64
            return continuity, "a" * 64

        with patch.object(shadow, "_run_reposkop", side_effect=run):
            before_result = shadow.capture_before_best_effort(
                task_id=task_id,
                workspace=str(self.workspace),
                evaluation_id="b" * 64,
                reposkop_cohort="prospective_control",
            )
            prepared = shadow.prepare_terminal_best_effort(
                task_id=task_id,
                before_summary=before_result,
            )

        self.assertEqual(prepared["status"], "completed")
        paths = shadow._paths(self.evidence_root, task_id)
        paths["terminal_artifact"].write_text(
            '{"tampered":true}\n', encoding="utf-8"
        )

        result = shadow.finalize_terminal_best_effort(
            task_id=task_id,
            terminalization_sha256="3" * 64,
            lifecycle_receipt_sha256="4" * 64,
            prepared=prepared,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["failure_category"], "evidence_integrity_error")
        self.assertIsNotNone(result["audit_ref"])
        self.assertFalse(paths["terminal_binding"].exists())
        terminal_event = self.events[-1]
        self.assertEqual(terminal_event["shadow_status"], "unavailable")
        self.assertEqual(
            terminal_event["failure_category"], "evidence_integrity_error"
        )
        self.assertEqual(
            terminal_event["artifact_file_sha256"],
            prepared["artifact_file_sha256"],
        )
        self.assertIs(terminal_event["decision_effect"], False)
        self.assertIs(terminal_event["effect_authorized"], False)

    def test_terminal_storage_failure_after_prepare_is_audited_unavailable(self) -> None:
        task_id = "terminal-storage-failure"
        purpose = f"grabowski-task-shadow:{shadow._task_key(task_id)[:32]}"
        before = _observation(self.workspace, purpose, identity="1")
        after = _observation(self.workspace, purpose, identity="1")
        continuity = _continuity(before, after, state="intact")

        def run(
            command: str,
            target: Path,
            *,
            purpose: str,
            expected_artifact: Path | None = None,
        ) -> tuple[dict[str, object], str]:
            if command == "inspect":
                return before, "a" * 64
            return continuity, "a" * 64

        with patch.object(shadow, "_run_reposkop", side_effect=run):
            before_result = shadow.capture_before_best_effort(
                task_id=task_id,
                workspace=str(self.workspace),
                evaluation_id="a" * 64,
                reposkop_cohort="prospective_control",
            )
            prepared = shadow.prepare_terminal_best_effort(
                task_id=task_id,
                before_summary=before_result,
            )

        self.assertEqual(prepared["status"], "completed")
        with patch.object(
            shadow,
            "_ensure_root",
            side_effect=PermissionError("terminal shadow root inaccessible"),
        ):
            result = shadow.finalize_terminal_best_effort(
                task_id=task_id,
                terminalization_sha256="3" * 64,
                lifecycle_receipt_sha256="4" * 64,
                prepared=prepared,
            )

        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["failure_category"], "permission_unavailable")
        self.assertEqual(result["continuity_state"], "inconclusive")
        self.assertEqual(result["measurement_class"], "inconclusive/unavailable")
        self.assertIsNotNone(result["audit_ref"])
        terminal_event = self.events[-1]
        self.assertEqual(terminal_event["operation"], shadow.TERMINAL_OPERATION)
        self.assertEqual(terminal_event["shadow_status"], "unavailable")
        self.assertEqual(terminal_event["failure_category"], "permission_unavailable")
        self.assertIs(terminal_event["decision_effect"], False)
        self.assertIs(terminal_event["effect_authorized"], False)
        terminal_path = shadow._paths(self.evidence_root, task_id)["terminal_binding"]
        self.assertFalse(terminal_path.exists())

    def test_non_repository_is_not_sent_to_reposkop(self) -> None:
        non_repository = self.root / "plain"
        non_repository.mkdir()
        with patch.object(shadow, "_run_reposkop") as run:
            result = shadow.capture_before_best_effort(
                task_id="not-a-repository",
                workspace=str(non_repository),
                evaluation_id=None,
                reposkop_cohort=None,
            )

        self.assertIsNone(result)
        run.assert_not_called()
        self.assertEqual(self.events, [])


if __name__ == "__main__":
    unittest.main()
