"""The receipt-bound continuation of an already-switched blue-green cutover.

Three things are pinned here, in this order of importance:

1. the classification admits *exactly* the state it was built for and nothing
   adjacent to it,
2. the effect promotes canonical before it retires green, and never rolls back
   to blue once an irreversible effect exists,
3. the narrow recovery surface stays narrow -- it is a continuation lane, not a
   general mutation or deployment bypass.
"""

from __future__ import annotations

from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
for module_root in (TOOLS, SRC):
    # src wins: several module names exist in both roots, and the deployed
    # runtime always resolves them out of src.
    if str(module_root) in sys.path:
        sys.path.remove(str(module_root))
    sys.path.insert(0, str(module_root))

import deploy_runtime_dual as dual
import grabowski_midcutover_resume as midcutover


HEAD_BLUE = "a" * 40
HEAD_GREEN = "b" * 40
CUTOVER_ID = "bgc-stuck-cutover"
GREEN_RELEASE = "bbbbbbbbbbbb-srcset0011223344-lock5566778899-contractaabbccdd"
BLUE_RELEASE = "aaaaaaaaaaaa-srcset0011223344-lock5566778899-contractaabbccdd"
SELECTOR_SHA256 = "c1" * 32
BINDING_SHA256 = "c2" * 32
SOURCE_IDENTITY_SHA256 = "c3" * 32
GENERATION = 8


def selector_document(
    *,
    slot: str = "green",
    generation: int = GENERATION,
    selector_sha256: str = SELECTOR_SHA256,
    binding_sha256: str = BINDING_SHA256,
    release_id: str = GREEN_RELEASE,
    repo_head: str = HEAD_GREEN,
    cutover_id: str = CUTOVER_ID,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": midcutover.ROUTING_SELECTOR_KIND,
        "generation": generation,
        "selected_slot": slot,
        "upstream_port": midcutover.ROUTING_SLOTS[slot],
        "runtime_binding": {
            "release_id": release_id,
            "repo_head": repo_head,
            "registered_names_sha256": "d1" * 32,
            "agent_instructions_sha256": "d2" * 32,
        },
        "runtime_binding_sha256": binding_sha256,
        "cutover_id": cutover_id,
        "previous_selector_sha256": None,
        "updated_at_unix": 1_000,
        "selector_sha256": selector_sha256,
    }


def cutover_receipt(
    *,
    cutover_id: str = CUTOVER_ID,
    outcome: str = "outcome_unknown",
    phase: str | None = None,
    expected_head: str = HEAD_GREEN,
    green_release_id: str = GREEN_RELEASE,
    generation: int = GENERATION,
    selector_sha256: str = SELECTOR_SHA256,
    binding_sha256: str = BINDING_SHA256,
    switched: bool = True,
    retirement: object = None,
    final_routing: object = None,
    rollback_forbidden: bool = True,
    source_identity_sha256: str | None = SOURCE_IDENTITY_SHA256,
) -> dict[str, object]:
    material: dict[str, object] = {
        "schema_version": 1,
        "kind": midcutover.CUTOVER_RECEIPT_KIND,
        "cutover_id": cutover_id,
        "expected_head": expected_head,
        "blue_release_id": BLUE_RELEASE,
        "green_release_id": green_release_id,
        "source_identity_sha256": source_identity_sha256,
        "outcome": outcome,
        "phase": outcome if phase is None else phase,
        "selector_switch": (
            {
                "switched": True,
                "generation": generation,
                "selected_slot": "green",
                "upstream_port": midcutover.GREEN_UPSTREAM_PORT,
                "selector_sha256": selector_sha256,
                "runtime_binding_sha256": binding_sha256,
                "release_id": green_release_id,
                "repo_head": expected_head,
            }
            if switched
            else None
        ),
        "retirement": retirement,
        "final_routing": final_routing,
        "recovery": {
            "action": "readback_active_runtime_and_recover",
            "automatic_rollback_forbidden": rollback_forbidden,
        },
    }
    return {**material, "receipt_sha256": midcutover.canonical_json_sha256(material)}


def resume_receipt(
    *, resumed_cutover_id: str = CUTOVER_ID, outcome: str = "completed"
) -> dict[str, object]:
    material = {
        "schema_version": 1,
        "kind": midcutover.RESUME_RECEIPT_KIND,
        "resume_id": "bgcr-0123456789abcdef",
        "resumed_cutover_id": resumed_cutover_id,
        "outcome": outcome,
    }
    return {**material, "receipt_sha256": midcutover.canonical_json_sha256(material)}


GREEN_OBSERVATION = {
    "release_id": GREEN_RELEASE,
    "repo_head": HEAD_GREEN,
    "listener_present": True,
}


def classify(**overrides) -> dict[str, object]:
    parameters: dict[str, object] = {
        "expected_head": HEAD_GREEN,
        "selector": selector_document(),
        "receipts": [cutover_receipt()],
        "green_observation": GREEN_OBSERVATION,
    }
    parameters.update(overrides)
    return midcutover.classify_recovery_lane(**parameters)


class ClassificationTests(unittest.TestCase):
    """Tests 10-16 and 23: only the exact stranded state is resumable."""

    def test_exact_receipt_bound_green_state_admits_resume(self) -> None:
        verdict = classify()
        self.assertEqual(verdict["lane"], midcutover.LANE_MID_CUTOVER_RESUME)
        self.assertEqual(verdict["reasons"], [])
        binding = verdict["resume_binding"]
        self.assertEqual(binding["cutover_id"], CUTOVER_ID)
        self.assertEqual(binding["expected_generation"], GENERATION)
        self.assertEqual(binding["expected_selector_sha256"], SELECTOR_SHA256)
        self.assertEqual(binding["expected_release_id"], GREEN_RELEASE)
        material = {
            key: value for key, value in binding.items() if key != "binding_sha256"
        }
        self.assertEqual(
            midcutover.canonical_json_sha256(material), binding["binding_sha256"]
        )

    def test_wrong_generation_is_not_resumable(self) -> None:
        verdict = classify(selector=selector_document(generation=GENERATION + 1))
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
        self.assertIn("selector_generation_matches_receipt", verdict["reasons"])

    def test_foreign_cutover_is_not_resumable(self) -> None:
        verdict = classify(selector=selector_document(cutover_id="bgc-someone-else"))
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
        self.assertIn("receipt_binds_current_selector_cutover", verdict["reasons"])

    def test_wrong_green_release_is_not_resumable(self) -> None:
        verdict = classify(
            selector=selector_document(release_id="cccccccccccc-srcset-lock-contract")
        )
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
        self.assertIn("selector_release_matches_receipt_green", verdict["reasons"])

    def test_newer_selector_generation_fails_the_compare(self) -> None:
        newer = cutover_receipt(
            cutover_id="bgc-newer",
            generation=GENERATION + 1,
            selector_sha256="e1" * 32,
            outcome="completed",
            retirement={"retired": True},
            final_routing={"selector_sha256": "e1" * 32},
        )
        verdict = classify(receipts=[cutover_receipt(), newer])
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
        self.assertIn("no_newer_switch_generation_recorded", verdict["reasons"])

    def test_receipt_before_the_switch_is_never_resumed(self) -> None:
        verdict = classify(receipts=[cutover_receipt(switched=False)])
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
        self.assertIn("exactly_one_unresolved_post_switch_cutover", verdict["reasons"])

    def test_terminal_outcomes_are_never_resumed(self) -> None:
        for outcome in ("completed", "rolled_back", "failed_pre_cutover"):
            with self.subTest(outcome=outcome):
                verdict = classify(receipts=[cutover_receipt(outcome=outcome)])
                self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)

    def test_already_resumed_cutover_is_retired_by_its_resume_receipt(self) -> None:
        verdict = classify(receipts=[cutover_receipt(), resume_receipt()])
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
        self.assertIn("exactly_one_unresolved_post_switch_cutover", verdict["reasons"])

    def test_wrong_expected_head_is_not_resumable(self) -> None:
        verdict = classify(expected_head=HEAD_BLUE)
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
        self.assertIn("receipt_expected_head_matches_request", verdict["reasons"])

    def test_green_that_does_not_serve_the_release_is_not_resumable(self) -> None:
        verdict = classify(
            green_observation={**GREEN_OBSERVATION, "listener_present": False}
        )
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
        self.assertIn("green_serves_expected_release", verdict["reasons"])

    def test_unreadable_receipt_evidence_fails_closed(self) -> None:
        verdict = classify(
            unreadable_receipts=[{"path": "/state/x.json", "error": "hash mismatch"}]
        )
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
        self.assertIn("all_receipt_evidence_readable", verdict["reasons"])

    def test_forged_receipt_is_not_authentic_evidence(self) -> None:
        forged = dict(cutover_receipt())
        forged["green_release_id"] = "attacker-release"
        with self.assertRaises(midcutover.MidCutoverEvidenceError):
            midcutover.validate_cutover_receipt(forged)

    def test_canonical_selector_routes_to_the_scheduled_deploy_lane(self) -> None:
        verdict = classify(
            selector=selector_document(slot="canonical", cutover_id="bgc-old"),
            receipts=[],
        )
        self.assertEqual(verdict["lane"], midcutover.LANE_SCHEDULED_DEPLOY)

    def test_canonical_selector_still_refuses_while_a_cutover_is_open(self) -> None:
        verdict = classify(
            selector=selector_document(slot="canonical", cutover_id="bgc-old"),
            receipts=[cutover_receipt()],
        )
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
        self.assertIn("no_unresolved_post_switch_cutover", verdict["reasons"])

    def test_absent_selector_keeps_the_ordinary_lane_available(self) -> None:
        verdict = classify(selector=None, selector_present=False, receipts=[])
        self.assertEqual(verdict["lane"], midcutover.LANE_SCHEDULED_DEPLOY)

    def test_unreadable_selector_fails_closed(self) -> None:
        verdict = classify(selector=None, selector_error="hash mismatch")
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
        self.assertIn("selector_readable", verdict["reasons"])


class SelectorEvidenceReaderTests(unittest.TestCase):
    def test_tampered_selector_is_unreadable_rather_than_misread(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "selector.json"
            document = selector_document()
            material = {
                key: value
                for key, value in document.items()
                if key != "selector_sha256"
            }
            document["selector_sha256"] = midcutover.canonical_json_sha256(material)
            path.write_text(json.dumps(document), encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(
                midcutover.read_routing_selector_document(path)["generation"],
                GENERATION,
            )
            tampered = dict(document)
            tampered["selected_slot"] = "canonical"
            tampered["upstream_port"] = midcutover.CANONICAL_UPSTREAM_PORT
            path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(midcutover.MidCutoverEvidenceError):
                midcutover.read_routing_selector_document(path)


class _FakeResumeRuntime:
    """Records the order of effects so promotion/retirement cannot silently swap."""

    def __init__(self, *, fail_phase: str | None = None) -> None:
        self.fail_phase = fail_phase
        self.calls: list[str] = []
        self.pointer_promoted = False
        self.canonical_selected = False
        self.green_unit = "grabowski-green-operator-0123456789ab.service"
        self.release_path = Path("/release/green")
        self.contract_evidence = {"judged_by_checkout": False}
        self.classification = {"classification_sha256": "f0" * 32}
        self.resume_binding = {
            "cutover_id": CUTOVER_ID,
            "resumed_receipt_sha256": "f1" * 32,
            "binding_sha256": "f2" * 32,
            "expected_head": HEAD_GREEN,
            "source_identity_sha256": SOURCE_IDENTITY_SHA256,
            "expected_release_id": GREEN_RELEASE,
            "expected_selector_sha256": SELECTOR_SHA256,
            "expected_generation": GENERATION,
        }
        self.admission_released = False

    @property
    def cutover_id(self) -> str:
        return CUTOVER_ID

    def _step(self, phase: str, value: dict[str, object]) -> dict[str, object]:
        self.calls.append(phase)
        if self.fail_phase == phase:
            raise RuntimeError(f"{phase} failed")
        return value

    def verify_green_serving(self):
        return self._step("verify_green_serving", {"green_serving": True})

    def close_mutations(self):
        return self._step("close_mutations", {"closed": True})

    def terminalize_effects(self):
        return self._step("terminalize_effects", {"blocking_tool_calls": 0})

    def promote_canonical(self):
        self.calls.append("promote_canonical")
        # Mirrors the shared primitive: the pointer marker is set before the
        # effect, the selector marker only after the CAS has landed.
        self.pointer_promoted = True
        if self.fail_phase == "promote_canonical":
            raise RuntimeError("promote_canonical failed")
        self.canonical_selected = True
        return {
            "promoted": True,
            "selector": {"selector_sha256": "f3" * 32},
            "final_routing": {"selector_sha256": "f3" * 32, "generation": 9},
            "authoritative_readback": {"authoritative": True},
            "canonical_readiness_sha256": "f5" * 32,
            "operator": {"pid": 4321, "listener": {}},
            "activation_steps": ["symlink-replaced"],
        }

    def promote_canonical_pointer_only(self):
        """Failure after the pointer moved but before the selector CAS."""
        self.calls.append("promote_canonical")
        self.pointer_promoted = True
        raise RuntimeError("canonical operator did not come up")

    def retire_green(self):
        return self._step("retire_green", {"retired": True})

    def final_readback(self):
        return self._step("final_readback", {"release_id": GREEN_RELEASE})

    def authoritative_readback(self):
        return {"authoritative": True, "readback_sha256": "f4" * 32}

    def release_admission_best_effort(self):
        self.calls.append("release_admission_best_effort")
        self.admission_released = True
        return {"released": True}

    # Deliberately absent: there is no rollback_green here. A resume that could
    # roll back would be able to undo a live cutover, which the contract forbids.


class ResumeEffectSemanticsTests(unittest.TestCase):
    """Tests 17-19: ordering, no blue rollback, terminal receipt."""

    def _run(self, runtime: _FakeResumeRuntime, receipt_root: Path):
        with (
            mock.patch.object(dual.core, "deployment_lock", return_value=nullcontext()),
            mock.patch.object(
                dual, "prepare_midcutover_resume_runtime", return_value=runtime
            ),
            mock.patch.object(dual, "BLUE_GREEN_RECEIPT_ROOT", receipt_root),
        ):
            return dual.resume_production_blue_green_cutover(
                repo=ROOT,
                expected_head=HEAD_GREEN,
                resume_id="bgcr-testresume01",
            )

    def test_canonical_promotion_precedes_green_retirement(self) -> None:
        runtime = _FakeResumeRuntime()
        with tempfile.TemporaryDirectory() as temporary:
            result = self._run(runtime, Path(temporary))
        self.assertEqual(result["outcome"], "completed")
        calls = runtime.calls
        self.assertLess(calls.index("promote_canonical"), calls.index("retire_green"))
        self.assertLess(
            calls.index("verify_green_serving"), calls.index("promote_canonical")
        )
        self.assertLess(
            calls.index("close_mutations"), calls.index("promote_canonical")
        )

    def test_green_retirement_failure_never_rolls_back_to_blue(self) -> None:
        runtime = _FakeResumeRuntime(fail_phase="retire_green")
        with tempfile.TemporaryDirectory() as temporary:
            result = self._run(runtime, Path(temporary))
        self.assertEqual(result["outcome"], "outcome_unknown")
        recovery = result["receipt"]["recovery"]
        self.assertTrue(recovery["blue_rollback_forbidden"])
        self.assertTrue(recovery["automatic_rollback_forbidden"])
        self.assertTrue(recovery["canonical_selected"])
        self.assertEqual(recovery["residual_green_unit"], runtime.green_unit)
        self.assertNotIn("release_admission_best_effort", runtime.calls)

    def test_pointer_promotion_failure_is_ambiguous_not_rolled_back(self) -> None:
        runtime = _FakeResumeRuntime(fail_phase="promote_canonical")
        with tempfile.TemporaryDirectory() as temporary:
            result = self._run(runtime, Path(temporary))
        self.assertEqual(result["outcome"], "outcome_unknown")
        self.assertTrue(result["receipt"]["recovery"]["blue_rollback_forbidden"])

    def test_canonical_operator_failure_after_promotion_is_ambiguous(self) -> None:
        runtime = _FakeResumeRuntime()
        runtime.promote_canonical = runtime.promote_canonical_pointer_only
        with tempfile.TemporaryDirectory() as temporary:
            result = self._run(runtime, Path(temporary))
        # The pointer already moved, so "nothing happened" is not an available
        # answer, and neither is undoing it.
        self.assertEqual(result["outcome"], "outcome_unknown")
        self.assertTrue(result["receipt"]["recovery"]["pointer_promoted"])
        self.assertFalse(result["receipt"]["recovery"]["canonical_selected"])

    def test_pre_effect_failure_releases_admission_and_changes_nothing(self) -> None:
        # Anything up to and including the drain is still reversible-by-absence:
        # nothing was promoted, so the state is exactly what it was.
        runtime = _FakeResumeRuntime(fail_phase="terminalize_effects")
        with tempfile.TemporaryDirectory() as temporary:
            result = self._run(runtime, Path(temporary))
        self.assertEqual(result["outcome"], "failed_pre_resume")
        recovery = result["receipt"]["recovery"]
        self.assertTrue(recovery["blue_green_state_unchanged"])
        self.assertTrue(runtime.admission_released)

    def test_successful_resume_persists_a_terminal_revision_bound_receipt(self) -> None:
        runtime = _FakeResumeRuntime()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self._run(runtime, root)
            persisted = json.loads(
                (root / "bgcr-testresume01.json").read_text(encoding="utf-8")
            )
        receipt = result["receipt"]
        self.assertEqual(receipt["kind"], midcutover.RESUME_RECEIPT_KIND)
        self.assertEqual(receipt["outcome"], "completed")
        self.assertEqual(receipt["resumed_cutover_id"], CUTOVER_ID)
        self.assertEqual(receipt["resumed_receipt_sha256"], "f1" * 32)
        self.assertEqual(receipt["expected_head"], HEAD_GREEN)
        self.assertEqual(persisted, receipt)
        self.assertEqual(midcutover.validate_resume_receipt(persisted), persisted)
        # The persisted resume receipt is what retires the original ambiguity.
        self.assertEqual(
            midcutover.resolved_cutover_ids([persisted]), {CUTOVER_ID}
        )
        verdict = classify(receipts=[cutover_receipt(), persisted])
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)


FIXTURE_CONTRACT = {
    "schema_version": 4,
    "mode": "module",
    "module": "grabowski_operator",
    "source": "src/grabowski_runtime.py",
    "expected_tools": ["grabowski_status", "grip_run"],
}
FIXTURE_CONTRACT_BYTES = json.dumps(
    FIXTURE_CONTRACT, indent=2, sort_keys=True
).encode("utf-8")
CONTRACT_SHA256 = hashlib.sha256(FIXTURE_CONTRACT_BYTES).hexdigest()
CONTRACT_RELEASE = (
    f"bbbbbbbbbbbb-srcset0011223344-lock5566778899-contract{CONTRACT_SHA256[:12]}"
)


class ReceiptBoundContractTests(unittest.TestCase):
    """The resume target comes from the artifact chain, never from a checkout."""

    def _release(
        self,
        root: Path,
        *,
        release_id: str = CONTRACT_RELEASE,
        repo_head: str = HEAD_GREEN,
        contract: dict[str, object] | None = None,
        declared_sha256: str | None = None,
        write_snapshot: bool = True,
    ) -> Path:
        contract = contract or FIXTURE_CONTRACT
        release_path = root / release_id
        (release_path / "inputs").mkdir(parents=True)
        contract_path = release_path / "inputs" / "runtime-entrypoint.json"
        payload = json.dumps(contract, indent=2, sort_keys=True).encode("utf-8")
        if write_snapshot:
            contract_path.write_bytes(payload)
        manifest = {
            "release_id": release_id,
            "repo_head": repo_head,
            "completion_status": "complete",
            "entrypoint_contract_sha256": declared_sha256
            or dual.core.sha256_bytes(payload),
            "entrypoint_contract": contract,
            "snapshot_paths": {"runtime_entrypoint": str(contract_path)},
        }
        (release_path / dual.core.MANIFEST_NAME).write_text(
            json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
        )
        return release_path

    def _derive(self, release_path: Path, **overrides):
        parameters = {
            "expected_release_id": release_path.name,
            "expected_repo_head": HEAD_GREEN,
        }
        parameters.update(overrides)
        return dual._receipt_bound_release_contract(release_path, **parameters)

    def test_resume_target_survives_a_newer_runner_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release_path = self._release(Path(temporary))
            # The local checkout deliberately ships a *different* contract than
            # the release: main has moved on, which is exactly what happens while
            # a stranded cutover blocks deploys.  Recovery must not expire.
            with mock.patch.object(
                dual.core,
                "local_contract_validator",
                side_effect=AssertionError("the checkout must not be consulted"),
            ):
                contract, evidence = self._derive(release_path)
        self.assertEqual(contract.module, "grabowski_operator")
        self.assertFalse(evidence["judged_by_checkout"])
        self.assertFalse(evidence["executed_release_code"])
        self.assertEqual(evidence["entrypoint_contract_sha256"], CONTRACT_SHA256)

    def test_release_id_must_commit_to_the_manifest_contract_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release_path = self._release(
                Path(temporary),
                release_id="bbbbbbbbbbbb-srcset0011223344-lock5566778899-contractdeadbeef0000",
            )
            with self.assertRaises(dual.core.DeployError) as raised:
                self._derive(release_path)
        self.assertIn("does not commit", str(raised.exception))

    def test_contract_snapshot_digest_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release_path = self._release(Path(temporary))
            snapshot = release_path / "inputs" / "runtime-entrypoint.json"
            snapshot.write_bytes(snapshot.read_bytes() + b"\n")
            with self.assertRaises(dual.core.DeployError) as raised:
                self._derive(release_path)
        self.assertIn("does not match its declared digest", str(raised.exception))

    def test_missing_immutable_contract_snapshot_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release_path = self._release(Path(temporary), write_snapshot=False)
            with self.assertRaises(dual.core.DeployError):
                self._derive(release_path)

    def test_manifest_head_must_equal_the_receipt_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release_path = self._release(Path(temporary), repo_head=HEAD_BLUE)
            with self.assertRaises(dual.core.DeployError) as raised:
                self._derive(release_path)
        self.assertIn("different repository head", str(raised.exception))

    def test_incomplete_release_is_never_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release_path = self._release(Path(temporary))
            manifest_path = release_path / dual.core.MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["completion_status"] = "incomplete"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(dual.core.DeployError) as raised:
                self._derive(release_path)
        self.assertIn("not a complete deployment artifact", str(raised.exception))


class AdmissionTopologyTests(unittest.TestCase):
    """A/B/C: green is already public, so blue is not required to be alive."""

    def _classify(self, *, service, listener, status_error=None):
        observation = mock.Mock()
        observation.confirmed_active = service == "active"
        observation.confirmed_inactive = service == "inactive"
        observation.to_dict = lambda: {"state": service}
        patches = [
            mock.patch.object(dual, "observe_service", return_value=observation),
            mock.patch.object(dual, "_listener_present", return_value=listener),
        ]
        if status_error is None:
            patches.append(
                mock.patch.object(
                    dual, "_operator_admission_observation", return_value={}
                )
            )
        else:
            patches.append(
                mock.patch.object(
                    dual,
                    "_operator_admission_observation",
                    side_effect=dual.core.DeployError(
                        status_error,
                        phase="operator-admission-drain",
                        details={"failure_class": "transport"},
                    ),
                )
            )
        with patches[0], patches[1], patches[2]:
            return dual.classify_canonical_admission_topology()

    def test_live_canonical_operator_is_drained(self) -> None:
        verdict = self._classify(service="active", listener=True)
        self.assertEqual(verdict["topology"], dual.CANONICAL_OPERATOR_LIVE)

    def test_absent_canonical_operator_needs_no_drain(self) -> None:
        verdict = self._classify(service="inactive", listener=False)
        self.assertEqual(verdict["topology"], dual.CANONICAL_OPERATOR_ABSENT)

    def test_active_but_unreachable_is_ambiguous(self) -> None:
        verdict = self._classify(
            service="active", listener=True, status_error="unreachable"
        )
        self.assertEqual(verdict["topology"], dual.CANONICAL_OPERATOR_AMBIGUOUS)

    def test_inactive_with_a_live_listener_is_ambiguous(self) -> None:
        verdict = self._classify(service="inactive", listener=True)
        self.assertEqual(verdict["topology"], dual.CANONICAL_OPERATOR_AMBIGUOUS)

    def test_unknown_service_state_is_ambiguous(self) -> None:
        verdict = self._classify(service="unknown", listener=False)
        self.assertEqual(verdict["topology"], dual.CANONICAL_OPERATOR_AMBIGUOUS)


class DeploymentAdmissionAuthorityTests(unittest.TestCase):
    """The resume gets its own entry point; the deployment path is untouched."""

    def test_deployment_admission_signature_is_unchanged(self) -> None:
        import inspect

        signature = inspect.signature(dual.engage_operator_deployment_admission)
        self.assertEqual(
            list(signature.parameters),
            ["snapshot", "timeout_seconds", "source_identity_sha256"],
        )
        # The snapshot stays positional and required: nothing that calls the
        # deployment path can reach the snapshot-free variant by omitting it.
        self.assertIs(
            signature.parameters["snapshot"].default, inspect.Parameter.empty
        )

    def test_deployment_admission_still_derives_identity_from_its_snapshot(self) -> None:
        snapshot = mock.Mock(repo_head=HEAD_GREEN)
        with (
            mock.patch.object(
                dual, "_deployment_source_identity_sha256", return_value="ab" * 32
            ) as derive,
            mock.patch.object(dual, "_engage_operator_deployment_admission") as engage,
        ):
            dual.engage_operator_deployment_admission(snapshot, timeout_seconds=10)
        derive.assert_called_once_with(snapshot)
        engage.assert_called_once_with(
            expected_head=HEAD_GREEN,
            source_identity_sha256="ab" * 32,
            timeout_seconds=10,
        )

    def test_receipt_bound_admission_requires_explicit_evidence(self) -> None:
        with self.assertRaises(ValueError):
            dual.engage_receipt_bound_deployment_admission(
                expected_head=None, source_identity_sha256="ab" * 32, timeout_seconds=10
            )
        with self.assertRaises(ValueError):
            dual.engage_receipt_bound_deployment_admission(
                expected_head=HEAD_GREEN, source_identity_sha256=None, timeout_seconds=10
            )
        with self.assertRaisesRegex(ValueError, "expected_head is invalid"):
            dual.engage_receipt_bound_deployment_admission(
                expected_head="not-a-head",
                source_identity_sha256="ab" * 32,
                timeout_seconds=10,
            )
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            dual.engage_receipt_bound_deployment_admission(
                expected_head=HEAD_GREEN,
                source_identity_sha256="not-a-digest",
                timeout_seconds=10,
            )

    def test_productive_deploy_still_needs_blue_continuity_evidence(self) -> None:
        """The cutover's snapshot-continuity gate is exactly as closed as before."""
        topology = mock.Mock(kind="url", server_url_port=18180)
        snapshot = mock.Mock()
        snapshot.contract = mock.Mock(expected_tools=("grabowski_status",))
        unusable_status = {
            "state": "mismatch",
            "external_client_snapshot_observable": False,
            "external_client_schema_observable": False,
            "server_loopback_observable": False,
            "server_loopback_schema_observable": False,
            "receipt_sha256": None,
            "client_declaration_sha256": None,
        }
        with (
            mock.patch.object(
                dual,
                "preflight_url",
                return_value=(snapshot, Path("/runtime"), topology),
            ),
            mock.patch.object(dual, "require_service_active"),
            mock.patch.object(
                dual.core,
                "read_manifest",
                return_value={
                    "entrypoint_contract": {"expected_tools": ["grabowski_status"]}
                },
            ),
            mock.patch.object(
                dual.transport_ingress,
                "_read_runtime_binding",
                return_value=(
                    {
                        "release_id": "blue",
                        "repo_head": HEAD_BLUE,
                        "registered_names_sha256": "d1" * 32,
                        "agent_instructions_sha256": "d2" * 32,
                    },
                    "aa" * 32,
                ),
            ),
            mock.patch.object(
                dual.transport_ingress,
                "read_routing_selector",
                return_value={
                    "selected_slot": "canonical",
                    "runtime_binding": {
                        "release_id": "blue",
                        "repo_head": HEAD_BLUE,
                        "registered_names_sha256": "d1" * 32,
                        "agent_instructions_sha256": "d2" * 32,
                    },
                    "selector_sha256": "aa" * 32,
                    "runtime_binding_sha256": "aa" * 32,
                },
            ),
            mock.patch.object(dual, "_require_selector_authority"),
            mock.patch.object(
                dual.core,
                "build_release",
                return_value=mock.Mock(release_path=Path("/release/green")),
            ),
            mock.patch.object(dual.core, "releases_root_for"),
            mock.patch.object(dual.core, "verify_apply_snapshot_unchanged"),
            mock.patch.object(dual.core, "verify_manifest"),
            mock.patch.object(
                dual.client_snapshot, "snapshot_status", return_value=unusable_status
            ),
        ):
            with self.assertRaises(dual.core.DeployError) as raised:
                dual.prepare_production_blue_green_runtime(
                    ROOT,
                    Path("/runtime"),
                    Path("/profile.yml"),
                    expected_head=HEAD_GREEN,
                    cutover_id="bgc-continuity-gate",
                    timeout_seconds=10,
                )
        self.assertEqual(raised.exception.phase, "snapshot-authenticity-preflight")


class GreenProofBeforeEffectTests(unittest.TestCase):
    """Nothing irreversible happens before green is proven authoritatively."""

    def _runtime(self) -> dual.MidCutoverResumeRuntime:
        return dual.MidCutoverResumeRuntime(
            repo=ROOT,
            runtime=Path("/runtime"),
            release_path=Path("/release/green"),
            contract=mock.Mock(module="grabowski_operator"),
            contract_evidence={"judged_by_checkout": False},
            green_binding={
                "release_id": GREEN_RELEASE,
                "repo_head": HEAD_GREEN,
                "registered_names_sha256": "d1" * 32,
                "agent_instructions_sha256": "d2" * 32,
            },
            classification={"classification_sha256": "f0" * 32},
            resume_binding={
                "cutover_id": CUTOVER_ID,
                "expected_selector_sha256": SELECTOR_SHA256,
                "expected_runtime_binding_sha256": BINDING_SHA256,
                "source_identity_sha256": SOURCE_IDENTITY_SHA256,
            },
            timeout_seconds=10,
            green_unit="grabowski-green-operator-0123456789ab.service",
            selector_before=selector_document(),
        )

    def test_failed_mcp_probe_leaves_pointer_and_selector_untouched(self) -> None:
        runtime = self._runtime()
        with (
            mock.patch.object(
                dual, "_require_selector_authority", return_value={"authoritative": True}
            ),
            mock.patch.object(
                dual,
                "_probe_release_runtime",
                side_effect=RuntimeError("green MCP readiness failed"),
            ),
            mock.patch.object(dual.core, "activate_pointer") as activate,
            mock.patch.object(
                dual.transport_ingress, "publish_routing_selector"
            ) as publish,
            mock.patch.object(dual, "_stop_green_operator") as stop_green,
        ):
            with self.assertRaisesRegex(RuntimeError, "green MCP readiness failed"):
                runtime.verify_green_serving()
        self.assertFalse(runtime.green_proven)
        activate.assert_not_called()
        publish.assert_not_called()
        stop_green.assert_not_called()

    def test_promotion_refuses_without_a_green_readiness_proof(self) -> None:
        runtime = self._runtime()
        with (
            mock.patch.object(dual.core, "activate_pointer") as activate,
            mock.patch.object(
                dual.transport_ingress, "publish_routing_selector"
            ) as publish,
        ):
            with self.assertRaises(dual.core.DeployError):
                runtime.promote_canonical()
        activate.assert_not_called()
        publish.assert_not_called()

    def test_retirement_refuses_without_a_proven_canonical_selection(self) -> None:
        runtime = self._runtime()
        with mock.patch.object(dual, "_stop_green_operator") as stop_green:
            with self.assertRaises(dual.core.DeployError):
                runtime.retire_green()
        stop_green.assert_not_called()

    def test_shared_promotion_reverifies_green_before_the_pointer_moves(self) -> None:
        events: list[str] = []
        progress = dual.CanonicalPromotionProgress()
        with (
            mock.patch.object(
                dual,
                "_require_selector_authority",
                side_effect=lambda **_k: (
                    events.append("selector-authority") or {"authoritative": True}
                ),
            ),
            mock.patch.object(
                dual.core,
                "activate_pointer",
                side_effect=lambda *_a: events.append("activate-pointer"),
            ),
            mock.patch.object(dual, "stop_service"),
            mock.patch.object(
                dual, "observe_service", return_value=mock.Mock(confirmed_active=True)
            ),
            mock.patch.object(dual, "start_service"),
            mock.patch.object(
                dual, "verify_operator_process", return_value={"pid": 7}
            ),
            mock.patch.object(dual, "_require_loopback_listener", return_value={}),
            mock.patch.object(
                dual.transport_ingress,
                "publish_routing_selector",
                return_value={
                    "selector_sha256": "f3" * 32,
                    "runtime_binding_sha256": BINDING_SHA256,
                    "generation": 9,
                    "selected_slot": "canonical",
                    "upstream_port": 18181,
                    "runtime_binding": {},
                },
            ),
            mock.patch.object(
                dual, "_probe_release_runtime", return_value={"ready": True}
            ),
        ):
            dual.promote_green_release_to_canonical(
                runtime=Path("/runtime"),
                release_path=Path("/release/green"),
                contract=mock.Mock(),
                green_binding={
                    "release_id": GREEN_RELEASE,
                    "repo_head": HEAD_GREEN,
                    "registered_names_sha256": "d1" * 32,
                    "agent_instructions_sha256": "d2" * 32,
                },
                activation=mock.Mock(steps=[]),
                expected_green_selector_sha256=SELECTOR_SHA256,
                expected_green_binding_sha256=BINDING_SHA256,
                cutover_id=CUTOVER_ID,
                timeout_seconds=10,
                progress=progress,
            )
        self.assertLess(
            events.index("selector-authority"), events.index("activate-pointer")
        )
        self.assertTrue(progress.pointer_promoted)
        self.assertTrue(progress.canonical_selected)


class ResumeLineageIdempotenceTests(unittest.TestCase):
    """One stranded cutover produces effects exactly once."""

    def test_denied_resume_receipt_never_poisons_classification(self) -> None:
        denied = {
            "schema_version": 1,
            "kind": midcutover.RESUME_RECEIPT_KIND,
            "resume_id": "bgcr-deniedattempt01",
            "resumed_cutover_id": None,
            "outcome": "denied",
        }
        denied["receipt_sha256"] = midcutover.canonical_json_sha256(denied)
        # It must read back as authentic evidence...
        self.assertEqual(midcutover.validate_resume_receipt(denied), denied)
        # ...resolve nothing...
        self.assertEqual(midcutover.resolved_cutover_ids([denied]), set())
        # ...and leave the stranded cutover resumable.
        verdict = classify(receipts=[cutover_receipt(), denied])
        self.assertEqual(verdict["lane"], midcutover.LANE_MID_CUTOVER_RESUME)

    def test_completed_resume_receipt_must_name_its_lineage(self) -> None:
        broken = {
            "schema_version": 1,
            "kind": midcutover.RESUME_RECEIPT_KIND,
            "resume_id": "bgcr-nolineage00001",
            "resumed_cutover_id": None,
            "outcome": "completed",
        }
        broken["receipt_sha256"] = midcutover.canonical_json_sha256(broken)
        with self.assertRaisesRegex(
            midcutover.MidCutoverEvidenceError, "names no lineage"
        ):
            midcutover.validate_resume_receipt(broken)

    def test_resolution_is_discoverable_from_the_original_cutover(self) -> None:
        resolution = midcutover.resolution_for_cutover(
            [cutover_receipt(), resume_receipt()], CUTOVER_ID
        )
        self.assertIsNotNone(resolution)
        self.assertEqual(resolution["resumed_cutover_id"], CUTOVER_ID)
        self.assertIsNone(
            midcutover.resolution_for_cutover([cutover_receipt()], CUTOVER_ID)
        )

    def test_lineage_survives_a_process_restart_through_the_receipt_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            for receipt in (cutover_receipt(), resume_receipt()):
                name = receipt.get("cutover_id") or receipt["resume_id"]
                path = root / f"{name}.json"
                path.write_text(
                    json.dumps(
                        receipt,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    encoding="utf-8",
                )
                path.chmod(0o600)
            # A cold reader with no in-memory state reaches the same verdict.
            loaded = midcutover.load_receipts(root)
            self.assertEqual(loaded["unreadable"], [])
            verdict = midcutover.classify_recovery_lane(
                expected_head=HEAD_GREEN,
                selector=selector_document(),
                receipts=loaded["receipts"],
                green_observation=GREEN_OBSERVATION,
            )
            self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
            self.assertEqual(
                verdict["evidence"]["resolution"]["resumed_cutover_id"], CUTOVER_ID
            )
            self.assertEqual(
                midcutover.resolved_cutover_ids(loaded["receipts"]), {CUTOVER_ID}
            )

    def test_second_resume_attempt_produces_no_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            with (
                mock.patch.object(
                    dual.core, "deployment_lock", return_value=nullcontext()
                ),
                mock.patch.object(dual, "BLUE_GREEN_RECEIPT_ROOT", root),
                mock.patch.object(
                    dual,
                    "prepare_midcutover_resume_runtime",
                    side_effect=dual.MidCutoverResumeDenied(
                        {
                            "lane": midcutover.LANE_FAIL_CLOSED,
                            "reasons": ["exactly_one_unresolved_post_switch_cutover"],
                            "classification_sha256": "f0" * 32,
                        }
                    ),
                ),
                mock.patch.object(dual.core, "activate_pointer") as activate,
                mock.patch.object(
                    dual.transport_ingress, "publish_routing_selector"
                ) as publish,
                mock.patch.object(dual, "_stop_green_operator") as stop_green,
            ):
                result = dual.resume_production_blue_green_cutover(
                    repo=ROOT,
                    expected_head=HEAD_GREEN,
                    resume_id="bgcr-secondattempt1",
                )
            self.assertEqual(result["outcome"], "denied")
            activate.assert_not_called()
            publish.assert_not_called()
            stop_green.assert_not_called()
            persisted = json.loads(
                (root / "bgcr-secondattempt1.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                midcutover.validate_resume_receipt(persisted), persisted
            )
            self.assertEqual(midcutover.resolved_cutover_ids([persisted]), set())


class RecoverySurfaceTests(unittest.TestCase):
    """Tests 20-23: the narrow lane stays narrow."""

    def setUp(self) -> None:
        try:
            import grabowski_provenance_recovery  # noqa: F401
        except Exception as exc:  # pragma: no cover - environment guard
            self.skipTest(f"provenance recovery module unavailable: {exc}")

    @staticmethod
    def _module():
        import grabowski_provenance_recovery as provenance_recovery

        return provenance_recovery

    def test_classified_resume_reaches_the_resume_operation(self) -> None:
        provenance_recovery = self._module()
        lane = {
            "lane": midcutover.LANE_MID_CUTOVER_RESUME,
            "resume_binding": {"binding_sha256": "f2" * 32},
        }
        with (
            mock.patch.object(provenance_recovery.operator, "_require_operator_capability"),
            mock.patch.object(
                provenance_recovery.self_deploy,
                "_deploy_schedule_lock",
                return_value=nullcontext(),
            ),
            mock.patch.object(provenance_recovery, "_recovery_lane", return_value=lane),
            mock.patch.object(
                provenance_recovery, "_resume_under_schedule_lock",
                return_value={"lane": midcutover.LANE_MID_CUTOVER_RESUME},
            ) as resume,
            mock.patch.object(
                provenance_recovery, "_repair_under_schedule_lock"
            ) as repair,
        ):
            result = provenance_recovery.grabowski_recovery_provenance_repair(
                expected_head=HEAD_GREEN
            )
        resume.assert_called_once_with(HEAD_GREEN)
        repair.assert_not_called()
        self.assertEqual(result["lane"], midcutover.LANE_MID_CUTOVER_RESUME)

    def test_scheduled_lane_still_reaches_the_deployment_repair(self) -> None:
        provenance_recovery = self._module()
        lane = {"lane": midcutover.LANE_SCHEDULED_DEPLOY, "resume_binding": None}
        with (
            mock.patch.object(provenance_recovery.operator, "_require_operator_capability"),
            mock.patch.object(
                provenance_recovery.self_deploy,
                "_deploy_schedule_lock",
                return_value=nullcontext(),
            ),
            mock.patch.object(provenance_recovery, "_recovery_lane", return_value=lane),
            mock.patch.object(
                provenance_recovery, "_resume_under_schedule_lock"
            ) as resume,
            mock.patch.object(
                provenance_recovery, "_repair_under_schedule_lock",
                return_value={"kind": "deploy"},
            ) as repair,
        ):
            provenance_recovery.grabowski_recovery_provenance_repair(
                expected_head=HEAD_GREEN
            )
        repair.assert_called_once()
        resume.assert_not_called()

    def test_recovery_tool_exposes_no_lane_selection_input(self) -> None:
        """The lane is never selectable, and the public contract stays put.

        Two invariants in one signature: a caller must not be able to pick the
        lane, and the recovery fix must not add an input to a tool whose schema
        the published 196-tool connector contract is currently converging on.
        """
        import inspect

        provenance_recovery = self._module()
        parameters = set(
            inspect.signature(
                provenance_recovery.grabowski_recovery_provenance_repair
            ).parameters
        )
        self.assertEqual(
            parameters,
            {
                "expected_head",
                "source_repository",
                "source_lease_owner_id",
                "delay_seconds",
                "ctx",
            },
        )
        assess_parameters = set(
            inspect.signature(
                provenance_recovery.grabowski_recovery_provenance_assess
            ).parameters
        )
        self.assertEqual(
            assess_parameters,
            {"expected_head", "source_repository", "source_lease_owner_id"},
        )

    def test_scheduled_deploy_gate_refuses_while_a_cutover_is_open(self) -> None:
        provenance_recovery = self._module()
        lane = {"lane": midcutover.LANE_FAIL_CLOSED, "resume_binding": None}
        with (
            mock.patch.object(provenance_recovery, "_recovery_lane", return_value=lane),
            mock.patch.object(
                provenance_recovery.self_deploy,
                "_deployment_source_preflight",
                side_effect=RuntimeError("source unavailable"),
            ),
        ):
            gate = provenance_recovery.evaluate_gate(HEAD_GREEN)
        self.assertFalse(gate["allowed"])
        self.assertIn("scheduled_deploy_lane_admitted", gate["reasons"])

    def test_resume_gate_refuses_without_a_classified_resume(self) -> None:
        provenance_recovery = self._module()
        lane = {"lane": midcutover.LANE_FAIL_CLOSED, "resume_binding": None}
        with mock.patch.object(
            provenance_recovery, "_recovery_lane", return_value=lane
        ):
            gate = provenance_recovery.evaluate_resume_gate(HEAD_GREEN)
        self.assertFalse(gate["allowed"])
        self.assertIn("mid_cutover_resume_classified", gate["reasons"])
        self.assertIn("resume_binding_available", gate["reasons"])
        self.assertFalse(gate["authority_model"]["grants_new_deployment_authority"])
        self.assertFalse(gate["authority_model"]["grants_power_worker_authority"])

    def test_resume_runner_is_reserved_for_the_typed_lane(self) -> None:
        import grabowski_operator as operator
        import grabowski_self_deploy as self_deploy

        command = self_deploy._midcutover_resume_command(
            self_deploy.CANONICAL_REPOSITORY,
            self_deploy.CANONICAL_REPOSITORY
            / self_deploy.MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH,
            HEAD_GREEN,
            CUTOVER_ID,
            "f2" * 32,
        )
        self.assertIsNotNone(self_deploy._midcutover_resume_command_fields(command))
        self.assertTrue(
            operator._reserved_runtime_deploy_command(command, Path.home())
        )
        with self.assertRaises(PermissionError):
            operator._start_job(command, allow_reserved_runtime_deploy=False)

    def test_transport_exemption_covers_only_the_recovery_tool(self) -> None:
        import grabowski_operator as operator

        broken = {
            flag: False
            for flag in operator._PROVENANCE_RECOVERY_REPAIRABLE_INTEGRITY_FLAGS
        }
        mutating = mock.Mock()
        mutating.annotations = mock.Mock(readOnlyHint=False)
        with mock.patch.object(
            operator.base, "_deployment_metadata", return_value=broken
        ):
            self.assertTrue(
                operator._provenance_recovery_transport_exempt_call(
                    "grabowski_recovery_provenance_repair", mutating
                )
            )
            for tool_name in (
                "grabowski_power_run",
                "grabowski_git",
                "grabowski_terminal_run",
                "grabowski_user_service",
                "grabowski_runtime_deploy_schedule",
            ):
                with self.subTest(tool=tool_name):
                    self.assertFalse(
                        operator._provenance_recovery_transport_exempt_call(
                            tool_name, mutating
                        )
                    )


if __name__ == "__main__":
    unittest.main()
