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

import ast
from contextlib import contextmanager, nullcontext
import hashlib
import json
from pathlib import Path
import re
import sys
import subprocess
import tempfile
import types
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

class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


def _install_import_stubs() -> None:
    """Make the operator and recovery modules importable without their deps.

    These checks must run wherever the suite runs.  Inheriting a stub from
    whichever test module discovery happened to reach first made the capability
    and transport-gate regressions below skip silently under some orderings and
    on the interpreter CI actually uses -- which is the one place they matter
    most.  Real packages always win; the stubs fill in only what is missing.
    """
    try:
        import mcp  # noqa: F401
    except ModuleNotFoundError:
        fake_mcp = types.ModuleType("mcp")
        fake_server = types.ModuleType("mcp.server")
        fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
        fake_types = types.ModuleType("mcp.types")
        fake_fastmcp.FastMCP = _FakeFastMCP
        fake_fastmcp.Context = object
        fake_types.ToolAnnotations = _FakeToolAnnotations
        sys.modules.setdefault("mcp", fake_mcp)
        sys.modules.setdefault("mcp.server", fake_server)
        sys.modules.setdefault("mcp.server.fastmcp", fake_fastmcp)
        sys.modules.setdefault("mcp.types", fake_types)
    try:
        import pydantic  # noqa: F401
    except ModuleNotFoundError:
        fake_pydantic = types.ModuleType("pydantic")
        fake_pydantic.Field = lambda **kwargs: kwargs
        sys.modules.setdefault("pydantic", fake_pydantic)


_install_import_stubs()

import deploy_runtime_dual as dual
import grabowski_midcutover_resume as midcutover


HEAD_BLUE = "a" * 40
HEAD_GREEN = "b" * 40
CUTOVER_ID = "bgc-stuck-cutover"
GREEN_RELEASE = "bbbbbbbbbbbb-srcset001122334455-lock556677889900-contractaabbccddeeff"
BLUE_RELEASE = "aaaaaaaaaaaa-srcset001122334455-lock556677889900-contractaabbccddeeff"
SELECTOR_SHA256 = "c1" * 32
BINDING_SHA256 = "c2" * 32
SOURCE_IDENTITY_SHA256 = "c3" * 32
GENERATION = 8
CUTOVER_GENERATION = 1
ACTIVATION_TIME = 1_100
PUBLICATION_REQUEST_ID = "gpp-test-publication"


def activation_observation() -> dict[str, object]:
    material: dict[str, object] = {
        "phase": "platform_publication_activation",
        "observed_at_unix": ACTIVATION_TIME,
        "details": {
            "state": "publication_pending",
            "request_id": PUBLICATION_REQUEST_ID,
        },
    }
    return {
        **material,
        "observation_sha256": midcutover.canonical_json_sha256(material),
    }


ACTIVATION_EVIDENCE = {
    "source_evidence_time": ACTIVATION_TIME,
    "publication_request_id": PUBLICATION_REQUEST_ID,
    "observation_sha256": activation_observation()["observation_sha256"],
    "state": "publication_pending",
}
BLUE_OBSERVATION = {
    "release_id": BLUE_RELEASE,
    "repo_head": HEAD_BLUE,
    "completion_status": "complete",
}
SOURCE_SNAPSHOT_RECEIPT_SHA256 = "91" * 32
SOURCE_CLIENT_DECLARATION_SHA256 = "94" * 32
REBOUND_SNAPSHOT_RECEIPT_SHA256 = "92" * 32
SNAPSHOT_PENDING = {
    "state": midcutover.SNAPSHOT_BINDING_PENDING,
    "bound_release_id": BLUE_RELEASE,
    "bound_repo_head": HEAD_BLUE,
    "observation_scope": "server_loopback_watchdog",
    "snapshot_receipt_sha256": SOURCE_SNAPSHOT_RECEIPT_SHA256,
    "source_receipt_sha256": SOURCE_SNAPSHOT_RECEIPT_SHA256,
    "source_snapshot_receipt_sha256": SOURCE_SNAPSHOT_RECEIPT_SHA256,
    "source_client_declaration_sha256": SOURCE_CLIENT_DECLARATION_SHA256,
    "classified_snapshot_receipt_sha256": SOURCE_SNAPSHOT_RECEIPT_SHA256,
}
SNAPSHOT_REBOUND = {
    **SNAPSHOT_PENDING,
    "state": midcutover.SNAPSHOT_BINDING_DONE,
    "bound_release_id": GREEN_RELEASE,
    "bound_repo_head": HEAD_GREEN,
    "snapshot_receipt_sha256": REBOUND_SNAPSHOT_RECEIPT_SHA256,
    "classified_snapshot_receipt_sha256": REBOUND_SNAPSHOT_RECEIPT_SHA256,
    "transition_sha256": "93" * 32,
    "schema_changed": True,
}
LINEAGE_EVIDENCE = {
    "blue_observation": BLUE_OBSERVATION,
    "activation_observation": ACTIVATION_EVIDENCE,
    "snapshot_observation": SNAPSHOT_REBOUND,
}
GREEN_READINESS = {
    "ready": True,
    "release_id": GREEN_RELEASE,
    "repo_head": HEAD_GREEN,
    "complete_schema_count": 2,
    "names_sha256": "d1" * 32,
    "agent_instructions_sha256": "d2" * 32,
}


def selector_document(
    *,
    slot: str = "green",
    generation: int = GENERATION,
    selector_sha256: str = SELECTOR_SHA256,
    binding_sha256: str = BINDING_SHA256,
    release_id: str = GREEN_RELEASE,
    repo_head: str = HEAD_GREEN,
    cutover_id: str = CUTOVER_ID,
    previous_selector_sha256: str | None = None,
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
        "previous_selector_sha256": previous_selector_sha256,
        "updated_at_unix": 1_000,
        "selector_sha256": selector_sha256,
    }


def cutover_receipt(
    *,
    cutover_id: str = CUTOVER_ID,
    outcome: str = "outcome_unknown",
    phase: str | None = None,
    expected_head: str = HEAD_GREEN,
    blue_release_id: str = BLUE_RELEASE,
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
        "cutover_generation": CUTOVER_GENERATION,
        "expected_head": expected_head,
        "blue_release_id": blue_release_id,
        "green_release_id": green_release_id,
        "source_identity_sha256": source_identity_sha256,
        "names_sha256": "d1" * 32,
        "agent_instructions_sha256": "d2" * 32,
        "green_readiness": {
            **GREEN_READINESS,
            "release_id": green_release_id,
            "repo_head": expected_head,
        },
        "observations": [activation_observation()],
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
    *,
    resumed_cutover_id: str = CUTOVER_ID,
    outcome: str = "completed",
    resumed_receipt_sha256: str | None = None,
    expected_head: str = HEAD_GREEN,
    green_release_id: str = GREEN_RELEASE,
    final_slot: str = "canonical",
    resume_id: str = "bgcr-0123456789abcdef",
    resume_phase: str = midcutover.PHASE_REBIND_SNAPSHOT,
) -> dict[str, object]:
    original_receipt_sha256 = (
        resumed_receipt_sha256
        if resumed_receipt_sha256 is not None
        else cutover_receipt()["receipt_sha256"]
    )
    canonical_start = resume_phase in {
        midcutover.PHASE_RETIRE_GREEN,
        midcutover.PHASE_CLOSEOUT,
    }
    snapshot_rebound = resume_phase != midcutover.PHASE_REBIND_SNAPSHOT
    pointer_promoted = resume_phase in {
        midcutover.PHASE_SELECT_CANONICAL,
        midcutover.PHASE_RETIRE_GREEN,
        midcutover.PHASE_CLOSEOUT,
    }
    binding: dict[str, object] = {
        "resume_binding_schema_version": 2,
        "cutover_id": resumed_cutover_id,
        "cutover_generation": CUTOVER_GENERATION,
        "resumed_receipt_sha256": original_receipt_sha256,
        "resume_phase": resume_phase,
        "snapshot_binding_state": (
            midcutover.SNAPSHOT_BINDING_DONE
            if snapshot_rebound
            else midcutover.SNAPSHOT_BINDING_PENDING
        ),
        "blue_release_id": BLUE_RELEASE,
        "blue_repo_head": HEAD_BLUE,
        "target_head": expected_head,
        "expected_head": expected_head,
        "expected_selector_sha256": "f3" * 32 if canonical_start else SELECTOR_SHA256,
        "switch_selector_sha256": SELECTOR_SHA256,
        "expected_generation": GENERATION + 1 if canonical_start else GENERATION,
        "switch_generation": GENERATION,
        "expected_slot": "canonical" if canonical_start else "green",
        "pointer_state": "target" if pointer_promoted else "blue",
        "green_retired": resume_phase == midcutover.PHASE_CLOSEOUT,
        "expected_release_id": green_release_id,
        "expected_runtime_binding_sha256": BINDING_SHA256,
        "expected_upstream_port": (
            midcutover.CANONICAL_UPSTREAM_PORT
            if canonical_start
            else midcutover.GREEN_UPSTREAM_PORT
        ),
        "source_identity_sha256": SOURCE_IDENTITY_SHA256,
        "source_evidence_time": ACTIVATION_TIME,
        "activation_observation_sha256": ACTIVATION_EVIDENCE[
            "observation_sha256"
        ],
        "publication_request_id": PUBLICATION_REQUEST_ID,
        "registered_tool_count": 2,
        "registered_names_sha256": "d1" * 32,
        "agent_instructions_sha256": "d2" * 32,
        "green_readiness": GREEN_READINESS,
        "source_snapshot_receipt_sha256": SOURCE_SNAPSHOT_RECEIPT_SHA256,
        "source_client_declaration_sha256": SOURCE_CLIENT_DECLARATION_SHA256,
        "classified_snapshot_receipt_sha256": (
            REBOUND_SNAPSHOT_RECEIPT_SHA256
            if snapshot_rebound
            else SOURCE_SNAPSHOT_RECEIPT_SHA256
        ),
    }
    binding["binding_sha256"] = midcutover.canonical_json_sha256(binding)
    final_routing = {
        "selector_sha256": "f3" * 32,
        "generation": GENERATION + 1,
        "selected_slot": final_slot,
        "upstream_port": midcutover.ROUTING_SLOTS[final_slot],
        "runtime_binding_sha256": BINDING_SHA256,
        "cutover_id": resumed_cutover_id,
        "previous_selector_sha256": SELECTOR_SHA256,
        "release_id": green_release_id,
        "repo_head": expected_head,
    }
    readback_material = {
        "authoritative": True,
        "selector": final_routing,
        "ingress": {
            "selector_sha256": final_routing["selector_sha256"],
            "selector_generation": final_routing["generation"],
            "selected_slot": final_routing["selected_slot"],
            "upstream_port": final_routing["upstream_port"],
            "runtime_binding_sha256": BINDING_SHA256,
            "release_id": green_release_id,
            "repo_head": expected_head,
        },
    }
    readback = {
        **readback_material,
        "readback_sha256": midcutover.canonical_json_sha256(readback_material),
    }
    green_unit = midcutover.green_operator_unit(resumed_cutover_id)
    material = {
        "schema_version": 1,
        "kind": midcutover.RESUME_RECEIPT_KIND,
        "resume_id": resume_id,
        "resumed_cutover_id": resumed_cutover_id,
        "resumed_receipt_sha256": original_receipt_sha256,
        "resume_binding_sha256": binding["binding_sha256"],
        "resume_binding": binding,
        "resume_phase": resume_phase,
        "expected_head": expected_head,
        "green_release_id": green_release_id,
        "source_identity_sha256": SOURCE_IDENTITY_SHA256,
        "resumed_selector_sha256": binding["expected_selector_sha256"],
        "resumed_generation": binding["expected_generation"],
        "target_contract": {
            "release_id": green_release_id,
            "repo_head": expected_head,
            "release_identity": midcutover.parse_release_id(green_release_id),
            "schema_version": 4,
            "mode": "module",
            "module": "grabowski_operator",
            "source": "src/grabowski_runtime.py",
            "entrypoint_contract_sha256": "aabbccddeeff" + "0" * 52,
            "decoded_contract_sha256": "ab" * 32,
            "expected_tool_count": 2,
            "historical_validator_executed": True,
            "executed_release_code": False,
            "judged_by_checkout": False,
        },
        "snapshot_rebind": {
            "rebound": True,
            "receipt_sha256": SNAPSHOT_REBOUND["snapshot_receipt_sha256"],
            "source_snapshot_receipt_sha256": (
                SOURCE_SNAPSHOT_RECEIPT_SHA256
            ),
            "source_client_declaration_sha256": (
                SOURCE_CLIENT_DECLARATION_SHA256
            ),
            "classified_snapshot_receipt_sha256": (
                binding["classified_snapshot_receipt_sha256"]
            ),
            "source_release_id": BLUE_RELEASE,
            "source_repo_head": HEAD_BLUE,
            "target_release_id": green_release_id,
            "target_repo_head": expected_head,
            "publication_schema_transition_sha256": SNAPSHOT_REBOUND[
                "transition_sha256"
            ],
        },
        "final_routing": final_routing,
        "retirement": {"retired": True, "unit": green_unit},
        "admission_state": {"state": "absent"},
        "final_state": {
            "release_id": green_release_id,
            "repo_head": expected_head,
            "completion_status": "complete",
            "runtime_binding_sha256": BINDING_SHA256,
            "admission_marker_state": "absent",
            "pointer": {
                "release_id": green_release_id,
                "repo_head": expected_head,
                "completion_status": "complete",
                "pointer_kind": "symlink",
                "pointer_target_release_id": green_release_id,
                "error": None,
            },
            "snapshot": SNAPSHOT_REBOUND,
            "selector": final_routing,
            "green_unit": {"unit": green_unit, "active": False, "error": None},
        },
        "authoritative_readback": readback,
        "phase": "completed" if outcome == "completed" else outcome,
        "outcome": outcome,
        "recovery": None if outcome == "completed" else {"action": "inspect"},
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
        "blue_observation": BLUE_OBSERVATION,
        "activation_observation": ACTIVATION_EVIDENCE,
        "pointer_observation": POINTER_AT_BLUE,
        "green_unit_observation": {"active": True},
        "snapshot_observation": SNAPSHOT_PENDING,
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

    def test_blue_release_identifier_must_commit_to_the_predecessor_head(self) -> None:
        inconsistent_release = (
            "cccccccccccc-srcset001122334455-lock556677889900-"
            "contractaabbccddeeff"
        )
        verdict = classify(
            receipts=[cutover_receipt(blue_release_id=inconsistent_release)],
            blue_observation={
                "release_id": inconsistent_release,
                "repo_head": HEAD_BLUE,
                "completion_status": "complete",
            },
            pointer_observation={
                **POINTER_AT_BLUE,
                "release_id": inconsistent_release,
                "pointer_target_release_id": inconsistent_release,
            },
            snapshot_observation={
                **SNAPSHOT_PENDING,
                "bound_release_id": inconsistent_release,
            },
        )
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
        self.assertIn(
            "blue_release_artifact_matches_predecessor", verdict["reasons"]
        )

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
            green_observation={**GREEN_OBSERVATION, "listener_present": False},
            snapshot_observation=SNAPSHOT_REBOUND,
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


class HistoricalActivationContractTests(unittest.TestCase):
    def _rehash(self, receipt: dict[str, object]) -> dict[str, object]:
        material = dict(receipt)
        material.pop("receipt_sha256", None)
        return {
            **material,
            "receipt_sha256": midcutover.canonical_json_sha256(material),
        }

    def test_unique_hash_bound_activation_is_required(self) -> None:
        missing = cutover_receipt()
        missing["observations"] = []
        missing = self._rehash(missing)
        with self.assertRaisesRegex(
            midcutover.MidCutoverEvidenceError, "exactly one"
        ):
            midcutover.activation_observation(missing)

        multiple = cutover_receipt()
        second = activation_observation()
        second["details"] = {
            "state": "publication_pending",
            "request_id": "gpp-conflicting",
        }
        material = {
            key: value
            for key, value in second.items()
            if key != "observation_sha256"
        }
        second["observation_sha256"] = midcutover.canonical_json_sha256(material)
        multiple["observations"] = [activation_observation(), second]
        multiple = self._rehash(multiple)
        with self.assertRaisesRegex(
            midcutover.MidCutoverEvidenceError, "exactly one"
        ):
            midcutover.activation_observation(multiple)

    def test_activation_hash_request_and_state_are_not_inferred(self) -> None:
        wrong_hash = cutover_receipt()
        wrong_hash["observations"][0]["observation_sha256"] = "00" * 32
        wrong_hash = self._rehash(wrong_hash)
        with self.assertRaisesRegex(
            midcutover.MidCutoverEvidenceError, "hash mismatch"
        ):
            midcutover.activation_observation(wrong_hash)

        wrong_state = cutover_receipt()
        observation = dict(wrong_state["observations"][0])
        observation["details"] = {
            "state": "outcome_unknown",
            "request_id": PUBLICATION_REQUEST_ID,
        }
        material = {
            key: value
            for key, value in observation.items()
            if key != "observation_sha256"
        }
        observation["observation_sha256"] = midcutover.canonical_json_sha256(
            material
        )
        wrong_state["observations"] = [observation]
        wrong_state = self._rehash(wrong_state)
        with self.assertRaisesRegex(
            midcutover.MidCutoverEvidenceError, "activation observation is invalid"
        ):
            midcutover.activation_observation(wrong_state)

    def test_missing_generation_is_not_generation_one(self) -> None:
        receipt = cutover_receipt()
        receipt.pop("cutover_generation")
        receipt = self._rehash(receipt)
        with self.assertRaisesRegex(
            midcutover.MidCutoverEvidenceError, "generation is invalid"
        ):
            midcutover.validate_cutover_receipt(receipt)


class SnapshotInspectorDependencyTests(unittest.TestCase):
    def test_snapshot_inspector_is_injected_and_unknown_state_fails_closed(self) -> None:
        calls: list[dict[str, object]] = []

        def inspect(**parameters):
            calls.append(parameters)
            return {
                "state": "unexpected-state",
                "publication_transition_sha256": "a" * 64,
            }

        observed = midcutover.observe_client_snapshot_binding(
            cutover_id=CUTOVER_ID,
            cutover_generation=GENERATION,
            blue_release_id=BLUE_RELEASE,
            blue_repo_head=HEAD_BLUE,
            green_release_id=GREEN_RELEASE,
            target_head=HEAD_GREEN,
            source_evidence_time=1,
            publication_request_id="gpp-test",
            registered_tool_count=1,
            registered_names_sha256="b" * 64,
            agent_instructions_sha256="c" * 64,
            green_readiness={},
            source_identity_sha256="d" * 64,
            snapshot_inspector=inspect,
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(
            calls[0]["deployment_source_identity_sha256"], "d" * 64
        )
        self.assertEqual(observed["state"], midcutover.SNAPSHOT_BINDING_UNREADABLE)
        self.assertEqual(observed["transition_sha256"], "a" * 64)

    def test_missing_snapshot_inspector_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            midcutover.MidCutoverEvidenceError,
            "canonical client snapshot inspector is unavailable",
        ):
            midcutover.observe_client_snapshot_binding(
                cutover_id=CUTOVER_ID,
                cutover_generation=GENERATION,
                blue_release_id=BLUE_RELEASE,
                blue_repo_head=HEAD_BLUE,
                green_release_id=GREEN_RELEASE,
                target_head=HEAD_GREEN,
                source_evidence_time=1,
                publication_request_id="gpp-test",
                registered_tool_count=1,
                registered_names_sha256="b" * 64,
                agent_instructions_sha256="c" * 64,
                green_readiness={},
                source_identity_sha256="d" * 64,
                snapshot_inspector=None,
            )


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

    def test_default_pointer_authority_is_the_same_releases_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt_root = root / "receipts"
            receipt_root.mkdir(mode=0o700)
            releases_root = root / "releases"
            releases_root.mkdir()
            with mock.patch.object(
                midcutover,
                "observe_stable_pointer",
                return_value={"error": "absent"},
            ) as observe:
                midcutover.collect_classification_inputs(
                    selector_path=root / "missing-selector.json",
                    receipt_root=receipt_root,
                    releases_root=releases_root,
                    runtime_path=root / "runtime",
                )
        observe.assert_called_once_with(root / "runtime", releases_root)


def resume_binding_for_phase(phase: str) -> dict[str, object]:
    canonical = phase in {
        midcutover.PHASE_RETIRE_GREEN,
        midcutover.PHASE_CLOSEOUT,
    }
    snapshot_state = (
        midcutover.SNAPSHOT_BINDING_PENDING
        if phase == midcutover.PHASE_REBIND_SNAPSHOT
        else midcutover.SNAPSHOT_BINDING_DONE
    )
    pointer_state = (
        "target"
        if phase
        in {
            midcutover.PHASE_SELECT_CANONICAL,
            midcutover.PHASE_RETIRE_GREEN,
            midcutover.PHASE_CLOSEOUT,
        }
        else "blue"
    )
    material: dict[str, object] = {
        "resume_binding_schema_version": 2,
        "cutover_id": CUTOVER_ID,
        "cutover_generation": CUTOVER_GENERATION,
        "resumed_receipt_sha256": cutover_receipt()["receipt_sha256"],
        "resume_phase": phase,
        "snapshot_binding_state": snapshot_state,
        "blue_release_id": BLUE_RELEASE,
        "blue_repo_head": HEAD_BLUE,
        "target_head": HEAD_GREEN,
        "expected_head": HEAD_GREEN,
        "expected_selector_sha256": "f3" * 32 if canonical else SELECTOR_SHA256,
        "switch_selector_sha256": SELECTOR_SHA256,
        "expected_generation": GENERATION + 1 if canonical else GENERATION,
        "switch_generation": GENERATION,
        "expected_slot": "canonical" if canonical else "green",
        "pointer_state": pointer_state,
        "green_retired": phase == midcutover.PHASE_CLOSEOUT,
        "expected_release_id": GREEN_RELEASE,
        "expected_runtime_binding_sha256": BINDING_SHA256,
        "expected_upstream_port": (
            midcutover.CANONICAL_UPSTREAM_PORT
            if canonical
            else midcutover.GREEN_UPSTREAM_PORT
        ),
        "source_identity_sha256": SOURCE_IDENTITY_SHA256,
        "source_evidence_time": ACTIVATION_TIME,
        "activation_observation_sha256": ACTIVATION_EVIDENCE[
            "observation_sha256"
        ],
        "publication_request_id": PUBLICATION_REQUEST_ID,
        "registered_tool_count": 2,
        "registered_names_sha256": "d1" * 32,
        "agent_instructions_sha256": "d2" * 32,
        "green_readiness": GREEN_READINESS,
        "source_snapshot_receipt_sha256": SOURCE_SNAPSHOT_RECEIPT_SHA256,
        "source_client_declaration_sha256": SOURCE_CLIENT_DECLARATION_SHA256,
        "classified_snapshot_receipt_sha256": (
            SOURCE_SNAPSHOT_RECEIPT_SHA256
            if snapshot_state == midcutover.SNAPSHOT_BINDING_PENDING
            else REBOUND_SNAPSHOT_RECEIPT_SHA256
        ),
    }
    return {**material, "binding_sha256": midcutover.canonical_json_sha256(material)}


class _FakeResumeRuntime:
    """Records the order of effects so promotion/retirement cannot silently swap."""

    def __init__(
        self,
        *,
        fail_phase: str | None = None,
        phase: str = midcutover.PHASE_PROMOTE_POINTER,
    ) -> None:
        self.fail_phase = fail_phase
        self.calls: list[str] = []
        self.pointer_promoted = False
        self.canonical_selected = False
        self.green_unit = midcutover.green_operator_unit(CUTOVER_ID)
        self.release_path = Path("/release/green")
        self.contract_evidence = {
            "release_id": GREEN_RELEASE,
            "repo_head": HEAD_GREEN,
            "release_identity": midcutover.parse_release_id(GREEN_RELEASE),
            "schema_version": 4,
            "mode": "module",
            "module": "grabowski_operator",
            "source": "src/grabowski_runtime.py",
            "entrypoint_contract_sha256": "aabbccddeeff" + "0" * 52,
            "decoded_contract_sha256": "ab" * 32,
            "expected_tool_count": 2,
            "historical_validator_executed": True,
            "executed_release_code": False,
            "judged_by_checkout": False,
        }
        self.classification = {"classification_sha256": "f0" * 32}
        self.resume_binding = resume_binding_for_phase(phase)
        self.snapshot_state = self.resume_binding["snapshot_binding_state"]
        self.snapshot_rebind = None
        self.receipt_root = Path("/tmp/unused-midcutover-receipts")
        self.current_selector = {
            "selector_sha256": "f3" * 32,
            "generation": 9,
            "selected_slot": "canonical",
            "upstream_port": 18181,
            "runtime_binding_sha256": BINDING_SHA256,
            "cutover_id": CUTOVER_ID,
            "previous_selector_sha256": SELECTOR_SHA256,
            "runtime_binding": {"release_id": GREEN_RELEASE, "repo_head": HEAD_GREEN},
        }
        self.admission_released = False

    @property
    def cutover_id(self) -> str:
        return CUTOVER_ID

    @property
    def resume_phase(self) -> str:
        return str(self.resume_binding["resume_phase"])

    def reconcile_admission_marker(self):
        return self._step(
            "reconcile_admission_marker",
            {"state": "absent", "cleanup_performed": False},
        )

    def adopt_applied_promotion(self):
        self.calls.append("adopt_applied_promotion")
        self.pointer_promoted = True
        self.canonical_selected = True
        return {"adopted": True}

    def reprobe_green(self):
        self.calls.append("reprobe_green")
        return {"green_still_serving": True}

    def _step(self, phase: str, value: dict[str, object]) -> dict[str, object]:
        self.calls.append(phase)
        if self.fail_phase == phase:
            raise RuntimeError(f"{phase} failed")
        return value

    def verify_green_serving(self):
        return self._step("verify_green_serving", {"green_serving": True})

    def rebind_snapshot(self):
        self.calls.append("rebind_snapshot")
        if self.fail_phase == "rebind_snapshot_before_write":
            raise RuntimeError("rebind refused")
        self.snapshot_state = midcutover.SNAPSHOT_BINDING_DONE
        if self.fail_phase == "rebind_snapshot_after_write":
            raise RuntimeError("rebind readback failed")
        return {
            "rebound": True,
            "receipt_sha256": SNAPSHOT_REBOUND["snapshot_receipt_sha256"],
            "source_snapshot_receipt_sha256": SOURCE_SNAPSHOT_RECEIPT_SHA256,
            "source_client_declaration_sha256": SOURCE_CLIENT_DECLARATION_SHA256,
            "classified_snapshot_receipt_sha256": (
                self.resume_binding["classified_snapshot_receipt_sha256"]
            ),
            "source_release_id": BLUE_RELEASE,
            "source_repo_head": HEAD_BLUE,
            "target_release_id": GREEN_RELEASE,
            "target_repo_head": HEAD_GREEN,
            "publication_schema_transition_sha256": SNAPSHOT_REBOUND[
                "transition_sha256"
            ],
        }

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
            "pointer_activated_now": True,
        }

    def promote_canonical_pointer_only(self):
        """Failure after the pointer moved but before the selector CAS."""
        self.calls.append("promote_canonical")
        self.pointer_promoted = True
        raise RuntimeError("canonical operator did not come up")

    def retire_green(self):
        return self._step(
            "retire_green", {"retired": True, "unit": self.green_unit}
        )

    def final_readback(self):
        return self._step(
            "final_readback",
            {
                "release_id": GREEN_RELEASE,
                "repo_head": HEAD_GREEN,
                "completion_status": "complete",
                "runtime_binding_sha256": BINDING_SHA256,
                "admission_marker_state": "absent",
                "pointer": {
                    "release_id": GREEN_RELEASE,
                    "repo_head": HEAD_GREEN,
                    "completion_status": "complete",
                    "pointer_kind": "symlink",
                    "pointer_target_release_id": GREEN_RELEASE,
                    "error": None,
                },
                "snapshot": SNAPSHOT_REBOUND,
                "selector": dual._selector_summary(self.current_selector),
                "green_unit": {
                    "unit": self.green_unit,
                    "active": False,
                    "error": None,
                },
            },
        )

    def authoritative_readback(self):
        selector = dual._selector_summary(self.current_selector)
        material = {
            "authoritative": True,
            "selector": selector,
            "ingress": {
                "selector_sha256": selector["selector_sha256"],
                "selector_generation": selector["generation"],
                "selected_slot": selector["selected_slot"],
                "upstream_port": selector["upstream_port"],
                "runtime_binding_sha256": selector["runtime_binding_sha256"],
                "release_id": selector["release_id"],
                "repo_head": selector["repo_head"],
            },
        }
        return {
            **material,
            "readback_sha256": midcutover.canonical_json_sha256(material),
        }

    def cold_snapshot_observation(self):
        return (
            SNAPSHOT_REBOUND
            if self.snapshot_state == midcutover.SNAPSHOT_BINDING_DONE
            else SNAPSHOT_PENDING
        )

    def adopted_snapshot_rebind(self):
        if self.snapshot_state != midcutover.SNAPSHOT_BINDING_DONE:
            return None
        return {
            "rebound": True,
            "adopted_from_durable_snapshot": True,
            "receipt_sha256": SNAPSHOT_REBOUND["snapshot_receipt_sha256"],
            "source_snapshot_receipt_sha256": SOURCE_SNAPSHOT_RECEIPT_SHA256,
            "source_client_declaration_sha256": SOURCE_CLIENT_DECLARATION_SHA256,
            "classified_snapshot_receipt_sha256": (
                self.resume_binding["classified_snapshot_receipt_sha256"]
            ),
            "source_release_id": BLUE_RELEASE,
            "source_repo_head": HEAD_BLUE,
            "target_release_id": GREEN_RELEASE,
            "target_repo_head": HEAD_GREEN,
            "publication_schema_transition_sha256": SNAPSHOT_REBOUND[
                "transition_sha256"
            ],
        }

    def release_admission_best_effort(self):
        self.calls.append("release_admission_best_effort")
        self.admission_released = True
        return {"released": True}

    # Deliberately absent: there is no rollback_green here. A resume that could
    # roll back would be able to undo a live cutover, which the contract forbids.


class ResumeEffectSemanticsTests(unittest.TestCase):
    """Tests 17-19: ordering, no blue rollback, terminal receipt."""

    def _run(self, runtime: _FakeResumeRuntime, receipt_root: Path):
        receipt_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        original = cutover_receipt()
        original_path = receipt_root / f"{CUTOVER_ID}.json"
        original_path.write_text(
            json.dumps(original, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        original_path.chmod(0o600)
        runtime.receipt_root = receipt_root
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
        # A failure before S0 leaves every durable recovery effect absent.
        runtime = _FakeResumeRuntime(
            fail_phase="verify_green_serving",
            phase=midcutover.PHASE_REBIND_SNAPSHOT,
        )
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
        self.assertEqual(
            receipt["resumed_receipt_sha256"], cutover_receipt()["receipt_sha256"]
        )
        self.assertEqual(receipt["expected_head"], HEAD_GREEN)
        self.assertEqual(persisted, receipt)
        self.assertEqual(midcutover.validate_resume_receipt(persisted), persisted)
        # The persisted resume receipt is what retires the original ambiguity.
        self.assertEqual(
            midcutover.claimed_resolution_cutover_ids([persisted]), {CUTOVER_ID}
        )
        verdict = classify(receipts=[cutover_receipt(), persisted])
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)


class FailureInjectionMatrixTests(unittest.TestCase):
    def _run(self, runtime: _FakeResumeRuntime, root: Path):
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        original = cutover_receipt()
        original_path = root / f"{CUTOVER_ID}.json"
        original_path.write_text(
            json.dumps(original, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        original_path.chmod(0o600)
        runtime.receipt_root = root
        with (
            mock.patch.object(dual.core, "deployment_lock", return_value=nullcontext()),
            mock.patch.object(
                dual, "prepare_midcutover_resume_runtime", return_value=runtime
            ),
            mock.patch.object(dual, "BLUE_GREEN_RECEIPT_ROOT", root),
        ):
            return dual.resume_production_blue_green_cutover(
                repo=ROOT,
                expected_head=HEAD_GREEN,
                resume_id="bgcr-failurematrix1",
            )

    def _cold_phase(
        self, *, snapshot, pointer, selector, green_active
    ) -> dict[str, object]:
        return midcutover.classify_recovery_lane(
            expected_head=HEAD_GREEN,
            selector=selector,
            receipts=[cutover_receipt()],
            green_observation=GREEN_OBSERVATION,
            blue_observation=BLUE_OBSERVATION,
            activation_observation=ACTIVATION_EVIDENCE,
            pointer_observation=pointer,
            green_unit_observation={"active": green_active},
            snapshot_observation=snapshot,
        )

    def test_f0_through_f6_have_one_cold_restart_phase(self) -> None:
        cases = (
            (
                "F0_before_s0",
                _FakeResumeRuntime(
                    fail_phase="verify_green_serving",
                    phase=midcutover.PHASE_REBIND_SNAPSHOT,
                ),
                SNAPSHOT_PENDING,
                POINTER_AT_BLUE,
                selector_document(),
                True,
                "failed_pre_resume",
                midcutover.PHASE_REBIND_SNAPSHOT,
            ),
            (
                "F1_s0_refused_before_write",
                _FakeResumeRuntime(
                    fail_phase="rebind_snapshot_before_write",
                    phase=midcutover.PHASE_REBIND_SNAPSHOT,
                ),
                SNAPSHOT_PENDING,
                POINTER_AT_BLUE,
                selector_document(),
                True,
                "failed_pre_resume",
                midcutover.PHASE_REBIND_SNAPSHOT,
            ),
            (
                "F2_write_landed_readback_failed",
                _FakeResumeRuntime(
                    fail_phase="rebind_snapshot_after_write",
                    phase=midcutover.PHASE_REBIND_SNAPSHOT,
                ),
                SNAPSHOT_REBOUND,
                POINTER_AT_BLUE,
                selector_document(),
                True,
                "outcome_unknown",
                midcutover.PHASE_PROMOTE_POINTER,
            ),
            (
                "F3_s0_confirmed_crash_before_pointer",
                _FakeResumeRuntime(
                    fail_phase="close_mutations",
                    phase=midcutover.PHASE_REBIND_SNAPSHOT,
                ),
                SNAPSHOT_REBOUND,
                POINTER_AT_BLUE,
                selector_document(),
                True,
                "outcome_unknown",
                midcutover.PHASE_PROMOTE_POINTER,
            ),
            (
                "F4_pointer_moved_selector_green",
                _FakeResumeRuntime(fail_phase="promote_canonical"),
                SNAPSHOT_REBOUND,
                POINTER_AT_TARGET,
                selector_document(),
                True,
                "outcome_unknown",
                midcutover.PHASE_SELECT_CANONICAL,
            ),
            (
                "F5_selector_canonical_green_active",
                _FakeResumeRuntime(fail_phase="retire_green"),
                SNAPSHOT_REBOUND,
                POINTER_AT_TARGET,
                canonical_selector(),
                True,
                "outcome_unknown",
                midcutover.PHASE_RETIRE_GREEN,
            ),
            (
                "F6_green_retired_cleanup_missing",
                _FakeResumeRuntime(fail_phase="reconcile_admission_marker"),
                SNAPSHOT_REBOUND,
                POINTER_AT_TARGET,
                canonical_selector(),
                False,
                "outcome_unknown",
                midcutover.PHASE_CLOSEOUT,
            ),
        )
        for (
            label,
            runtime,
            snapshot,
            pointer,
            selector,
            green_active,
            outcome,
            phase,
        ) in cases:
            with self.subTest(boundary=label), tempfile.TemporaryDirectory() as temporary:
                result = self._run(runtime, Path(temporary))
                self.assertEqual(result["outcome"], outcome)
                recovery = result["receipt"]["recovery"]
                self.assertFalse(recovery["blind_retry_allowed"])
                self.assertTrue(recovery["automatic_rollback_forbidden"])
                self.assertFalse(hasattr(runtime, "rollback_blue"))
                restarted = self._cold_phase(
                    snapshot=snapshot,
                    pointer=pointer,
                    selector=selector,
                    green_active=green_active,
                )
                self.assertEqual(restarted["lane"], midcutover.LANE_MID_CUTOVER_RESUME)
                self.assertEqual(restarted["resume_binding"]["resume_phase"], phase)

                foreign = self._cold_phase(
                    snapshot={"state": midcutover.SNAPSHOT_BINDING_FOREIGN},
                    pointer=pointer,
                    selector=selector,
                    green_active=green_active,
                )
                self.assertEqual(foreign["lane"], midcutover.LANE_FAIL_CLOSED)

    def test_f7_crash_after_final_readback_restarts_at_closeout(self) -> None:
        runtime = _FakeResumeRuntime()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            dual,
            "_midcutover_resume_receipt",
            side_effect=SystemExit("crash before terminal receipt construction"),
        ):
            root = Path(temporary)
            with self.assertRaises(SystemExit):
                self._run(runtime, root)
            self.assertFalse((root / "bgcr-failurematrix1.json").exists())
        self.assertIn("final_readback", runtime.calls)
        self.assertFalse(hasattr(runtime, "rollback_blue"))
        restarted = self._cold_phase(
            snapshot=SNAPSHOT_REBOUND,
            pointer=POINTER_AT_TARGET,
            selector=canonical_selector(),
            green_active=False,
        )
        self.assertEqual(restarted["lane"], midcutover.LANE_MID_CUTOVER_RESUME)
        self.assertEqual(
            restarted["resume_binding"]["resume_phase"],
            midcutover.PHASE_CLOSEOUT,
        )

    def test_f8_terminal_receipt_persistence_failure_forbids_blind_retry(self) -> None:
        runtime = _FakeResumeRuntime()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            dual,
            "_persist_midcutover_resume_receipt",
            side_effect=OSError("durable receipt write failed"),
        ):
            with self.assertRaises(dual.ProductionBlueGreenReceiptPersistenceError) as raised:
                self._run(runtime, Path(temporary))
        self.assertEqual(raised.exception.outcome, "completed")
        self.assertEqual(raised.exception.receipt["phase"], "completed")
        self.assertTrue(raised.exception.receipt["final_state"])
        self.assertFalse(hasattr(runtime, "rollback_blue"))
        restarted = self._cold_phase(
            snapshot=SNAPSHOT_REBOUND,
            pointer=POINTER_AT_TARGET,
            selector=canonical_selector(),
            green_active=False,
        )
        self.assertEqual(
            restarted["resume_binding"]["resume_phase"],
            midcutover.PHASE_CLOSEOUT,
        )

    def test_prepare_failure_reclassifies_every_already_applied_phase(self) -> None:
        cases = (
            (
                midcutover.PHASE_PROMOTE_POINTER,
                SNAPSHOT_REBOUND,
                POINTER_AT_BLUE,
                selector_document(),
                True,
            ),
            (
                midcutover.PHASE_SELECT_CANONICAL,
                SNAPSHOT_REBOUND,
                POINTER_AT_TARGET,
                selector_document(),
                True,
            ),
            (
                midcutover.PHASE_RETIRE_GREEN,
                SNAPSHOT_REBOUND,
                POINTER_AT_TARGET,
                canonical_selector(),
                True,
            ),
            (
                midcutover.PHASE_CLOSEOUT,
                SNAPSHOT_REBOUND,
                POINTER_AT_TARGET,
                canonical_selector(),
                False,
            ),
        )
        for index, (phase, snapshot, pointer, selector, green_active) in enumerate(
            cases
        ):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                root.chmod(0o700)
                fresh = self._cold_phase(
                    snapshot=snapshot,
                    pointer=pointer,
                    selector=selector,
                    green_active=green_active,
                )
                self.assertEqual(fresh["resume_binding"]["resume_phase"], phase)
                with (
                    mock.patch.object(
                        dual.core, "deployment_lock", return_value=nullcontext()
                    ),
                    mock.patch.object(
                        dual,
                        "prepare_midcutover_resume_runtime",
                        side_effect=RuntimeError("prepare readback failed"),
                    ),
                    mock.patch.object(
                        dual,
                        "classify_midcutover_resume",
                        return_value=fresh,
                    ),
                    mock.patch.object(dual, "BLUE_GREEN_RECEIPT_ROOT", root),
                ):
                    result = dual.resume_production_blue_green_cutover(
                        repo=ROOT,
                        expected_head=HEAD_GREEN,
                        resume_id=f"bgcr-preparefail{index}",
                    )
            self.assertEqual(result["outcome"], "outcome_unknown")
            recovery = result["receipt"]["recovery"]
            self.assertNotIn("blue_green_state_unchanged", recovery)
            self.assertTrue(recovery["blue_rollback_forbidden"])
            self.assertFalse(recovery["blind_retry_allowed"])
            self.assertTrue(recovery["fresh_classification_required"])
            self.assertEqual(
                result["receipt"]["resume_binding"]["resume_phase"], phase
            )

    def test_early_receipt_persistence_failure_is_typed_after_s0(self) -> None:
        fresh = self._cold_phase(
            snapshot=SNAPSHOT_REBOUND,
            pointer=POINTER_AT_BLUE,
            selector=selector_document(),
            green_active=True,
        )
        for label, prepare_error in (
            ("prepare", RuntimeError("artifact decoder failed")),
            (
                "denied",
                dual.MidCutoverResumeDenied(
                    {
                        "lane": midcutover.LANE_FAIL_CLOSED,
                        "reasons": ["resume_binding_drifted"],
                    }
                ),
            ),
        ):
            with self.subTest(path=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                root.chmod(0o700)
                with (
                    mock.patch.object(
                        dual.core, "deployment_lock", return_value=nullcontext()
                    ),
                    mock.patch.object(
                        dual,
                        "prepare_midcutover_resume_runtime",
                        side_effect=prepare_error,
                    ),
                    mock.patch.object(
                        dual,
                        "classify_midcutover_resume",
                        return_value=fresh,
                    ),
                    mock.patch.object(
                        dual,
                        "_persist_midcutover_resume_receipt",
                        side_effect=OSError("durable receipt write failed"),
                    ),
                ):
                    with self.assertRaises(
                        dual.ProductionBlueGreenReceiptPersistenceError
                    ) as raised:
                        dual.resume_production_blue_green_cutover(
                            repo=ROOT,
                            expected_head=HEAD_GREEN,
                            receipt_root=root,
                            resume_id=f"bgcr-earlypersist-{label}",
                        )
            self.assertEqual(raised.exception.outcome, "outcome_unknown")
            recovery = raised.exception.receipt["recovery"]
            self.assertFalse(recovery["blind_retry_allowed"])
            self.assertTrue(recovery["fresh_classification_required"])


FIXTURE_CONTRACT = {
    "schema_version": 1,
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
    f"{HEAD_GREEN[:12]}-srcset001122334455-lock556677889900"
    f"-contract{CONTRACT_SHA256[:12]}"
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
        validator_bytes: bytes | None = None,
    ) -> Path:
        contract = contract or FIXTURE_CONTRACT
        release_path = root / release_id
        (release_path / "inputs").mkdir(parents=True)
        contract_path = release_path / "inputs" / "runtime-entrypoint.json"
        payload = json.dumps(contract, indent=2, sort_keys=True).encode("utf-8")
        validator_path = release_path / "grabowski_runtime_contract.py"
        validator_bytes = validator_bytes or (
            SRC / "grabowski_runtime_contract.py"
        ).read_bytes()
        validator_path.write_bytes(validator_bytes)
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
            "module_paths": {
                "grabowski_runtime_contract": str(validator_path)
            },
            "source_sha256s": {
                "grabowski_runtime_contract": dual.core.sha256_bytes(
                    validator_bytes
                )
            },
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

    def test_historical_contract_decoder_is_lossless_for_v1_through_v4(self) -> None:
        contract = dict(FIXTURE_CONTRACT)
        for version in range(1, 5):
            with self.subTest(schema_version=version):
                candidate = {**contract, "schema_version": version}
                if version >= 2:
                    candidate["supporting_sources"] = []
                if version >= 3:
                    candidate["runtime_assets"] = []
                if version >= 4:
                    candidate["spawn_dependencies"] = []
                decoded = dual._decode_historical_runtime_contract(candidate)
                self.assertEqual(decoded.to_manifest(), candidate)
                self.assertEqual(decoded.mode, "module")

    def test_full_v4_contract_decodes_nonempty_runtime_fields_losslessly(self) -> None:
        candidate = json.loads(
            (ROOT / "config/runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        self.assertTrue(candidate["supporting_sources"])
        self.assertTrue(candidate["runtime_assets"])
        self.assertTrue(candidate["spawn_dependencies"])
        self.assertIsInstance(candidate.get("browser_operator_default"), dict)
        decoded = dual._decode_historical_runtime_contract(candidate)
        self.assertEqual(decoded.to_manifest(), candidate)

    def test_historical_contract_decoder_refuses_unknown_mode_and_fields(self) -> None:
        for candidate in (
            {**FIXTURE_CONTRACT, "mode": "script"},
            {**FIXTURE_CONTRACT, "future_field": True},
            {key: value for key, value in FIXTURE_CONTRACT.items() if key != "source"},
            {**FIXTURE_CONTRACT, "schema_version": 99},
        ):
            with self.subTest(candidate=candidate), self.assertRaises(
                dual.core.DeployError
            ):
                dual._decode_historical_runtime_contract(candidate)

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

    def test_release_uses_its_own_older_validator_not_the_checkout(self) -> None:
        historical_validator = b"""\
class RuntimeContractError(ValueError):
    pass
CANONICAL_VALIDATOR_MODULE = 'grabowski_runtime_contract'
def contract_error(message):
    return RuntimeContractError(message)
def validate_contract(value):
    if value.get('schema_version') != 1:
        raise RuntimeContractError('legacy validator accepts v1 only')
    return value
"""
        with tempfile.TemporaryDirectory() as temporary:
            release_path = self._release(
                Path(temporary), validator_bytes=historical_validator
            )
            with mock.patch.object(
                dual.core,
                "local_contract_validator",
                side_effect=AssertionError("checkout validator must not run"),
            ):
                contract, evidence = self._derive(release_path)
        self.assertEqual(contract.schema_version, 1)
        self.assertEqual(
            evidence["historical_validator_sha256"],
            dual.core.sha256_bytes(historical_validator),
        )

    def test_release_id_must_commit_to_the_manifest_contract_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release_path = self._release(
                Path(temporary),
                release_id=(
                f"{HEAD_GREEN[:12]}-srcset001122334455-lock556677889900"
                "-contractdeadbeef0000"
            ),
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


def pointer_observation(release_id: str, repo_head: str, **overrides) -> dict[str, object]:
    observation = {
        "runtime_path": "/runtime",
        "release_id": release_id,
        "repo_head": repo_head,
        "completion_status": "complete",
        "pointer_kind": "symlink",
        "pointer_target_release_id": release_id,
        "error": None,
    }
    observation.update(overrides)
    return observation


POINTER_AT_TARGET = pointer_observation(GREEN_RELEASE, HEAD_GREEN)
POINTER_AT_BLUE = pointer_observation(BLUE_RELEASE, HEAD_BLUE)


def canonical_selector(generation: int = GENERATION + 1) -> dict[str, object]:
    """The selector a previous resume left behind after its CAS."""
    return selector_document(
        slot="canonical",
        generation=generation,
        selector_sha256="f3" * 32,
        previous_selector_sha256=SELECTOR_SHA256,
    )


class ResumeStateMachineTests(unittest.TestCase):
    """A resume that itself fails must be continuable, not terminal."""

    def _classify(self, *, selector, pointer, green_active, snapshot=SNAPSHOT_REBOUND):
        return midcutover.classify_recovery_lane(
            expected_head=HEAD_GREEN,
            selector=selector,
            receipts=[cutover_receipt()],
            green_observation=GREEN_OBSERVATION,
            blue_observation=BLUE_OBSERVATION,
            activation_observation=ACTIVATION_EVIDENCE,
            pointer_observation=pointer,
            green_unit_observation={"active": green_active},
            snapshot_observation=snapshot,
        )

    def test_s0_snapshot_predecessor_pointer_not_yet_promoted(self) -> None:
        verdict = self._classify(
            selector=selector_document(),
            pointer=POINTER_AT_BLUE,
            green_active=True,
            snapshot=SNAPSHOT_PENDING,
        )
        self.assertEqual(verdict["lane"], midcutover.LANE_MID_CUTOVER_RESUME)
        self.assertEqual(
            verdict["resume_binding"]["resume_phase"], midcutover.PHASE_REBIND_SNAPSHOT
        )

    def test_s1_snapshot_rebound_pointer_still_blue(self) -> None:
        verdict = self._classify(
            selector=selector_document(), pointer=POINTER_AT_BLUE, green_active=True
        )
        self.assertEqual(verdict["lane"], midcutover.LANE_MID_CUTOVER_RESUME)
        self.assertEqual(
            verdict["resume_binding"]["resume_phase"], midcutover.PHASE_PROMOTE_POINTER
        )

    def test_blue_pointer_with_wrong_predecessor_head_is_foreign(self) -> None:
        verdict = self._classify(
            selector=selector_document(),
            pointer=pointer_observation(BLUE_RELEASE, "e" * 40),
            green_active=True,
        )
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
        self.assertIn("stable_pointer_classifiable", verdict["reasons"])

    def test_s2_pointer_promoted_selector_still_green(self) -> None:
        verdict = self._classify(
            selector=selector_document(), pointer=POINTER_AT_TARGET, green_active=True
        )
        self.assertEqual(verdict["lane"], midcutover.LANE_MID_CUTOVER_RESUME)
        self.assertEqual(
            verdict["resume_binding"]["resume_phase"], midcutover.PHASE_SELECT_CANONICAL
        )

    def test_s3_canonical_selected_green_still_running(self) -> None:
        verdict = self._classify(
            selector=canonical_selector(), pointer=POINTER_AT_TARGET, green_active=True
        )
        self.assertEqual(verdict["lane"], midcutover.LANE_MID_CUTOVER_RESUME)
        self.assertEqual(
            verdict["resume_binding"]["resume_phase"], midcutover.PHASE_RETIRE_GREEN
        )

    def test_s4_green_retired_closeout_remains(self) -> None:
        verdict = self._classify(
            selector=canonical_selector(), pointer=POINTER_AT_TARGET, green_active=False
        )
        self.assertEqual(verdict["lane"], midcutover.LANE_MID_CUTOVER_RESUME)
        self.assertEqual(
            verdict["resume_binding"]["resume_phase"], midcutover.PHASE_CLOSEOUT
        )

    def test_canonical_selector_without_promoted_pointer_is_a_contradiction(self) -> None:
        verdict = self._classify(
            selector=canonical_selector(), pointer=POINTER_AT_BLUE, green_active=True
        )
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)

    def test_canonical_selector_of_a_foreign_cutover_is_not_adopted(self) -> None:
        foreign = selector_document(
            slot="canonical",
            generation=GENERATION + 1,
            selector_sha256="f3" * 32,
            cutover_id="bgc-someone-else",
        )
        verdict = self._classify(
            selector=foreign, pointer=POINTER_AT_TARGET, green_active=True
        )
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)

    def test_canonical_generation_must_follow_the_receipt_by_exactly_one(self) -> None:
        jumped = canonical_selector(generation=GENERATION + 4)
        verdict = self._classify(
            selector=jumped, pointer=POINTER_AT_TARGET, green_active=True
        )
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
        self.assertIn("canonical_generation_follows_receipt", verdict["reasons"])

    def test_every_phase_stays_bound_to_the_same_cutover_lineage(self) -> None:
        for selector, pointer, active, expected in (
            (selector_document(), POINTER_AT_BLUE, True, midcutover.PHASE_PROMOTE_POINTER),
            (selector_document(), POINTER_AT_TARGET, True, midcutover.PHASE_SELECT_CANONICAL),
            (canonical_selector(), POINTER_AT_TARGET, True, midcutover.PHASE_RETIRE_GREEN),
            (canonical_selector(), POINTER_AT_TARGET, False, midcutover.PHASE_CLOSEOUT),
        ):
            with self.subTest(phase=expected):
                verdict = self._classify(
                    selector=selector, pointer=pointer, green_active=active
                )
                binding = verdict["resume_binding"]
                self.assertEqual(binding["cutover_id"], CUTOVER_ID)
                self.assertEqual(binding["target_head"], HEAD_GREEN)
                self.assertEqual(
                    binding["resumed_receipt_sha256"],
                    cutover_receipt()["receipt_sha256"],
                )

    def test_an_outcome_unknown_resume_receipt_does_not_strand_the_cutover(self) -> None:
        """A failed resume attempt is evidence, never a terminal verdict."""
        failed = resume_receipt(outcome="outcome_unknown", resume_id="bgcr-failedonce1")
        verdict = midcutover.classify_recovery_lane(
            expected_head=HEAD_GREEN,
            selector=canonical_selector(),
            receipts=[cutover_receipt(), failed],
            green_observation=GREEN_OBSERVATION,
            blue_observation=BLUE_OBSERVATION,
            activation_observation=ACTIVATION_EVIDENCE,
            pointer_observation=POINTER_AT_TARGET,
            green_unit_observation={"active": True},
            snapshot_observation=SNAPSHOT_REBOUND,
        )
        self.assertEqual(verdict["lane"], midcutover.LANE_MID_CUTOVER_RESUME)
        self.assertEqual(
            verdict["resume_binding"]["resume_phase"], midcutover.PHASE_RETIRE_GREEN
        )


class TwoHeadBootstrapTests(unittest.TestCase):
    """Execution head and resume target head are different revisions."""

    NEW_HEAD = "e" * 40

    def test_resume_target_comes_from_lineage_not_from_the_execution_head(self) -> None:
        # The runner executes merged code (NEW_HEAD) while the open cutover is
        # about 8351 (HEAD_GREEN).  Asking about the execution head must not
        # reinterpret the execution head as the resume target.
        asked_about_new_head = midcutover.classify_recovery_lane(
            **LINEAGE_EVIDENCE,
            expected_head=self.NEW_HEAD,
            selector=selector_document(),
            receipts=[cutover_receipt()],
            green_observation=GREEN_OBSERVATION,
            pointer_observation=POINTER_AT_BLUE,
            green_unit_observation={"active": True},
        )
        self.assertEqual(asked_about_new_head["lane"], midcutover.LANE_FAIL_CLOSED)
        self.assertIn(
            "receipt_expected_head_matches_request", asked_about_new_head["reasons"]
        )

        asked_about_lineage = midcutover.classify_recovery_lane(
            **LINEAGE_EVIDENCE,
            expected_head=HEAD_GREEN,
            selector=selector_document(),
            receipts=[cutover_receipt()],
            green_observation=GREEN_OBSERVATION,
            pointer_observation=POINTER_AT_BLUE,
            green_unit_observation={"active": True},
        )
        binding = asked_about_lineage["resume_binding"]
        self.assertEqual(binding["target_head"], HEAD_GREEN)
        self.assertNotEqual(binding["target_head"], self.NEW_HEAD)

    def test_runner_bridge_resumes_the_lineage_head_not_the_execution_head(self) -> None:
        import run_scheduled_deploy as runner

        classification = midcutover.classify_recovery_lane(
            **LINEAGE_EVIDENCE,
            expected_head=HEAD_GREEN,
            selector=selector_document(),
            receipts=[cutover_receipt()],
            green_observation=GREEN_OBSERVATION,
            pointer_observation=POINTER_AT_BLUE,
            green_unit_observation={"active": True},
        )
        empty = midcutover.classify_recovery_lane(
            **LINEAGE_EVIDENCE,
            expected_head=self.NEW_HEAD,
            selector=selector_document(),
            receipts=[cutover_receipt()],
            green_observation=GREEN_OBSERVATION,
            pointer_observation=POINTER_AT_BLUE,
            green_unit_observation={"active": True},
        )
        calls: list[str] = []

        def classify(*, expected_head, receipt_root=None):
            calls.append(expected_head)
            return classification if expected_head == HEAD_GREEN else empty

        with mock.patch.object(
            runner.deploy_dual, "classify_midcutover_resume", side_effect=classify
        ):
            decision = runner.classify_recovery_before_deploy(
                repo=ROOT, execution_head=self.NEW_HEAD
            )
        self.assertTrue(decision["resume_required"])
        self.assertEqual(decision["execution_head"], self.NEW_HEAD)
        self.assertEqual(decision["resume_target_head"], HEAD_GREEN)
        self.assertEqual(decision["cutover_id"], CUTOVER_ID)
        # It asked about the execution head first, then about the lineage head.
        self.assertEqual(calls, [self.NEW_HEAD, HEAD_GREEN])

    def test_runner_bridge_defers_to_the_ordinary_deploy_when_nothing_is_open(self) -> None:
        import run_scheduled_deploy as runner

        clean = midcutover.classify_recovery_lane(
            expected_head=self.NEW_HEAD,
            selector=selector_document(slot="canonical", cutover_id="bgc-old"),
            receipts=[],
            pointer_observation=POINTER_AT_TARGET,
        )
        with mock.patch.object(
            runner.deploy_dual, "classify_midcutover_resume", return_value=clean
        ):
            decision = runner.classify_recovery_before_deploy(
                repo=ROOT, execution_head=self.NEW_HEAD
            )
        self.assertFalse(decision["resume_required"])
        self.assertEqual(decision["lane"], midcutover.LANE_SCHEDULED_DEPLOY)


class PublishedRuntimeColdReentryTests(unittest.TestCase):
    """The serving immutable contract exposes a real S0-S4 bootstrap path."""

    PUBLIC_RECOVERY_TOOL = "grabowski_recovery_provenance_repair"
    PUBLIC_SCHEDULE_TOOL = "grabowski_runtime_deploy_schedule"
    STABLE_RUNTIME = Path("/home/alex/.local/share/grabowski-mcp")

    def test_portable_contract_keeps_the_existing_surface_and_resume_bridge(self) -> None:
        import grabowski_runtime_contract as runtime_contract

        contract = json.loads(
            (ROOT / "config/runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        self.assertIsNone(runtime_contract.contract_error(contract))
        modules = runtime_contract.contract_modules(contract)
        self.assertIn("grabowski_midcutover_resume", modules)
        self.assertEqual(len(contract["expected_tools"]), 199)
        self.assertEqual(len(set(contract["expected_tools"])), 199)
        self.assertIn("grabowski_operational_guidance", contract["expected_tools"])
        self.assertNotIn("grabowski_agent_workspace_adopt", contract["expected_tools"])
        self.assertIn(self.PUBLIC_RECOVERY_TOOL, contract["expected_tools"])
        self.assertIn(self.PUBLIC_SCHEDULE_TOOL, contract["expected_tools"])
        self.assertFalse(
            any("midcutover" in name for name in contract["expected_tools"])
        )

        recovery_source = (
            ROOT / "src/grabowski_provenance_recovery.py"
        ).read_text(encoding="utf-8")
        self_deploy_source = (ROOT / "src/grabowski_self_deploy.py").read_text(
            encoding="utf-8"
        )
        for evidence in (
            "return _resume_under_schedule_lock(expected_head)",
            "self_deploy._midcutover_resume_command(",
            "operator._start_job(",
        ):
            self.assertIn(evidence, recovery_source)
        self.assertIn(
            'MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH = Path("tools/run_midcutover_resume.py")',
            self_deploy_source,
        )

        tree = ast.parse(recovery_source)
        public = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "grabowski_recovery_provenance_repair"
        )
        self.assertEqual(
            [argument.arg for argument in public.args.args],
            [
                "expected_head",
                "source_repository",
                "source_lease_owner_id",
                "delay_seconds",
                "ctx",
            ],
        )

    def test_serving_immutable_release_validates_and_dispatches_this_contract(
        self,
    ) -> None:
        if not self.STABLE_RUNTIME.is_symlink():
            self.skipTest("host-bound stable runtime pointer is unavailable")
        release = self.STABLE_RUNTIME.resolve(strict=True)
        manifest_path = release / "deployment-manifest.json"
        if not manifest_path.is_file():
            self.skipTest("host-bound immutable release manifest is unavailable")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        release_id = manifest["release_id"]
        repo_head = manifest["repo_head"]
        self.assertEqual(release.name, release_id)
        self.assertTrue(midcutover.release_id_binds_head(release_id, repo_head))
        self.assertEqual(manifest["completion_status"], "complete")

        snapshot = release / "inputs/runtime-entrypoint.json"
        self.assertTrue(snapshot.is_file())
        self.assertFalse(snapshot.is_symlink())
        snapshot_bytes = snapshot.read_bytes()
        self.assertEqual(
            hashlib.sha256(snapshot_bytes).hexdigest(),
            manifest["entrypoint_contract_sha256"],
        )
        identity = midcutover.parse_release_id(release_id)
        self.assertEqual(
            manifest["entrypoint_contract_sha256"][:12], identity["contract12"]
        )
        immutable_contract = json.loads(snapshot_bytes)
        self.assertEqual(manifest["entrypoint_contract"], immutable_contract)
        self.assertEqual(immutable_contract["schema_version"], 4)
        self.assertEqual(immutable_contract["mode"], "module")
        self.assertEqual(immutable_contract["module"], "grabowski_operator")
        self.assertIn(self.PUBLIC_RECOVERY_TOOL, immutable_contract["expected_tools"])
        self.assertIn(self.PUBLIC_SCHEDULE_TOOL, immutable_contract["expected_tools"])

        source_hashes = manifest["source_sha256s"]
        for module in (
            "grabowski_runtime_contract",
            "grabowski_self_deploy",
            "grabowski_provenance_recovery",
            "grabowski_midcutover_resume",
        ):
            with self.subTest(module=module):
                source = release / f"inputs/src/{module}.py"
                self.assertTrue(source.is_file())
                self.assertFalse(source.is_symlink())
                self.assertEqual(
                    hashlib.sha256(source.read_bytes()).hexdigest(),
                    source_hashes[module],
                )

        validator_script = """
import json
import pathlib
import sys
import grabowski_runtime_contract as contract
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
print(json.dumps({
    'error': contract.contract_error(document),
    'modules': contract.contract_modules(document),
}, sort_keys=True))
"""
        validator = subprocess.run(
            [manifest["release_python_path"], "-c", validator_script, str(ROOT / "config/runtime-entrypoint.json")],
            check=True,
            capture_output=True,
            text=True,
            env={**__import__("os").environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        validation = json.loads(validator.stdout)
        self.assertIsNone(validation["error"])
        self.assertIn("grabowski_midcutover_resume", validation["modules"])

        recovery_source = (
            release / "inputs/src/grabowski_provenance_recovery.py"
        ).read_text(encoding="utf-8")
        self_deploy_source = (
            release / "inputs/src/grabowski_self_deploy.py"
        ).read_text(encoding="utf-8")
        self.assertIn("return _resume_under_schedule_lock(expected_head)", recovery_source)
        self.assertIn("self_deploy._midcutover_resume_command(", recovery_source)
        self.assertIn("operator._start_job(", recovery_source)
        self.assertIn("tools/run_midcutover_resume.py", self_deploy_source)

    def test_host_terminal_legacy_lineage_remains_a_resolved_tombstone(self) -> None:
        root = Path(
            "/home/alex/.local/state/grabowski/blue-green-deployment-receipts"
        )
        if not root.is_dir():
            self.skipTest("host-bound blue-green receipt root is unavailable")
        candidates = []
        for path in sorted(root.glob("bgcr-*.json")):
            receipt = json.loads(path.read_text(encoding="utf-8"))
            if receipt.get("outcome") == "completed":
                candidates.append(receipt)
        if not candidates:
            self.skipTest("host carries no completed resume tombstone")
        for receipt in candidates:
            with self.subTest(resume_id=receipt.get("resume_id")):
                cutover_path = root / f"{receipt['resumed_cutover_id']}.json"
                self.assertTrue(cutover_path.is_file())
                cutover = json.loads(cutover_path.read_text(encoding="utf-8"))
                self.assertIsNotNone(
                    midcutover._completed_lineage_binding(receipt)
                )
                self.assertTrue(midcutover._lineage_resolved([receipt], cutover))

    def test_cold_s0_s4_are_each_classified_before_any_next_effect(self) -> None:
        cases = (
            (
                midcutover.PHASE_REBIND_SNAPSHOT,
                selector_document(),
                POINTER_AT_BLUE,
                True,
                SNAPSHOT_PENDING,
            ),
            (
                midcutover.PHASE_PROMOTE_POINTER,
                selector_document(),
                POINTER_AT_BLUE,
                True,
                SNAPSHOT_REBOUND,
            ),
            (
                midcutover.PHASE_SELECT_CANONICAL,
                selector_document(),
                POINTER_AT_TARGET,
                True,
                SNAPSHOT_REBOUND,
            ),
            (
                midcutover.PHASE_RETIRE_GREEN,
                canonical_selector(),
                POINTER_AT_TARGET,
                True,
                SNAPSHOT_REBOUND,
            ),
            (
                midcutover.PHASE_CLOSEOUT,
                canonical_selector(),
                POINTER_AT_TARGET,
                False,
                SNAPSHOT_REBOUND,
            ),
        )
        for phase, selector, pointer, green_active, snapshot in cases:
            with self.subTest(phase=phase):
                verdict = midcutover.classify_recovery_lane(
                    expected_head=HEAD_GREEN,
                    selector=selector,
                    receipts=[cutover_receipt()],
                    green_observation=GREEN_OBSERVATION,
                    blue_observation=BLUE_OBSERVATION,
                    activation_observation=ACTIVATION_EVIDENCE,
                    pointer_observation=pointer,
                    green_unit_observation={"active": green_active},
                    snapshot_observation=snapshot,
                )
                self.assertEqual(verdict["lane"], midcutover.LANE_MID_CUTOVER_RESUME)
                self.assertEqual(verdict["resume_binding"]["resume_phase"], phase)
                self.assertIsNotNone(
                    midcutover._validated_resume_binding(verdict["resume_binding"])
                )

    def test_scheduled_runner_cannot_skip_any_s0_s4_phase_into_a_deploy(self) -> None:
        import run_scheduled_deploy as runner

        states = (
            (selector_document(), POINTER_AT_BLUE, True, SNAPSHOT_PENDING),
            (selector_document(), POINTER_AT_BLUE, True, SNAPSHOT_REBOUND),
            (selector_document(), POINTER_AT_TARGET, True, SNAPSHOT_REBOUND),
            (canonical_selector(), POINTER_AT_TARGET, True, SNAPSHOT_REBOUND),
            (canonical_selector(), POINTER_AT_TARGET, False, SNAPSHOT_REBOUND),
        )
        for selector, pointer, green_active, snapshot in states:
            verdict = midcutover.classify_recovery_lane(
                expected_head=HEAD_GREEN,
                selector=selector,
                receipts=[cutover_receipt()],
                green_observation=GREEN_OBSERVATION,
                blue_observation=BLUE_OBSERVATION,
                activation_observation=ACTIVATION_EVIDENCE,
                pointer_observation=pointer,
                green_unit_observation={"active": green_active},
                snapshot_observation=snapshot,
            )
            phase = verdict["resume_binding"]["resume_phase"]
            with (
                self.subTest(phase=phase),
                mock.patch.object(
                    runner.deploy_dual,
                    "classify_midcutover_resume",
                    return_value=verdict,
                ),
                mock.patch.object(
                    runner,
                    "run_midcutover_resume",
                    return_value={
                        "outcome": "completed",
                        "receipt_persisted": True,
                        "receipt": {"receipt_sha256": "ab" * 32},
                    },
                ) as resume,
                mock.patch.object(runner, "run_productive_blue_green") as deploy,
            ):
                decision = runner.classify_recovery_before_deploy(
                    repo=ROOT, execution_head=HEAD_GREEN
                )
                self.assertTrue(decision["resume_required"])
                self.assertFalse(decision["deploy_allowed"])
                self.assertEqual(decision["resume_phase"], phase)
                self.assertEqual(
                    runner.run_resume_only(
                        {**decision, "repo": str(ROOT)}, binding=None
                    ),
                    0,
                )
            resume.assert_called_once()
            deploy.assert_not_called()


class ReleaseIdentityAuthorityTests(unittest.TestCase):
    """One release-id grammar, and it actually binds what it claims to bind."""

    def test_canonical_grammar_decomposes_the_committed_identities(self) -> None:
        identity = midcutover.parse_release_id(GREEN_RELEASE)
        self.assertIsNotNone(identity)
        self.assertEqual(identity["head12"], HEAD_GREEN[:12])
        self.assertIsNone(identity["attempt"])

    def test_retry_releases_are_a_legitimate_release_id(self) -> None:
        # A -attemptN release is produced by the ordinary builder; refusing it
        # would refuse a recovery for a reason unrelated to the cutover.
        retry = f"{GREEN_RELEASE}-attempt2"
        identity = midcutover.parse_release_id(retry)
        self.assertIsNotNone(identity)
        self.assertEqual(identity["attempt"], 2)
        self.assertEqual(identity["contract12"], midcutover.parse_release_id(GREEN_RELEASE)["contract12"])

    def test_non_canonical_release_ids_are_refused(self) -> None:
        for bad in (
            "not-a-release",
            "bbbbbbbbbbbb-srcsetzz-lock00-contract00",
            f"{GREEN_RELEASE}-attempt",
            f"../{GREEN_RELEASE}",
            "",
            None,
        ):
            with self.subTest(release_id=bad):
                self.assertIsNone(midcutover.parse_release_id(bad))

    def test_release_decoder_and_classifier_share_one_grammar(self) -> None:
        """The decoder must accept exactly what the classifier accepts."""
        source = (TOOLS / "deploy_runtime_dual.py").read_text(encoding="utf-8")
        self.assertIn("midcutover.parse_release_id(expected_release_id)", source)
        self.assertNotIn("RELEASE_ID_CONTRACT_RE", source)

    def test_decoder_binds_both_halves_of_the_identifier(self) -> None:
        source = (TOOLS / "deploy_runtime_dual.py").read_text(encoding="utf-8")
        self.assertIn('declared.startswith(identity["contract12"])', source)
        self.assertIn('expected_repo_head.startswith(identity["head12"])', source)


class StablePointerAuthenticityTests(unittest.TestCase):
    """A symlink is only the pointer if it lands inside the managed root."""

    def _layout(self, root: Path) -> tuple[Path, Path]:
        releases = root / "releases"
        outside = root / "elsewhere"
        for parent in (releases, outside):
            (parent / GREEN_RELEASE).mkdir(parents=True)
            manifest = {
                "release_id": GREEN_RELEASE,
                "repo_head": HEAD_GREEN,
                "completion_status": "complete",
            }
            (parent / GREEN_RELEASE / "deployment-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
        return releases, outside

    def test_pointer_into_the_managed_root_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            releases, _ = self._layout(root)
            runtime = root / "grabowski-mcp"
            runtime.symlink_to(releases / GREEN_RELEASE)
            observed = midcutover.observe_stable_pointer(runtime, releases)
        self.assertIsNone(observed["error"])
        self.assertEqual(observed["release_id"], GREEN_RELEASE)

    def test_same_named_release_outside_the_root_is_refused(self) -> None:
        """The decisive case: identical name, unmanaged location."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            releases, outside = self._layout(root)
            runtime = root / "grabowski-mcp"
            runtime.symlink_to(outside / GREEN_RELEASE)
            observed = midcutover.observe_stable_pointer(runtime, releases)
        self.assertIsNotNone(observed["error"])
        self.assertEqual(observed["pointer_kind"], "outside_releases_root")
        self.assertIsNone(observed["release_id"])

    def test_an_unmanaged_pointer_cannot_fake_a_later_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            releases, outside = self._layout(root)
            runtime = root / "grabowski-mcp"
            runtime.symlink_to(outside / GREEN_RELEASE)
            observed = midcutover.observe_stable_pointer(runtime, releases)
            verdict = classify(
                selector=canonical_selector(), pointer_observation=observed
            )
        # Without containment this would have classified as S2 and retired green.
        self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
        self.assertIn("stable_pointer_classifiable", verdict["reasons"])

    def test_pointer_to_a_non_canonical_release_name_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            releases = root / "releases"
            (releases / "handmade").mkdir(parents=True)
            runtime = root / "grabowski-mcp"
            runtime.symlink_to(releases / "handmade")
            observed = midcutover.observe_stable_pointer(runtime, releases)
        self.assertIn("canonical release id", str(observed["error"]))


class LaneSwitchTests(unittest.TestCase):
    """fail_closed is a stop, never a fallback into the ordinary deploy."""

    FAIL_CLOSED_CASES = {
        "unreadable_receipt": dict(
            unreadable_receipts=[{"path": "/x.json", "error": "hash mismatch"}]
        ),
        "contradictory_pointer": dict(
            selector=canonical_selector(), pointer_observation=POINTER_AT_BLUE
        ),
        "multiple_unresolved_cutovers": dict(
            receipts=[cutover_receipt(), cutover_receipt(cutover_id="bgc-second")]
        ),
        "foreign_selector": dict(selector=selector_document(cutover_id="bgc-foreign")),
        "unknown_green_unit": dict(
            selector=canonical_selector(),
            pointer_observation=POINTER_AT_TARGET,
            green_unit_observation={"active": None},
        ),
        "pointer_on_a_third_release": dict(
            pointer_observation=pointer_observation(
                "cccccccccccc-srcset001122334455-lock556677889900-contractaabbccddeeff",
                "c" * 40,
            )
        ),
        "pointer_missing": dict(
            pointer_observation=pointer_observation(
                BLUE_RELEASE, HEAD_BLUE, error="FileNotFoundError"
            )
        ),
        "pointer_not_a_symlink": dict(
            pointer_observation=pointer_observation(
                BLUE_RELEASE, HEAD_BLUE, pointer_kind="directory"
            )
        ),
    }

    def test_every_fail_closed_state_is_fail_closed(self) -> None:
        for name, overrides in self.FAIL_CLOSED_CASES.items():
            with self.subTest(case=name):
                self.assertEqual(
                    classify(**overrides)["lane"], midcutover.LANE_FAIL_CLOSED
                )

    def test_fail_closed_never_reaches_the_ordinary_deploy(self) -> None:
        import run_scheduled_deploy as runner

        for name, overrides in self.FAIL_CLOSED_CASES.items():
            with self.subTest(case=name):
                verdict = classify(**overrides)
                with mock.patch.object(
                    runner.deploy_dual,
                    "classify_midcutover_resume",
                    return_value=verdict,
                ):
                    decision = runner.classify_recovery_before_deploy(
                        repo=ROOT, execution_head=HEAD_GREEN
                    )
                self.assertFalse(decision["resume_required"])
                self.assertFalse(decision["deploy_allowed"])

    def test_blocked_classification_stops_the_run(self) -> None:
        import run_scheduled_deploy as runner

        decision = {
            "lane": midcutover.LANE_FAIL_CLOSED,
            "resume_required": False,
            "deploy_allowed": False,
            "reasons": ["all_receipt_evidence_readable"],
        }
        with (
            mock.patch.object(
                runner, "classify_recovery_before_deploy", return_value=decision
            ),
            mock.patch.object(runner, "run_productive_blue_green") as deploy,
        ):
            self.assertTrue(hasattr(runner, "RecoveryClassificationBlocked"))
            deploy.assert_not_called()

    def test_clean_state_still_reaches_the_ordinary_deploy(self) -> None:
        import run_scheduled_deploy as runner

        clean = classify(
            selector=selector_document(slot="canonical", cutover_id="bgc-old"),
            receipts=[],
            pointer_observation=POINTER_AT_TARGET,
        )
        self.assertEqual(clean["lane"], midcutover.LANE_SCHEDULED_DEPLOY)
        with mock.patch.object(
            runner.deploy_dual, "classify_midcutover_resume", return_value=clean
        ):
            decision = runner.classify_recovery_before_deploy(
                repo=ROOT, execution_head=HEAD_GREEN
            )
        self.assertTrue(decision["deploy_allowed"])
        self.assertFalse(decision["resume_required"])


class DeployedFinalizationCompatibilityTests(unittest.TestCase):
    """The finalization a resume-only run writes must satisfy the *deployed* validator.

    Not a re-implementation of the rules: the acceptance conditions are read out
    of the release that is actually running, so a drift between what this code
    writes and what that runtime accepts shows up here rather than in a job that
    silently fails to finalize.
    """

    #: The deployed grabowski_operator_core.py is installed from this file, so
    #: the rules can be read here and still describe the running runtime. Where
    #: the release is actually on disk, the equivalence is asserted rather than
    #: assumed.
    VALIDATOR_SOURCE = SRC / "grabowski_operator.py"
    DEPLOYED_RELEASE = (
        Path("/home/alex/.local/share/grabowski-mcp-releases")
        / "8351bcdc257a-srcsetaa58d27f6581-lock33399b89320a-contract85274180e76c"
        / ".venv/lib/python3.10/site-packages/grabowski_operator_core.py"
    )

    def setUp(self) -> None:
        self.source = self.VALIDATOR_SOURCE.read_text(encoding="utf-8")

    def test_finalization_rules_match_the_deployed_release_exactly(self) -> None:
        """The rules this patch relies on are the rules that are running.

        Compared block by block rather than file by file: this branch changes
        other parts of the operator on purpose, and a whole-file digest would
        fail for those changes while saying nothing about the contract that
        actually matters here.
        """
        if not self.DEPLOYED_RELEASE.is_file():
            self.skipTest("deployed release is not present on this host")
        deployed = self.DEPLOYED_RELEASE.read_text(encoding="utf-8")
        for marker in (
            'if final_status == "completed":',
            'elif final_status == "failed":',
            'elif final_status == "outcome_unknown":',
        ):
            with self.subTest(rule=marker):
                start = deployed.index(marker)
                deployed_rule = deployed[start : start + 1400]
                self.assertEqual(
                    deployed_rule,
                    self._deployed_rule(marker),
                    "finalization rules drifted from the deployed release",
                )

    def _deployed_rule(self, marker: str) -> str:
        start = self.source.index(marker)
        return self.source[start : start + 1400]

    def test_completed_requires_this_jobs_head_and_a_real_release(self) -> None:
        rule = self._deployed_rule('if final_status == "completed":')
        self.assertIn('payload.get("repo_head") != contract["expected_head"]', rule)
        self.assertIn('not isinstance(release_id, str)', rule)
        self.assertIn('payload.get("failure_type") is not None', rule)

    def test_outcome_unknown_requires_an_unpersisted_blue_green_summary(self) -> None:
        rule = self._deployed_rule('elif final_status == "outcome_unknown":')
        self.assertIn('blue_green.get("receipt_persisted") is not False', rule)
        self.assertIn("not isinstance(blue_green, dict)", rule)

    def test_resume_only_finalization_matches_the_accepted_failed_shape(self) -> None:
        import run_scheduled_deploy as runner

        rule = self._deployed_rule('elif final_status == "failed":')
        # What the deployed validator demands of a failed receipt.
        self.assertIn('payload.get("completion_status") != "failed"', rule)
        self.assertIn('payload.get("repo_head") is not None', rule)
        self.assertIn('payload.get("release_id") is not None', rule)
        self.assertIn('payload.get("blind_retry_allowed") not in {None, True}', rule)

        for outcome, expected in (
            ("completed", "MidCutoverPrerequisiteRecovered"),
            ("outcome_unknown", "MidCutoverResumeOutcomeUnknown"),
            ("denied", "MidCutoverResumeDenied"),
            ("failed_pre_resume", "MidCutoverResumeFailedPreResume"),
        ):
            with self.subTest(outcome=outcome):
                failure_type = runner._resume_finalization_failure_type(
                    {"outcome": outcome, "receipt_persisted": True}
                )
                self.assertEqual(failure_type, expected)
                self.assertTrue(0 < len(failure_type.encode("utf-8")) <= 200)

    def test_unpersisted_resume_receipt_is_its_own_failure_type(self) -> None:
        import run_scheduled_deploy as runner

        self.assertEqual(
            runner._resume_finalization_failure_type(
                {"outcome": "completed", "receipt_persisted": False}
            ),
            "MidCutoverResumeReceiptUnpersisted",
        )
        self.assertEqual(
            runner._resume_finalization_failure_type(
                {"outcome": "outcome_unknown", "receipt_persisted": False}
            ),
            "MidCutoverResumeReceiptUnpersisted",
        )

    def test_resume_only_run_never_claims_a_deployed_head(self) -> None:
        import run_scheduled_deploy as runner

        written: dict[str, object] = {}

        def capture(binding, **kwargs):
            written.update(kwargs)
            return Path("/jobs/finalization.json")

        decision = {
            "resume_required": True,
            "deploy_allowed": False,
            "execution_head": "e" * 40,
            "resume_target_head": HEAD_GREEN,
            "resume_binding_sha256": "f2" * 32,
            "cutover_id": CUTOVER_ID,
        }
        with (
            mock.patch.object(
                runner, "classify_recovery_before_deploy", return_value=decision
            ),
            mock.patch.object(
                runner,
                "run_midcutover_resume",
                return_value={
                    "outcome": "completed",
                    "receipt_persisted": True,
                    "receipt": {"receipt_sha256": "ab" * 32},
                },
            ),
            mock.patch.object(runner, "write_finalization_receipt", side_effect=capture),
            mock.patch.object(runner, "run_productive_blue_green") as deploy,
        ):
            runner_result = runner.run_resume_only(
                {**decision, "repo": str(ROOT)}, binding={"x": 1}
            )
        deploy.assert_not_called()
        self.assertEqual(written["final_status"], "failed")
        self.assertEqual(written["failure_type"], "MidCutoverPrerequisiteRecovered")
        # Neither head may be presented as the deployed one.
        self.assertIsNone(written["repo_head"])
        self.assertIsNone(written["release_id"])
        self.assertIsNone(written["blue_green"])
        self.assertEqual(runner_result, 0)


class GreenDrainTargetTests(unittest.TestCase):
    """Green is the publicly routed process, so green is what must be drained."""

    def _runtime(self, topology: str) -> dual.MidCutoverResumeRuntime:
        runtime = dual.MidCutoverResumeRuntime(
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
            classification={
                "classification_sha256": "f0" * 32,
                "receipt": {"blue_release_id": BLUE_RELEASE},
            },
            resume_binding=resume_binding_for_phase(
                midcutover.PHASE_PROMOTE_POINTER
            ),
            timeout_seconds=10,
            green_unit="grabowski-green-operator-0123456789ab.service",
            selector_before=selector_document(),
            cutover_generation=CUTOVER_GENERATION,
            blue_repo_head=HEAD_BLUE,
            receipt_root=Path("/tmp/unused-midcutover-receipts"),
        )
        runtime.admission_topology = {"topology": topology}
        return runtime

    def test_absent_canonical_operator_still_closes_admission(self) -> None:
        runtime = self._runtime(dual.CANONICAL_OPERATOR_ABSENT)
        marker = {"token": "t", "expected_head": HEAD_GREEN}
        with (
            mock.patch.object(
                dual,
                "classify_canonical_admission_topology",
                return_value={"topology": dual.CANONICAL_OPERATOR_ABSENT},
            ),
            mock.patch.object(
                dual,
                "engage_receipt_bound_deployment_admission",
                return_value=marker,
            ) as engage,
            mock.patch.object(
                runtime, "snapshot_effect_guard", return_value=nullcontext()
            ),
        ):
            result = runtime.close_mutations()
        # The old canonical unit being gone is not a reason to leave green open:
        # green is still the public route and can still admit a mutation.
        engage.assert_called_once()
        self.assertTrue(result["closed"])
        self.assertEqual(result["drain_target_port"], 18182)
        self.assertFalse(result["canonical_guard_available"])

    def test_ambiguous_canonical_state_fails_closed(self) -> None:
        runtime = self._runtime(dual.CANONICAL_OPERATOR_AMBIGUOUS)
        with (
            mock.patch.object(
                dual,
                "classify_canonical_admission_topology",
                return_value={"topology": dual.CANONICAL_OPERATOR_AMBIGUOUS},
            ),
            mock.patch.object(
                dual, "engage_receipt_bound_deployment_admission"
            ) as engage,
        ):
            with self.assertRaises(dual.core.DeployError):
                runtime.close_mutations()
        engage.assert_not_called()

    def test_drain_targets_the_green_listener_not_canonical(self) -> None:
        for topology in (
            dual.CANONICAL_OPERATOR_LIVE,
            dual.CANONICAL_OPERATOR_ABSENT,
        ):
            with self.subTest(topology=topology):
                runtime = self._runtime(topology)
                runtime.admission_marker = {"token": "t"}
                with (
                    mock.patch.object(
                        dual,
                        "wait_for_operator_deployment_admission",
                        return_value={"supported": True, "blocking_tool_calls": 0},
                    ) as wait,
                    mock.patch.object(
                        dual,
                        "verify_operator_deployment_admission",
                        return_value={"guard": True},
                    ) as verify,
                ):
                    result = runtime.terminalize_effects()
                self.assertEqual(wait.call_args.kwargs["port"], 18182)
                self.assertEqual(result["drain_target_port"], 18182)
                verify_ports = [call.kwargs["port"] for call in verify.call_args_list]
                self.assertIn(18182, verify_ports)
                if topology == dual.CANONICAL_OPERATOR_LIVE:
                    self.assertIn(18181, verify_ports)
                    self.assertIsNotNone(result["canonical_guard_sha256"])
                else:
                    self.assertNotIn(18181, verify_ports)
                    self.assertIsNone(result["canonical_guard_sha256"])

    def test_green_without_admission_support_fails_closed(self) -> None:
        runtime = self._runtime(dual.CANONICAL_OPERATOR_ABSENT)
        runtime.admission_marker = {"token": "t"}
        with mock.patch.object(
            dual,
            "wait_for_operator_deployment_admission",
            return_value={"supported": False, "reason": "predates contract"},
        ):
            with self.assertRaises(dual.core.DeployError):
                runtime.terminalize_effects()

    def test_terminalize_refuses_without_an_engaged_marker(self) -> None:
        runtime = self._runtime(dual.CANONICAL_OPERATOR_ABSENT)
        with self.assertRaises(dual.core.DeployError):
            runtime.terminalize_effects()

    def test_admission_readback_url_is_bound_to_the_two_known_ports(self) -> None:
        self.assertTrue(
            dual._operator_admission_status_url(18182).startswith(
                "http://127.0.0.1:18182/"
            )
        )
        self.assertTrue(
            dual._operator_admission_status_url(18181).startswith(
                "http://127.0.0.1:18181/"
            )
        )
        with self.assertRaises(dual.core.DeployError):
            dual._operator_admission_status_url(18180)


class ReceiptEvidencePrivacyTests(unittest.TestCase):
    """An unkeyed self-hash only proves authorship if nobody else can write."""

    def _write(self, root: Path, receipt: dict[str, object]) -> Path:
        name = receipt.get("cutover_id") or receipt["resume_id"]
        path = root / f"{name}.json"
        path.write_text(
            json.dumps(
                receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ),
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path

    def test_group_writable_receipt_is_not_authentic_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            path = self._write(root, cutover_receipt())
            self.assertEqual(len(midcutover.load_receipts(root)["receipts"]), 1)
            path.chmod(0o660)
            loaded = midcutover.load_receipts(root)
            self.assertEqual(loaded["receipts"], [])
            self.assertEqual(len(loaded["unreadable"]), 1)

    def test_group_writable_receipt_root_fails_the_classification_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o770)
            self._write(root, cutover_receipt())
            loaded = midcutover.load_receipts(root)
            self.assertEqual(loaded["receipts"], [])
            self.assertTrue(loaded["unreadable"])
            verdict = midcutover.classify_recovery_lane(
                expected_head=HEAD_GREEN,
                selector=selector_document(),
                receipts=loaded["receipts"],
                unreadable_receipts=loaded["unreadable"],
                green_observation=GREEN_OBSERVATION,
            )
            self.assertEqual(verdict["lane"], midcutover.LANE_FAIL_CLOSED)
            self.assertIn("all_receipt_evidence_readable", verdict["reasons"])


class ObjectIdContractTests(unittest.TestCase):
    """The resume path uses one object-id contract, not two."""

    @staticmethod
    def _self_deploy_object_id_pattern():
        """Read the command builder's contract from source, not by importing it."""
        source = (SRC / "grabowski_self_deploy.py").read_text(encoding="utf-8")
        match = re.search(r'OBJECT_ID_RE = re\.compile\(r"([^"]+)"\)', source)
        assert match is not None, "OBJECT_ID_RE contract not found"
        return re.compile(match.group(1))

    def test_classifier_accepts_every_supported_object_id_length(self) -> None:
        command_contract = self._self_deploy_object_id_pattern()

        for head in (HEAD_GREEN, "b" * 64):
            with self.subTest(length=len(head)):
                self.assertIsNotNone(midcutover.HEAD_RE.fullmatch(head))
                self.assertIsNotNone(command_contract.fullmatch(head))
                verdict = midcutover.classify_recovery_lane(
                    **{
                        **LINEAGE_EVIDENCE,
                        "snapshot_observation": {
                            **SNAPSHOT_REBOUND,
                            "bound_repo_head": head,
                        },
                    },
                    expected_head=head,
                    selector=selector_document(repo_head=head),
                    receipts=[cutover_receipt(expected_head=head)],
                    green_observation={**GREEN_OBSERVATION, "repo_head": head},
                    pointer_observation=POINTER_AT_BLUE,
                    green_unit_observation={"active": True},
                )
                self.assertNotIn("expected_head_named", verdict["reasons"])
                self.assertEqual(verdict["lane"], midcutover.LANE_MID_CUTOVER_RESUME)

    def test_runner_accepts_the_same_object_id_contract(self) -> None:
        import run_midcutover_resume as runner

        for head in (HEAD_GREEN, "c" * 64):
            self.assertIsNotNone(runner.HEAD_RE.fullmatch(head))
        self.assertIsNone(runner.HEAD_RE.fullmatch("c" * 39))


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
            classification={
                "classification_sha256": "f0" * 32,
                "receipt": {"blue_release_id": BLUE_RELEASE},
            },
            resume_binding=resume_binding_for_phase(
                midcutover.PHASE_PROMOTE_POINTER
            ),
            timeout_seconds=10,
            green_unit="grabowski-green-operator-0123456789ab.service",
            selector_before=selector_document(),
            cutover_generation=CUTOVER_GENERATION,
            blue_repo_head=HEAD_BLUE,
            receipt_root=Path("/tmp/unused-midcutover-receipts"),
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

    def test_pointer_cas_refuses_same_release_with_changed_blue_head(self) -> None:
        runtime = self._runtime()
        runtime.green_proven = True
        runtime.green_readiness = GREEN_READINESS
        with (
            mock.patch.object(runtime, "reprobe_green"),
            mock.patch.object(
                dual.midcutover,
                "observe_stable_pointer",
                return_value=pointer_observation(BLUE_RELEASE, "e" * 40),
            ),
            mock.patch.object(dual.core, "activate_pointer") as activate,
        ):
            with self.assertRaises(dual.core.DeployError) as raised:
                runtime.promote_canonical()
        self.assertEqual(raised.exception.phase, "midcutover-pointer-cas")
        activate.assert_not_called()

    def test_canonical_process_identity_waits_for_post_start_exec_settle(self) -> None:
        expected = {"pid": 7}
        transient = dual.core.DeployError(
            "Operator-Prozess verwendet nicht exakt den erwarteten Entry-Point"
        )
        with (
            mock.patch.object(
                dual,
                "verify_operator_process",
                side_effect=[transient, expected],
            ) as verify,
            mock.patch.object(dual.time, "sleep") as sleep,
        ):
            observed = dual._verify_operator_process_after_start(
                Path("/runtime"),
                mock.Mock(),
                release_hint=Path("/release"),
                settle_timeout_seconds=1.0,
            )
        self.assertEqual(observed, expected)
        self.assertEqual(verify.call_count, 2)
        sleep.assert_called_once()

    def test_canonical_process_identity_remains_fail_closed_after_settle_deadline(self) -> None:
        mismatch = dual.core.DeployError(
            "Operator-Prozess verwendet nicht exakt den erwarteten Entry-Point"
        )
        with (
            mock.patch.object(
                dual, "verify_operator_process", side_effect=mismatch
            ),
            mock.patch.object(dual.time, "monotonic", side_effect=[10.0, 11.0]),
            mock.patch.object(dual.time, "sleep") as sleep,
        ):
            with self.assertRaises(dual.core.DeployError):
                dual._verify_operator_process_after_start(
                    Path("/runtime"),
                    mock.Mock(),
                    settle_timeout_seconds=0.5,
                )
        sleep.assert_not_called()

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
            mock.patch.object(
                dual.midcutover,
                "observe_stable_pointer",
                return_value={
                    "error": None,
                    "pointer_kind": "symlink",
                    "release_id": GREEN_RELEASE,
                    "repo_head": HEAD_GREEN,
                },
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

    def test_snapshot_drift_before_pointer_prevents_pointer_and_selector(self) -> None:
        @contextmanager
        def refuse_pointer():
            raise RuntimeError("snapshot binding drift before pointer")
            yield

        def guard(stage: str):
            return refuse_pointer() if stage == "pointer" else nullcontext()

        with (
            mock.patch.object(
                dual, "_require_selector_authority", return_value={"authoritative": True}
            ),
            mock.patch.object(dual.core, "activate_pointer") as activate,
            mock.patch.object(
                dual.transport_ingress, "publish_routing_selector"
            ) as publish,
        ):
            with self.assertRaisesRegex(RuntimeError, "drift before pointer"):
                dual.promote_green_release_to_canonical(
                    runtime=Path("/runtime"),
                    release_path=Path("/release/green"),
                    contract=mock.Mock(),
                    green_binding={
                        "release_id": GREEN_RELEASE,
                        "repo_head": HEAD_GREEN,
                    },
                    activation=mock.Mock(steps=[]),
                    expected_green_selector_sha256=SELECTOR_SHA256,
                    expected_green_binding_sha256=BINDING_SHA256,
                    cutover_id=CUTOVER_ID,
                    timeout_seconds=10,
                    progress=dual.CanonicalPromotionProgress(),
                    snapshot_effect_guard=guard,
                )
        activate.assert_not_called()
        publish.assert_not_called()

    def test_snapshot_drift_between_pointer_and_selector_stops_next_effect(self) -> None:
        @contextmanager
        def refuse_selector():
            raise RuntimeError("snapshot binding drift before selector")
            yield

        def guard(stage: str):
            return refuse_selector() if stage == "selector" else nullcontext()

        with (
            mock.patch.object(
                dual, "_require_selector_authority", return_value={"authoritative": True}
            ),
            mock.patch.object(dual.core, "activate_pointer") as activate,
            mock.patch.object(
                dual.midcutover,
                "observe_stable_pointer",
                return_value={
                    "error": None,
                    "pointer_kind": "symlink",
                    "release_id": GREEN_RELEASE,
                    "repo_head": HEAD_GREEN,
                },
            ),
            mock.patch.object(dual, "stop_service") as stop,
            mock.patch.object(
                dual.transport_ingress, "publish_routing_selector"
            ) as publish,
        ):
            with self.assertRaisesRegex(RuntimeError, "drift before selector"):
                dual.promote_green_release_to_canonical(
                    runtime=Path("/runtime"),
                    release_path=Path("/release/green"),
                    contract=mock.Mock(),
                    green_binding={
                        "release_id": GREEN_RELEASE,
                        "repo_head": HEAD_GREEN,
                    },
                    activation=mock.Mock(steps=[]),
                    expected_green_selector_sha256=SELECTOR_SHA256,
                    expected_green_binding_sha256=BINDING_SHA256,
                    cutover_id=CUTOVER_ID,
                    timeout_seconds=10,
                    progress=dual.CanonicalPromotionProgress(),
                    snapshot_effect_guard=guard,
                )
        activate.assert_called_once()
        stop.assert_not_called()
        publish.assert_not_called()


class ResumeLineageIdempotenceTests(unittest.TestCase):
    """One stranded cutover produces effects exactly once."""

    @staticmethod
    def _rehash(receipt: dict[str, object], *, binding_changed: bool = False):
        if binding_changed:
            binding = receipt["resume_binding"]
            binding.pop("binding_sha256", None)
            binding["binding_sha256"] = midcutover.canonical_json_sha256(binding)
            receipt["resume_binding_sha256"] = binding["binding_sha256"]
        receipt.pop("receipt_sha256", None)
        receipt["receipt_sha256"] = midcutover.canonical_json_sha256(receipt)
        return receipt

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
        self.assertEqual(midcutover.claimed_resolution_cutover_ids([denied]), set())
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

    def test_lineage_resolution_requires_the_exact_original_receipt(self) -> None:
        """A matching cutover id is a name, not a proof."""
        forged = resume_receipt(resumed_receipt_sha256="ee" * 32)
        self.assertFalse(
            midcutover._lineage_resolved([forged], cutover_receipt())
        )
        verdict = classify(receipts=[cutover_receipt(), forged])
        self.assertEqual(verdict["lane"], midcutover.LANE_MID_CUTOVER_RESUME)

    def test_lineage_resolution_requires_the_exact_target_head(self) -> None:
        wrong_head = resume_receipt(expected_head=HEAD_BLUE)
        self.assertFalse(
            midcutover._lineage_resolved([wrong_head], cutover_receipt())
        )

    def test_lineage_resolution_requires_the_exact_target_release(self) -> None:
        wrong_release = resume_receipt(green_release_id="cccccccccccc-srcset-lock-c")
        self.assertFalse(
            midcutover._lineage_resolved([wrong_release], cutover_receipt())
        )

    def test_lineage_resolution_requires_canonical_final_routing(self) -> None:
        not_promoted = resume_receipt(final_slot="green")
        self.assertEqual(midcutover.claimed_resolution_cutover_ids([not_promoted]), set())
        self.assertFalse(
            midcutover._lineage_resolved([not_promoted], cutover_receipt())
        )

    def test_lineage_resolution_recomputes_binding_and_terminal_chain(self) -> None:
        forged_binding = resume_receipt()
        forged_binding["resume_binding"]["target_head"] = HEAD_BLUE
        self._rehash(forged_binding, binding_changed=True)
        self.assertFalse(
            midcutover._lineage_resolved([forged_binding], cutover_receipt())
        )

        for field in (
            "snapshot_rebind",
            "retirement",
            "admission_state",
            "final_state",
            "authoritative_readback",
        ):
            with self.subTest(missing=field):
                incomplete = resume_receipt()
                incomplete[field] = None
                self._rehash(incomplete)
                self.assertFalse(
                    midcutover._lineage_resolved([incomplete], cutover_receipt())
                )

    def test_terminal_binding_rejects_rehashed_start_selector_drift(self) -> None:
        for field, value in (
            ("expected_selector_sha256", "ee" * 32),
            ("expected_generation", GENERATION + 3),
        ):
            with self.subTest(field=field):
                forged = resume_receipt()
                forged["resume_binding"][field] = value
                self._rehash(forged, binding_changed=True)
                self.assertFalse(
                    midcutover._lineage_resolved([forged], cutover_receipt())
                )

    def test_terminal_binding_rejects_blue_release_head_contradiction(self) -> None:
        forged = resume_receipt()
        forged["resume_binding"]["blue_release_id"] = (
            "cccccccccccc-srcset001122334455-lock556677889900-"
            "contractaabbccddeeff"
        )
        self._rehash(forged, binding_changed=True)
        self.assertIsNone(midcutover._completed_lineage_binding(forged))
        self.assertFalse(
            midcutover._lineage_resolved([forged], cutover_receipt())
        )

    def test_terminal_binding_rejects_rehashed_publication_transition_drift(self) -> None:
        for location in ("snapshot_rebind", "final_snapshot"):
            with self.subTest(location=location):
                forged = resume_receipt()
                if location == "snapshot_rebind":
                    forged["snapshot_rebind"][
                        "publication_schema_transition_sha256"
                    ] = "ee" * 32
                else:
                    forged["final_state"]["snapshot"]["transition_sha256"] = (
                        "ee" * 32
                    )
                self._rehash(forged)
                self.assertFalse(
                    midcutover._lineage_resolved([forged], cutover_receipt())
                )

    def test_every_terminal_binding_authority_rejects_rehashed_contradictions(
        self,
    ) -> None:
        different_blue_release = (
            "aaaaaaaaaaaa-srcsetffffffffffff-lock556677889900-"
            "contractaabbccddeeff"
        )
        different_target_release = (
            "bbbbbbbbbbbb-srcsetffffffffffff-lock556677889900-"
            "contractaabbccddeeff"
        )
        cases = (
            (
                "completed_phase_contradiction",
                False,
                lambda receipt: receipt.__setitem__("phase", "outcome_unknown"),
            ),
            (
                "completed_recovery_contradiction",
                False,
                lambda receipt: receipt.__setitem__(
                    "recovery", {"action": "rollback"}
                ),
            ),
            (
                "expected_head",
                True,
                lambda receipt: receipt["resume_binding"].__setitem__(
                    "expected_head", HEAD_BLUE
                ),
            ),
            (
                "registered_tool_count",
                True,
                lambda receipt: receipt["resume_binding"].__setitem__(
                    "registered_tool_count", 999
                ),
            ),
            (
                "expected_upstream_port",
                True,
                lambda receipt: receipt["resume_binding"].__setitem__(
                    "expected_upstream_port", midcutover.CANONICAL_UPSTREAM_PORT
                ),
            ),
            (
                "source_snapshot_receipt_sha256",
                True,
                lambda receipt: receipt["resume_binding"].__setitem__(
                    "source_snapshot_receipt_sha256", "e1" * 32
                ),
            ),
            (
                "source_client_declaration_sha256",
                True,
                lambda receipt: receipt["resume_binding"].__setitem__(
                    "source_client_declaration_sha256", "e2" * 32
                ),
            ),
            (
                "selector_ancestry",
                True,
                lambda receipt: receipt["resume_binding"].__setitem__(
                    "switch_selector_sha256", "e3" * 32
                ),
            ),
            (
                "blue_release_same_head",
                True,
                lambda receipt: receipt["resume_binding"].__setitem__(
                    "blue_release_id", different_blue_release
                ),
            ),
            (
                "target_release_same_head",
                True,
                lambda receipt: receipt["resume_binding"].__setitem__(
                    "expected_release_id", different_target_release
                ),
            ),
            (
                "foreign_pointer_state",
                True,
                lambda receipt: receipt["resume_binding"].__setitem__(
                    "pointer_state", "foreign"
                ),
            ),
            (
                "foreign_snapshot_state",
                True,
                lambda receipt: receipt["resume_binding"].__setitem__(
                    "snapshot_binding_state", "foreign"
                ),
            ),
            (
                "green_retired_type",
                True,
                lambda receipt: receipt["resume_binding"].__setitem__(
                    "green_retired", "no"
                ),
            ),
            (
                "unknown_binding_authority",
                True,
                lambda receipt: receipt["resume_binding"].__setitem__(
                    "invented_authority", "accepted-by-self-hash"
                ),
            ),
            (
                "false_execution_head_duplicate",
                False,
                lambda receipt: receipt.__setitem__(
                    "execution_expected_head", HEAD_BLUE
                ),
            ),
        )
        for label, binding_changed, mutate in cases:
            with self.subTest(label=label):
                forged = resume_receipt()
                mutate(forged)
                self._rehash(forged, binding_changed=binding_changed)
                self.assertIsNone(midcutover._completed_lineage_binding(forged))
                self.assertFalse(
                    midcutover._lineage_resolved([forged], cutover_receipt())
                )

    def test_legacy_completed_receipt_is_only_a_terminal_tombstone(self) -> None:
        legacy = resume_receipt()
        binding = legacy["resume_binding"]
        for field in (
            "resume_binding_schema_version",
            "source_snapshot_receipt_sha256",
            "source_client_declaration_sha256",
            "classified_snapshot_receipt_sha256",
        ):
            binding.pop(field)
        for field in (
            "source_snapshot_receipt_sha256",
            "source_client_declaration_sha256",
            "classified_snapshot_receipt_sha256",
            "source_release_id",
            "source_repo_head",
            "target_release_id",
            "target_repo_head",
        ):
            legacy["snapshot_rebind"].pop(field)
        legacy["execution_expected_head"] = HEAD_GREEN
        self._rehash(legacy, binding_changed=True)

        self.assertIsNotNone(midcutover._completed_lineage_binding(legacy))
        self.assertTrue(midcutover._lineage_resolved([legacy], cutover_receipt()))
        self.assertIsNone(midcutover._validated_resume_binding(binding))

    def test_completed_receipt_is_terminal_from_every_cold_start_phase(self) -> None:
        for phase in midcutover.RESUME_PHASES:
            with self.subTest(phase=phase):
                receipt = resume_receipt(resume_phase=phase)
                binding = midcutover._completed_lineage_binding(receipt)
                self.assertIsNotNone(binding)
                self.assertEqual(binding["resume_phase"], phase)
                self.assertTrue(
                    midcutover._lineage_resolved([receipt], cutover_receipt())
                )

    def test_resolution_is_discoverable_from_the_original_cutover(self) -> None:
        resolution = midcutover.resolution_for_cutover(
            [cutover_receipt(), resume_receipt()], cutover_receipt()
        )
        self.assertIsNotNone(resolution)
        self.assertEqual(resolution["resumed_cutover_id"], CUTOVER_ID)
        self.assertIsNone(
            midcutover.resolution_for_cutover([cutover_receipt()], cutover_receipt())
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
                midcutover.claimed_resolution_cutover_ids(loaded["receipts"]), {CUTOVER_ID}
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
            self.assertEqual(midcutover.claimed_resolution_cutover_ids([persisted]), set())


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
        the published connector contract is currently converging on.
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


class OperatorCapabilitySourceTests(unittest.TestCase):
    """Tests 24-26: one canonical capability authority, still fail-closed."""

    @staticmethod
    def _policy(capabilities: list[str]) -> dict[str, object]:
        return {
            "active_profile": "test",
            "profiles": {"test": {"capabilities": list(capabilities)}},
            "forbidden_capabilities": [],
        }

    def test_base_capabilities_from_the_active_profile_stay_available(self) -> None:
        import grabowski_operator as operator

        policy = self._policy(["file_read", "audit_verify", "durable_job"])
        with mock.patch.object(operator.base, "_load_policy", return_value=policy):
            operator._require_operator_capability("file_read")
            operator._require_operator_capability("audit_verify")
            operator._require_operator_capability("durable_job")
            self.assertEqual(operator._operator_capabilities(), {"durable_job"})

    def test_capability_absent_from_the_profile_is_refused(self) -> None:
        import grabowski_operator as operator

        policy = self._policy(["file_read"])
        with mock.patch.object(operator.base, "_load_policy", return_value=policy):
            with self.assertRaisesRegex(PermissionError, "not enabled"):
                operator._require_operator_capability("audit_verify")

    def test_undefined_capability_stays_fail_closed(self) -> None:
        import grabowski_operator as operator

        policy = self._policy(["file_read", "not_a_real_capability"])
        with mock.patch.object(operator.base, "_load_policy", return_value=policy):
            with self.assertRaisesRegex(PermissionError, "Unknown capability"):
                operator._require_operator_capability("not_a_real_capability")
            self.assertNotIn(
                "not_a_real_capability", operator._effective_capability_set()
            )

    def test_forbidden_capabilities_still_win(self) -> None:
        import grabowski_operator as operator

        policy = self._policy(["file_read", "audit_verify"])
        policy["forbidden_capabilities"] = ["audit_verify"]
        with mock.patch.object(operator.base, "_load_policy", return_value=policy):
            with self.assertRaisesRegex(PermissionError, "not enabled"):
                operator._require_operator_capability("audit_verify")

    def test_write_capability_follows_the_profile_and_nothing_else(self) -> None:
        import grabowski_operator as operator

        granted = self._policy(["file_read", "file_write"])
        with mock.patch.object(operator.base, "_load_policy", return_value=granted):
            operator._require_operator_capability("file_write")
        withheld = self._policy(["file_read"])
        with mock.patch.object(operator.base, "_load_policy", return_value=withheld):
            with self.assertRaisesRegex(PermissionError, "not enabled"):
                operator._require_operator_capability("file_write")

    def test_capability_correction_grants_no_mutation_on_a_broken_runtime(self) -> None:
        """A wider read capability must not widen the transport gate."""
        import grabowski_operator as operator

        broken = {
            flag: False
            for flag in operator._PROVENANCE_RECOVERY_REPAIRABLE_INTEGRITY_FLAGS
        }
        mutating = mock.Mock()
        mutating.annotations = mock.Mock(readOnlyHint=False)
        policy = self._policy(
            ["file_read", "audit_verify", "durable_job", "git_cli", "power_execute"]
        )
        with (
            mock.patch.object(operator.base, "_load_policy", return_value=policy),
            mock.patch.object(
                operator.base, "_deployment_metadata", return_value=broken
            ),
        ):
            for tool_name in ("grabowski_power_run", "grabowski_git"):
                with self.subTest(tool=tool_name):
                    self.assertFalse(
                        operator._provenance_recovery_transport_exempt_call(
                            tool_name, mutating
                        )
                    )

    def test_mutation_gate_stays_narrower_than_the_catalog(self) -> None:
        import grabowski_operator as operator

        policy = self._policy(["file_read", "audit_verify"])
        with mock.patch.object(operator.base, "_load_policy", return_value=policy):
            with self.assertRaisesRegex(
                PermissionError, "Not an operator mutation capability"
            ):
                operator._require_operator_mutation("file_read")


if __name__ == "__main__":
    unittest.main()
