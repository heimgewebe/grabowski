from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from grabowski_blockades import (  # noqa: E402
    ACTION_CLASSES,
    GLOBAL_HARD_STOP_TRIGGER_CLASSES,
    POSTURE_ORDER,
    POSTURES,
    SCOPE_KINDS,
    ActionContext,
    BlockadeRecord,
    BlockadeValidationError,
    DisarmEvidence,
    Provenance,
    Scope,
    canonical_json,
    canonical_sha256,
    environment_stop_record,
    evaluate_blockades,
    legacy_marker_record,
    load_records,
    scope_matches,
    validate_disarm,
)


NOW = datetime(2026, 7, 14, 19, 0, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64
CANONICAL_MARKER = "/home/alex/.local/state/grabowski/operator-kill-switch"


def provenance() -> Provenance:
    return Provenance(
        tool="grabowski_operator_blockade_engage",
        request_id="request-1",
        session_id="session-1",
        task_id="TASK-1",
        owner_id="owner-1",
    )


def record(
    *,
    blockade_id: str = "blockade-1",
    posture: str = "mutation_freeze",
    scope: Scope | None = None,
    expires_at: datetime | None = None,
    source: str = "typed",
    disarm_policy: str = "in_band",
    trigger_class: str | None = None,
    schema_version: int = 1,
    evidence_refs: tuple[str, ...] = ("audit:123", "receipt:abc"),
) -> BlockadeRecord:
    resolved_scope = scope or Scope("path", "/srv/example")
    resolved_trigger = trigger_class or (
        "host_wide_damage_unknown"
        if posture == "hard_stop" and resolved_scope.kind == "global"
        else "test_incident"
    )
    return BlockadeRecord(
        blockade_id=blockade_id,
        posture=posture,
        scope=resolved_scope,
        reason="Bounded test incident.",
        trigger_class=resolved_trigger,
        engaged_at=NOW,
        expires_at=expires_at,
        evidence_refs=evidence_refs,
        provenance=provenance(),
        source=source,
        disarm_policy=disarm_policy,
        schema_version=schema_version,
    )


def evidence_for(item: BlockadeRecord, **overrides: object) -> DisarmEvidence:
    values: dict[str, object] = {
        "blockade_id": item.blockade_id,
        "record_sha256": item.sha256,
        "scope": item.scope,
        "marker_path": CANONICAL_MARKER,
        "marker_present": True,
        "marker_regular": True,
        "marker_nlink": 1,
        "marker_mode": 0o600,
        "marker_owner_matches": True,
        "environment_switch_off": True,
        "audit_valid": True,
        "deployment_provenance_valid": True,
        "canonical_recovery_fresh": True,
        "root_broker_ready": True,
    }
    values.update(overrides)
    return DisarmEvidence(**values)  # type: ignore[arg-type]


class BlockadeTests(unittest.TestCase):
    def test_public_enums_have_stable_order(self) -> None:
        self.assertEqual(
            SCOPE_KINDS,
            (
                "path",
                "capability",
                "task",
                "owner",
                "repo",
                "service",
                "host",
                "global",
            ),
        )
        self.assertEqual(
            POSTURES,
            (
                "observe",
                "preflight_required",
                "mutation_freeze",
                "hard_stop",
            ),
        )
        self.assertEqual([POSTURE_ORDER[name] for name in POSTURES], [0, 1, 2, 3])
        self.assertEqual(
            set(ACTION_CLASSES),
            {"read", "status", "audit_read", "mutate", "recovery_disarm"},
        )

    def test_record_round_trip_and_hash_are_deterministic(self) -> None:
        item = record(
            posture="preflight_required",
            expires_at=NOW + timedelta(hours=1),
        )
        mapping = item.to_mapping()
        parsed = BlockadeRecord.from_mapping(mapping)
        self.assertEqual(parsed, item)
        self.assertEqual(parsed.sha256, item.sha256)
        self.assertEqual(
            canonical_json(mapping),
            canonical_json(dict(reversed(list(mapping.items())))),
        )
        self.assertEqual(canonical_sha256(mapping), item.sha256)
        self.assertEqual(json.loads(canonical_json(mapping)), mapping)

    def test_mapping_rejects_unknown_and_missing_keys(self) -> None:
        mapping = record().to_mapping()
        mapping["unexpected"] = True
        with self.assertRaisesRegex(BlockadeValidationError, "unknown keys"):
            BlockadeRecord.from_mapping(mapping)

        mapping = record().to_mapping()
        del mapping["reason"]
        with self.assertRaisesRegex(BlockadeValidationError, "missing keys"):
            BlockadeRecord.from_mapping(mapping)

    def test_nested_mappings_reject_unknown_keys(self) -> None:
        mapping = record().to_mapping()
        mapping["scope"]["extra"] = "x"
        with self.assertRaisesRegex(BlockadeValidationError, "scope has unknown keys"):
            BlockadeRecord.from_mapping(mapping)

        mapping = record().to_mapping()
        mapping["provenance"]["extra"] = "x"
        with self.assertRaisesRegex(
            BlockadeValidationError, "provenance has unknown keys"
        ):
            BlockadeRecord.from_mapping(mapping)

    def test_record_rejects_boolean_schema_version(self) -> None:
        with self.assertRaisesRegex(BlockadeValidationError, "schema_version"):
            record(schema_version=True)

    def test_evidence_refs_are_arrays_and_hash_order_independent(self) -> None:
        with self.assertRaisesRegex(
            BlockadeValidationError, "evidence_refs must be an array"
        ):
            record(evidence_refs="audit:123")  # type: ignore[arg-type]

        first = record(evidence_refs=("receipt:abc", "audit:123"))
        second = record(evidence_refs=("audit:123", "receipt:abc"))
        self.assertEqual(first.evidence_refs, ("audit:123", "receipt:abc"))
        self.assertEqual(first, second)
        self.assertEqual(first.sha256, second.sha256)

        with self.assertRaisesRegex(BlockadeValidationError, "must be unique"):
            record(evidence_refs=("audit:123", "audit:123"))

    def test_global_hard_stop_requires_global_trust_trigger(self) -> None:
        with self.assertRaisesRegex(BlockadeValidationError, "global trust trigger"):
            record(
                posture="hard_stop",
                scope=Scope("global", "*"),
                trigger_class="local_ci_failure",
            )

        for trigger in GLOBAL_HARD_STOP_TRIGGER_CLASSES:
            with self.subTest(trigger=trigger):
                item = record(
                    posture="hard_stop",
                    scope=Scope("global", "*"),
                    trigger_class=trigger,
                )
                self.assertEqual(item.trigger_class, trigger)

    def test_scope_rejects_invalid_values(self) -> None:
        cases = (
            ("path", "relative/path"),
            ("repo", "repo"),
            ("path", "/srv/../etc"),
            ("path", "/srv/example/"),
            ("global", "all"),
            ("capability", "bad value"),
            ("unknown", "x"),
        )
        for kind, value in cases:
            with self.subTest(kind=kind, value=value):
                with self.assertRaises(BlockadeValidationError):
                    Scope(kind, value)

    def test_scope_accepts_root_and_canonical_absolute_paths(self) -> None:
        self.assertEqual(Scope("path", "/").value, "/")
        self.assertEqual(Scope("path", "/srv/example").value, "/srv/example")
        self.assertTrue(
            Scope("repo", "/home/alex/repos/grabowski").value.endswith("/grabowski")
        )

    def test_all_scope_kinds_match(self) -> None:
        cases = (
            (
                Scope("path", "/srv/example"),
                ActionContext("mutate", path="/srv/example/a"),
            ),
            (
                Scope("capability", "file_write"),
                ActionContext("mutate", capability="file_write"),
            ),
            (Scope("task", "TASK-1"), ActionContext("mutate", task_id="TASK-1")),
            (
                Scope("owner", "owner-1"),
                ActionContext("mutate", owner_id="owner-1"),
            ),
            (
                Scope("repo", "/home/alex/repos/grabowski"),
                ActionContext("mutate", repo="/home/alex/repos/grabowski/subdir"),
            ),
            (
                Scope("service", "grabowski.service"),
                ActionContext("mutate", service="grabowski.service"),
            ),
            (
                Scope("host", "heim-pc"),
                ActionContext("mutate", host="heim-pc"),
            ),
            (Scope("global", "*"), ActionContext("mutate")),
        )
        for scope, action in cases:
            with self.subTest(scope=scope):
                self.assertTrue(scope_matches(scope, action))

    def test_specific_scopes_do_not_overmatch(self) -> None:
        cases = (
            (
                Scope("path", "/srv/example"),
                ActionContext("mutate", path="/srv/examples"),
            ),
            (Scope("path", "/srv/example"), ActionContext("mutate")),
            (
                Scope("repo", "/home/alex/repos/grabowski"),
                ActionContext("mutate", repo="/home/alex/repos/grabowski-old"),
            ),
            (Scope("capability", "file_write"), ActionContext("mutate")),
            (Scope("task", "TASK-1"), ActionContext("mutate", task_id="TASK-2")),
            (
                Scope("owner", "owner-1"),
                ActionContext("mutate", owner_id="owner-2"),
            ),
            (
                Scope("service", "grabowski.service"),
                ActionContext("mutate", service="other.service"),
            ),
            (
                Scope("host", "heim-pc"),
                ActionContext("mutate", host="heimberry"),
            ),
        )
        for scope, action in cases:
            with self.subTest(scope=scope):
                self.assertFalse(scope_matches(scope, action))

    def test_path_matching_uses_component_boundaries(self) -> None:
        scope = Scope("path", "/srv/data")
        self.assertTrue(scope_matches(scope, ActionContext("mutate", path="/srv/data")))
        self.assertTrue(
            scope_matches(scope, ActionContext("mutate", path="/srv/data/item"))
        )
        self.assertFalse(
            scope_matches(scope, ActionContext("mutate", path="/srv/database"))
        )

    def test_observe_never_blocks_mutation(self) -> None:
        decision = evaluate_blockades(
            [record(posture="observe")],
            ActionContext("mutate", path="/srv/example/item"),
            now=NOW,
        )
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.blocked)
        self.assertEqual(decision.effective_posture, "observe")
        self.assertEqual(decision.reasons, ("observe_only",))

    def test_preflight_posture_requires_fresh_preflight(self) -> None:
        item = record(
            posture="preflight_required",
            expires_at=NOW + timedelta(hours=1),
        )
        denied = evaluate_blockades(
            [item], ActionContext("mutate", path="/srv/example/a"), now=NOW
        )
        self.assertTrue(denied.blocked)
        self.assertTrue(denied.requires_preflight)
        self.assertEqual(denied.reasons, ("fresh_preflight_required",))

        allowed = evaluate_blockades(
            [item],
            ActionContext(
                "mutate",
                path="/srv/example/a",
                fresh_preflight=True,
            ),
            now=NOW,
        )
        self.assertTrue(allowed.allowed)
        self.assertTrue(allowed.requires_preflight)
        self.assertEqual(allowed.reasons, ("fresh_preflight_satisfied",))

    def test_strong_postures_block_mutation(self) -> None:
        for posture in ("mutation_freeze", "hard_stop"):
            with self.subTest(posture=posture):
                decision = evaluate_blockades(
                    [record(posture=posture)],
                    ActionContext(
                        "mutate",
                        path="/srv/example/a",
                        fresh_preflight=True,
                    ),
                    now=NOW,
                )
                self.assertTrue(decision.blocked)
                self.assertFalse(decision.requires_preflight)
                self.assertEqual(
                    decision.reasons,
                    (f"mutation_blocked_by_{posture}",),
                )

    def test_immutable_read_lanes_remain_available(self) -> None:
        for action_class in ("read", "status", "audit_read"):
            with self.subTest(action_class=action_class):
                decision = evaluate_blockades(
                    [record(posture="hard_stop", scope=Scope("global", "*"))],
                    ActionContext(action_class, path="/srv/example/a"),
                    now=NOW,
                )
                self.assertTrue(decision.allowed)
                self.assertEqual(
                    decision.reasons,
                    ("immutable_read_lane_remains_available",),
                )

    def test_nonmatching_blockade_has_no_effect(self) -> None:
        decision = evaluate_blockades(
            [record(scope=Scope("path", "/srv/other"))],
            ActionContext("mutate", path="/srv/example"),
            now=NOW,
        )
        self.assertTrue(decision.allowed)
        self.assertIsNone(decision.effective_posture)
        self.assertEqual(decision.matched_blockade_ids, ())

    def test_multiple_records_compose_monotonically(self) -> None:
        records = [
            record(blockade_id="z-local", posture="observe"),
            record(
                blockade_id="a-global",
                posture="hard_stop",
                scope=Scope("global", "*"),
            ),
            record(
                blockade_id="m-preflight",
                posture="preflight_required",
                expires_at=NOW + timedelta(hours=1),
            ),
        ]
        decision = evaluate_blockades(
            records,
            ActionContext("mutate", path="/srv/example/a", fresh_preflight=True),
            now=NOW,
        )
        self.assertTrue(decision.blocked)
        self.assertEqual(decision.effective_posture, "hard_stop")
        self.assertEqual(
            decision.matched_blockade_ids,
            ("a-global", "m-preflight", "z-local"),
        )
        self.assertEqual(
            decision.matched_record_sha256s,
            tuple(
                item.sha256
                for item in sorted(records, key=lambda item: item.blockade_id)
            ),
        )
        self.assertEqual(decision.evidence_refs, ("audit:123", "receipt:abc"))

    def test_expiry_semantics_fail_closed(self) -> None:
        expired = record(
            posture="preflight_required",
            expires_at=NOW + timedelta(minutes=5),
        )
        decision = evaluate_blockades(
            [expired],
            ActionContext("mutate", path="/srv/example/a"),
            now=NOW + timedelta(minutes=5),
        )
        self.assertTrue(decision.allowed)
        self.assertIsNone(decision.effective_posture)

        for posture in ("mutation_freeze", "hard_stop"):
            with self.subTest(posture=posture):
                with self.assertRaisesRegex(
                    BlockadeValidationError, "must not expire automatically"
                ):
                    record(posture=posture, expires_at=NOW + timedelta(hours=1))

        with self.assertRaisesRegex(BlockadeValidationError, "after engaged_at"):
            record(posture="observe", expires_at=NOW)

    def test_record_requires_timezone_aware_timestamps(self) -> None:
        mapping = record(posture="observe").to_mapping()
        mapping["engaged_at"] = "2026-07-14T19:00:00"
        with self.assertRaisesRegex(BlockadeValidationError, "timezone"):
            BlockadeRecord.from_mapping(mapping)

    def test_disarm_validation_succeeds_with_exact_evidence(self) -> None:
        item = record(posture="hard_stop", scope=Scope("global", "*"))
        result = validate_disarm(
            item,
            evidence_for(item),
            expected_marker_path=CANONICAL_MARKER,
        )
        self.assertTrue(result.allowed)
        self.assertEqual(result.reasons, ())

    def test_disarm_validation_fails_closed(self) -> None:
        item = record(posture="hard_stop", scope=Scope("global", "*"))
        cases: tuple[tuple[dict[str, object], str], ...] = (
            ({"blockade_id": "other"}, "blockade_id_mismatch"),
            ({"record_sha256": SHA_B}, "record_sha256_mismatch"),
            ({"scope": Scope("path", "/other")}, "scope_mismatch"),
            ({"marker_path": "/tmp/not-canonical-marker"}, "marker_path_mismatch"),
            ({"marker_present": False}, "marker_absent"),
            ({"marker_regular": False}, "marker_not_regular"),
            ({"marker_nlink": 2}, "marker_link_count_invalid"),
            ({"marker_mode": 0o644}, "marker_mode_invalid"),
            ({"marker_owner_matches": False}, "marker_owner_mismatch"),
            ({"environment_switch_off": False}, "environment_switch_engaged"),
            ({"audit_valid": False}, "audit_invalid"),
            (
                {"deployment_provenance_valid": False},
                "deployment_provenance_invalid",
            ),
            ({"canonical_recovery_fresh": False}, "canonical_recovery_stale"),
            ({"root_broker_ready": False}, "root_broker_not_ready"),
        )
        for override, expected_reason in cases:
            with self.subTest(reason=expected_reason):
                result = validate_disarm(
                    item,
                    evidence_for(item, **override),
                    expected_marker_path=CANONICAL_MARKER,
                )
                self.assertFalse(result.allowed)
                self.assertIn(expected_reason, result.reasons)

    def test_recovery_disarm_requires_active_matching_target(self) -> None:
        item = record(posture="hard_stop", scope=Scope("path", "/srv/example"))
        action = ActionContext(
            "recovery_disarm",
            path="/srv/other",
            expected_marker_path=CANONICAL_MARKER,
            disarm_evidence=evidence_for(item),
        )
        decision = evaluate_blockades([item], action, now=NOW)
        self.assertTrue(decision.blocked)
        self.assertIsNotNone(decision.disarm_validation)
        assert decision.disarm_validation is not None
        self.assertEqual(
            decision.disarm_validation.reasons,
            ("target_blockade_not_active_in_scope",),
        )

    def test_recovery_disarm_is_allowed_only_for_exact_evidence(self) -> None:
        item = record(posture="hard_stop", scope=Scope("path", "/srv/example"))
        action = ActionContext(
            "recovery_disarm",
            path="/srv/example/marker",
            expected_marker_path=CANONICAL_MARKER,
            disarm_evidence=evidence_for(item),
        )
        decision = evaluate_blockades([item], action, now=NOW)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reasons, ("evidence_bound_recovery_allowed",))

        denied = evaluate_blockades(
            [item],
            replace(action, disarm_evidence=evidence_for(item, audit_valid=False)),
            now=NOW,
        )
        self.assertTrue(denied.blocked)
        self.assertIn("audit_invalid", denied.reasons)

    def test_environment_record_is_global_external_only(self) -> None:
        external = environment_stop_record(
            value_sha256=SHA_A,
            engaged_at=NOW,
            host="heim-pc",
        )
        self.assertEqual(external.posture, "hard_stop")
        self.assertEqual(external.scope, Scope("global", "*"))
        self.assertEqual(external.source, "environment")
        self.assertEqual(external.disarm_policy, "external_only")

        action = ActionContext(
            "recovery_disarm",
            expected_marker_path=CANONICAL_MARKER,
            disarm_evidence=evidence_for(external),
        )
        decision = evaluate_blockades([external], action, now=NOW)
        self.assertTrue(decision.blocked)
        self.assertIn("external_only_disarm", decision.reasons)
        self.assertIn("external_stop_requires_external_clear", decision.reasons)

    def test_external_record_blocks_disarm_of_another_matching_record(self) -> None:
        typed = record(posture="hard_stop", scope=Scope("global", "*"))
        external = environment_stop_record(
            value_sha256=SHA_B,
            engaged_at=NOW,
            host="heim-pc",
        )
        action = ActionContext(
            "recovery_disarm",
            expected_marker_path=CANONICAL_MARKER,
            disarm_evidence=evidence_for(typed),
        )
        decision = evaluate_blockades([typed, external], action, now=NOW)
        self.assertTrue(decision.blocked)
        self.assertIn("external_stop_requires_external_clear", decision.reasons)

    def test_legacy_adapter_is_deterministic_and_recovery_gated(self) -> None:
        first = legacy_marker_record(
            marker_path=CANONICAL_MARKER,
            marker_sha256=SHA_A,
            engaged_at=NOW,
            host="heim-pc",
        )
        second = legacy_marker_record(
            marker_path=CANONICAL_MARKER,
            marker_sha256=SHA_A,
            engaged_at=NOW,
            host="heim-pc",
        )
        self.assertEqual(first, second)
        self.assertEqual(first.blockade_id, "legacy-" + SHA_A[:24])
        self.assertEqual(first.scope, Scope("global", "*"))
        self.assertEqual(first.posture, "hard_stop")
        self.assertEqual(first.source, "legacy_file")
        self.assertEqual(first.disarm_policy, "in_band")
        self.assertEqual(first.sha256, second.sha256)

    def test_environment_source_requires_external_only_policy(self) -> None:
        with self.assertRaisesRegex(BlockadeValidationError, "external_only"):
            record(source="environment", disarm_policy="in_band")

    def test_action_context_rejects_misplaced_disarm_evidence(self) -> None:
        item = record()
        with self.assertRaisesRegex(
            BlockadeValidationError, "requires disarm_evidence"
        ):
            ActionContext(
                "recovery_disarm",
                path="/srv/example",
                expected_marker_path=CANONICAL_MARKER,
            )
        with self.assertRaisesRegex(BlockadeValidationError, "expected_marker_path"):
            ActionContext(
                "recovery_disarm",
                path="/srv/example",
                disarm_evidence=evidence_for(item),
            )
        with self.assertRaisesRegex(BlockadeValidationError, "only valid"):
            ActionContext(
                "mutate",
                path="/srv/example",
                disarm_evidence=evidence_for(item),
            )
        with self.assertRaisesRegex(BlockadeValidationError, "only valid"):
            ActionContext(
                "mutate",
                path="/srv/example",
                expected_marker_path=CANONICAL_MARKER,
            )

    def test_load_and_evaluate_reject_duplicate_ids_and_wrong_types(self) -> None:
        mapping = record().to_mapping()
        with self.assertRaisesRegex(BlockadeValidationError, "duplicate blockade_id"):
            load_records([mapping, dict(mapping)])

        item = record()
        with self.assertRaisesRegex(BlockadeValidationError, "duplicate blockade_id"):
            evaluate_blockades(
                [item, item],
                ActionContext("mutate", path="/srv/example"),
                now=NOW,
            )
        with self.assertRaisesRegex(BlockadeValidationError, "BlockadeRecord"):
            evaluate_blockades(
                [item, object()],  # type: ignore[list-item]
                ActionContext("mutate", path="/srv/example"),
                now=NOW,
            )

    def test_schema_contract_is_strict_and_matches_runtime_enums(self) -> None:
        schema_path = ROOT / "contracts" / "operator-blockade-state.v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["const"], 1)
        self.assertEqual(tuple(schema["properties"]["posture"]["enum"]), POSTURES)
        self.assertEqual(
            tuple(schema["$defs"]["scope"]["properties"]["kind"]["enum"]),
            SCOPE_KINDS,
        )
        self.assertFalse(schema["$defs"]["scope"]["additionalProperties"])
        self.assertFalse(schema["$defs"]["provenance"]["additionalProperties"])
        global_guard = schema["allOf"][2]["then"]["properties"]["trigger_class"]["enum"]
        self.assertEqual(tuple(global_guard), GLOBAL_HARD_STOP_TRIGGER_CLASSES)

        strong_expiry_guard = schema["allOf"][0]
        self.assertEqual(
            set(strong_expiry_guard["if"]["properties"]["posture"]["enum"]),
            {"mutation_freeze", "hard_stop"},
        )
        self.assertEqual(
            strong_expiry_guard["then"]["not"]["required"],
            ["expires_at"],
        )
        environment_guard = schema["allOf"][1]
        self.assertEqual(
            environment_guard["then"]["properties"]["disarm_policy"]["const"],
            "external_only",
        )

    def test_schema_semantics_are_enforced_by_runtime_parser(self) -> None:
        valid = record(
            posture="hard_stop",
            scope=Scope("global", "*"),
            trigger_class="audit_integrity_invalid",
        ).to_mapping()
        self.assertEqual(BlockadeRecord.from_mapping(valid).to_mapping(), valid)

        invalid_global_trigger = dict(valid)
        invalid_global_trigger["trigger_class"] = "local_ci_failure"
        with self.assertRaisesRegex(BlockadeValidationError, "global trust trigger"):
            BlockadeRecord.from_mapping(invalid_global_trigger)

        expiring_hard_stop = dict(valid)
        expiring_hard_stop["expires_at"] = "2026-07-15T19:00:00Z"
        with self.assertRaisesRegex(
            BlockadeValidationError, "must not expire automatically"
        ):
            BlockadeRecord.from_mapping(expiring_hard_stop)

        environment = environment_stop_record(
            value_sha256=SHA_A,
            engaged_at=NOW,
            host="heim-pc",
        ).to_mapping()
        environment["disarm_policy"] = "in_band"
        with self.assertRaisesRegex(BlockadeValidationError, "external_only"):
            BlockadeRecord.from_mapping(environment)

        unknown = dict(valid)
        unknown["unexpected"] = True
        with self.assertRaisesRegex(BlockadeValidationError, "unknown keys"):
            BlockadeRecord.from_mapping(unknown)

        boolean_version = dict(valid)
        boolean_version["schema_version"] = True
        with self.assertRaisesRegex(BlockadeValidationError, "schema_version"):
            BlockadeRecord.from_mapping(boolean_version)

    def test_evidence_order_and_decision_mapping_are_stable(self) -> None:
        one = replace(
            record(blockade_id="b", posture="observe"),
            evidence_refs=("z", "a"),
        )
        two = replace(
            record(blockade_id="a", posture="observe"),
            evidence_refs=("m", "a"),
        )
        decision = evaluate_blockades(
            [one, two],
            ActionContext("mutate", path="/srv/example"),
            now=NOW,
        )
        self.assertEqual(decision.matched_blockade_ids, ("a", "b"))
        self.assertEqual(decision.evidence_refs, ("a", "m", "z"))
        self.assertEqual(decision.to_mapping(), decision.to_mapping())


if __name__ == "__main__":
    unittest.main()
