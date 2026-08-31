from pathlib import Path


def replace_between(path: Path, start_marker: str, end_marker: str, replacement: str) -> None:
    source = path.read_text(encoding="utf-8")
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    path.write_text(source[:start] + replacement + source[end:], encoding="utf-8")


replace_between(
    Path("tools/maintain_runtime_state.py"),
    "def _retention_audit_reconciliation_state(",
    "\n\ndef _require_reconciliation_mutation_authority",
    r'''def _retention_audit_reconciliation_state(
    *,
    intent_record_sha256: str,
    plan_sha256: str,
    attempt: int,
    receipt_sha256: str,
) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{64}", intent_record_sha256) is None:
        raise RuntimeError("retention reconciliation intent hash is invalid")
    source = str(SRC)
    if source not in sys.path:
        sys.path.insert(0, source)
    import grabowski_audit_query as audit_query

    snapshot = audit_query.capture_verified_audit_snapshot()
    open_intents: dict[str, dict[str, Any]] = {}
    target_seen = False
    receipt_consumer_digest: str | None = None
    receipt_consumer_kind: str | None = None
    original_completion: dict[str, Any] | None = None
    existing_reconciliation: dict[str, Any] | None = None

    for item in audit_query._iter_snapshot_items(snapshot, order="asc"):
        evidence = item.get("evidence", {})
        record = item.get("record", {})
        if not isinstance(evidence, dict) or not isinstance(record, dict):
            continue
        record_digest = evidence.get("record_sha256")
        operation = record.get("operation")
        same_identity = (
            record.get("plan_sha256") == plan_sha256
            and record.get("attempt") == attempt
        )
        if record_digest == intent_record_sha256 and (
            operation != "runtime-state-retention-intent" or not same_identity
        ):
            raise RuntimeError("retention reconciliation intent binding is invalid")

        if operation == "runtime-state-retention-intent" and same_identity:
            if (
                not isinstance(record_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", record_digest) is None
            ):
                raise RuntimeError(
                    "retention reconciliation intent evidence digest is invalid"
                )
            open_intents.setdefault(record_digest, record)
            if record_digest == intent_record_sha256:
                target_seen = True
            continue

        if operation == "runtime-state-retention-complete" and same_identity:
            if record.get("receipt_sha256") != receipt_sha256:
                raise RuntimeError(
                    "retention completion audit receipt binding conflicts"
                )
            # The canonical terminal receipt represents one retention execution.
            # Once that execution has already been bound by a prior completion or
            # reconciliation, later audit repair evidence must not consume another
            # duplicate intent.
            if receipt_consumer_digest is not None or not open_intents:
                continue
            consumed_digest = next(reversed(open_intents))
            open_intents.pop(consumed_digest)
            receipt_consumer_digest = consumed_digest
            receipt_consumer_kind = "completion"
            if consumed_digest == intent_record_sha256:
                original_completion = {
                    "record_sha256": record_digest,
                    "record": record,
                }
            continue

        if (
            operation == RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION
            and same_identity
        ):
            claimed_intent_digest = record.get("intent_record_sha256")
            if (
                not isinstance(claimed_intent_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", claimed_intent_digest) is None
                or record.get("receipt_sha256") != receipt_sha256
                or record.get("reconciliation_kind") != "completion_audit_gap"
                or record.get("completed") is not True
                or record.get("retention_effect_retried") is not False
            ):
                raise RuntimeError(
                    "retention completion reconciliation binding conflicts"
                )

            if receipt_consumer_digest is not None:
                if receipt_consumer_digest != claimed_intent_digest:
                    raise RuntimeError(
                        "retention terminal receipt is already bound to another intent"
                    )
                # A completion appended after reconciliation is redundant repair
                # evidence for the same execution. It must not change which intent
                # the terminal receipt consumed.
                if (
                    receipt_consumer_kind == "reconciliation"
                    and claimed_intent_digest == intent_record_sha256
                    and existing_reconciliation is None
                ):
                    existing_reconciliation = {
                        "record_sha256": record_digest,
                        "record": record,
                    }
                continue

            if not open_intents:
                raise RuntimeError(
                    "retention reconciliation has no eligible open intent"
                )
            eligible_intent_digest = next(reversed(open_intents))
            if claimed_intent_digest != eligible_intent_digest:
                raise RuntimeError(
                    "retention reconciliation intent is ambiguous among duplicate intents"
                )
            open_intents.pop(claimed_intent_digest)
            receipt_consumer_digest = claimed_intent_digest
            receipt_consumer_kind = "reconciliation"
            if claimed_intent_digest == intent_record_sha256:
                existing_reconciliation = {
                    "record_sha256": record_digest,
                    "record": record,
                }

    if not target_seen:
        raise RuntimeError(
            "retention reconciliation intent record was not found in verified audit"
        )
    if original_completion is not None or existing_reconciliation is not None:
        return {
            "original_completion": original_completion,
            "existing_reconciliation": existing_reconciliation,
        }

    if receipt_consumer_digest is not None:
        raise RuntimeError(
            "retention terminal receipt is already bound to another intent"
        )
    if intent_record_sha256 not in open_intents:
        raise RuntimeError("retention reconciliation intent is no longer open")
    if next(reversed(open_intents)) != intent_record_sha256:
        raise RuntimeError(
            "retention reconciliation intent is ambiguous among duplicate intents"
        )
    return {
        "original_completion": None,
        "existing_reconciliation": None,
    }
''',
)

replace_between(
    Path("src/grabowski_audit_signal.py"),
    "def _audit_transition_gap_signal(",
    "\n\ndef _audit_friction_signal_source",
    r'''def _audit_transition_gap_signal(
    prepared_records: list[tuple[dict[str, Any], int | None]],
    *,
    start_unix: int,
    end_unix: int,
) -> dict[str, Any]:
    retention_pair = (
        "runtime-state-retention-intent",
        "runtime-state-retention-complete",
    )
    pending: dict[tuple[str, str], list[tuple[dict[str, Any], int]]] = {
        pair: [] for pair in AUDIT_TRANSITION_PAIRS
    }
    pending_retention: dict[
        tuple[str, int, str], tuple[dict[str, Any], int]
    ] = {}
    pending_retention_keys_by_identity: dict[
        tuple[str, int], dict[tuple[str, int, str], None]
    ] = {}
    historical_retention_intents: dict[
        tuple[str, int, str], tuple[dict[str, Any], int]
    ] = {}
    historical_retention_intents_by_digest: dict[
        str, tuple[tuple[str, int, str], dict[str, Any], int]
    ] = {}
    historical_reconciled_keys: set[tuple[str, int, str]] = set()
    historical_completed_keys: set[tuple[str, int, str]] = set()
    historical_open_keys_by_identity: dict[
        tuple[str, int], dict[tuple[str, int, str], None]
    ] = {}
    historical_unmatched: dict[
        tuple[str, int, str], tuple[str, dict[str, Any], int]
    ] = {}
    consumed_retention_receipts: dict[str, tuple[str, int, str]] = {}
    completed_counts: Counter[str] = Counter()
    reconciled_counts: Counter[str] = Counter()
    reconciled_records: list[dict[str, Any]] = []

    def _remember_pending_retention(
        key: tuple[str, int, str], record: dict[str, Any], timestamp_unix: int
    ) -> None:
        pending_retention[key] = (record, timestamp_unix)
        keys = pending_retention_keys_by_identity.setdefault(key[:2], {})
        keys.setdefault(key, None)

    def _pop_pending_retention(
        key: tuple[str, int, str]
    ) -> tuple[dict[str, Any], int] | None:
        item = pending_retention.pop(key, None)
        keys = pending_retention_keys_by_identity.get(key[:2])
        if keys is not None:
            keys.pop(key, None)
            if not keys:
                pending_retention_keys_by_identity.pop(key[:2], None)
        return item

    def _remember_historical_open(key: tuple[str, int, str]) -> None:
        keys = historical_open_keys_by_identity.setdefault(key[:2], {})
        keys.setdefault(key, None)

    def _pop_historical_open(key: tuple[str, int, str]) -> bool:
        keys = historical_open_keys_by_identity.get(key[:2])
        if keys is None or key not in keys:
            return False
        keys.pop(key, None)
        if not keys:
            historical_open_keys_by_identity.pop(key[:2], None)
        return True

    def _peek_latest_historical_open(
        identity: tuple[str, int],
    ) -> tuple[str, int, str] | None:
        keys = historical_open_keys_by_identity.get(identity)
        return next(reversed(keys)) if keys else None

    def _latest_open_retention_key(
        identity: tuple[str, int],
    ) -> tuple[str, int, str] | None:
        # In-window intents necessarily follow historical intents in verified
        # audit order, so prefer their ordered index when one exists.
        pending_keys = pending_retention_keys_by_identity.get(identity)
        if pending_keys:
            return next(reversed(pending_keys))
        return _peek_latest_historical_open(identity)

    def _remember_historical_unmatched(
        key: tuple[str, int, str], record: dict[str, Any], timestamp_unix: int
    ) -> None:
        historical_unmatched[key] = (
            retention_pair[0],
            record,
            timestamp_unix,
        )

    def _pop_historical_unmatched(
        key: tuple[str, int, str]
    ) -> tuple[str, dict[str, Any], int] | None:
        return historical_unmatched.pop(key, None)

    def _receipt_consumed(record: dict[str, Any]) -> bool:
        receipt_sha256 = record.get("receipt_sha256")
        return bool(
            _audit_sha256_valid(receipt_sha256)
            and receipt_sha256 in consumed_retention_receipts
        )

    def _claim_receipt(
        record: dict[str, Any], key: tuple[str, int, str]
    ) -> bool:
        receipt_sha256 = record.get("receipt_sha256")
        if not _audit_sha256_valid(receipt_sha256):
            return True
        existing = consumed_retention_receipts.get(receipt_sha256)
        if existing is not None:
            return existing == key
        consumed_retention_receipts[receipt_sha256] = key
        return True

    for record, timestamp_unix in prepared_records:
        if timestamp_unix is None or timestamp_unix > end_unix:
            continue
        operation = record.get("operation")

        if timestamp_unix < start_unix:
            if operation == retention_pair[0]:
                key = _retention_intent_index_key(record)
                if key is not None:
                    historical_retention_intents[key] = (record, timestamp_unix)
                    historical_retention_intents_by_digest[key[2]] = (
                        key, record, timestamp_unix
                    )
                    _remember_historical_open(key)
            elif operation == retention_pair[1]:
                identity = _retention_transition_identity(record)
                if identity is not None and not _receipt_consumed(record):
                    completed_key = _peek_latest_historical_open(identity)
                    if completed_key is not None and _claim_receipt(
                        record, completed_key
                    ):
                        _pop_historical_open(completed_key)
                        _pop_historical_unmatched(completed_key)
                        historical_completed_keys.add(completed_key)
            elif operation == RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION:
                target_key = _retention_reconciliation_target_key(record)
                if (
                    target_key in historical_retention_intents
                    and _retention_reconciliation_record_valid(record)
                    and target_key not in historical_completed_keys
                    and target_key
                    == _latest_open_retention_key(target_key[:2])
                    and not _receipt_consumed(record)
                    and _claim_receipt(record, target_key)
                    and _pop_historical_open(target_key)
                ):
                    historical_reconciled_keys.add(target_key)
            continue

        if operation == retention_pair[0]:
            key = _retention_intent_index_key(record)
            if key is None:
                # Preserve legacy/malformed fail-closed FIFO behavior separately.
                pending[retention_pair].append((record, timestamp_unix))
            else:
                _remember_pending_retention(key, record, timestamp_unix)
            continue

        if operation == RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION:
            target_key = _retention_reconciliation_target_key(record)
            if target_key is not None and target_key in pending_retention:
                if (
                    _retention_reconciliation_record_valid(record)
                    and target_key
                    == _latest_open_retention_key(target_key[:2])
                    and not _receipt_consumed(record)
                    and _claim_receipt(record, target_key)
                ):
                    _pop_pending_retention(target_key)
                    reconciled_counts[retention_pair[0]] += 1
                    reconciled_records.append(record)
                # Invalid or ambiguously ordered evidence leaves the exact
                # in-window intent pending/HIGH.
                continue

            intent_record_sha256 = record.get("intent_record_sha256")
            historical_target = (
                historical_retention_intents_by_digest.get(intent_record_sha256)
                if _audit_sha256_valid(intent_record_sha256)
                else None
            )
            if historical_target is None:
                continue
            historical_key, historical_record, historical_timestamp = historical_target
            if (
                historical_key in historical_reconciled_keys
                or historical_key in historical_completed_keys
            ):
                continue
            if (
                target_key == historical_key
                and _retention_reconciliation_record_valid(record)
                and historical_key
                == _latest_open_retention_key(historical_key[:2])
                and not _receipt_consumed(record)
                and _claim_receipt(record, historical_key)
            ):
                _pop_historical_unmatched(historical_key)
                _pop_historical_open(historical_key)
                historical_reconciled_keys.add(historical_key)
                reconciled_counts[retention_pair[0]] += 1
                reconciled_records.append(record)
            else:
                # Resolve the referenced historical intent by its immutable digest
                # before trusting the reconciliation's claimed plan/attempt or
                # receipt. Ambiguous identity order and receipt reuse therefore
                # remain visible as HIGH execution gaps.
                _remember_historical_unmatched(
                    historical_key,
                    historical_record,
                    historical_timestamp,
                )
            continue

        if operation == retention_pair[1]:
            completion_fields_present = _audit_transition_identity_fields_present(
                retention_pair[0], record
            )
            identity = _retention_transition_identity(record)
            matched = False
            if completion_fields_present:
                if identity is not None and not _receipt_consumed(record):
                    latest_key = _latest_open_retention_key(identity)
                    if latest_key is not None and _claim_receipt(record, latest_key):
                        if latest_key in pending_retention:
                            _pop_pending_retention(latest_key)
                        else:
                            _pop_historical_open(latest_key)
                            _pop_historical_unmatched(latest_key)
                            historical_completed_keys.add(latest_key)
                        matched = True
            else:
                match_index = _audit_transition_match_index(
                    retention_pair[0], pending[retention_pair], record
                )
                if match_index is not None:
                    pending[retention_pair].pop(match_index)
                    matched = True
            if matched:
                completed_counts[retention_pair[0]] += 1
            continue

        for intent, completion in AUDIT_TRANSITION_PAIRS:
            key = (intent, completion)
            if key == retention_pair:
                continue
            if operation == intent:
                pending[key].append((record, timestamp_unix))
                break
            if operation == completion:
                match_index = _audit_transition_match_index(
                    intent, pending[key], record
                )
                if match_index is not None:
                    pending[key].pop(match_index)
                    completed_counts[intent] += 1
                break

    gaps: list[tuple[str, dict[str, Any], int]] = list(
        historical_unmatched.values()
    )
    for record, timestamp_unix in pending_retention.values():
        if timestamp_unix <= end_unix - AUDIT_SIGNAL_GRACE_SECONDS:
            gaps.append((retention_pair[0], record, timestamp_unix))
    for (intent, _completion), entries in pending.items():
        for record, timestamp_unix in entries:
            if timestamp_unix <= end_unix - AUDIT_SIGNAL_GRACE_SECONDS:
                gaps.append((intent, record, timestamp_unix))

    by_transition = Counter(intent for intent, _record, _timestamp in gaps)
    execution_refs = [
        ref
        for _intent, record, _timestamp in gaps
        if (ref := _audit_record_ref(record))
    ]
    execution_gap_refs, execution_gap_refs_truncated = _audit_signal_refs(
        execution_refs
    )
    unique_execution_ref_count = len(set(ref for ref in execution_refs if ref))
    reconciliation_refs_all = [
        ref for record in reconciled_records if (ref := _audit_record_ref(record))
    ]
    reconciliation_refs, reconciliation_refs_truncated = _audit_signal_refs(
        reconciliation_refs_all
    )
    unique_reconciliation_ref_count = len(
        set(ref for ref in reconciliation_refs_all if ref)
    )
    observed_count = len(gaps) + len(reconciled_records)
    if gaps:
        severity = "high"
        count = len(gaps)
        primary_evidence_refs = execution_refs
        recommended_action = "trace each unmatched intent and read the exact target state before retry"
    elif reconciled_records:
        severity = "medium"
        count = len(reconciled_records)
        primary_evidence_refs = reconciliation_refs_all
        recommended_action = (
            "review append-only completion-audit reconciliation evidence; "
            "do not retry the retention effect"
        )
    else:
        severity = "none"
        count = 0
        primary_evidence_refs = []
        recommended_action = "none"
    return _audit_signal_entry(
        "transition_gap",
        status="observed" if observed_count else "clear",
        severity=severity,
        count=count,
        observed_count=observed_count,
        evidence_refs=primary_evidence_refs,
        evidence_quality=(
            "explicit_identity_with_terminal_receipt_reconciliation_and_legacy_fifo_fallback"
        ),
        recommended_action=recommended_action,
        details={
            "grace_seconds": AUDIT_SIGNAL_GRACE_SECONDS,
            "execution_gap_count": len(gaps),
            "completion_audit_gap_count": len(reconciled_records),
            "count_semantics": "execution_gaps_when_present_else_completion_audit_gaps",
            "observed_count_semantics": "execution_gaps_plus_completion_audit_gaps",
            "execution_gap_evidence_refs": execution_gap_refs,
            "execution_gap_evidence_refs_truncated": execution_gap_refs_truncated,
            "execution_gap_evidence_refs_omitted_count": max(
                0, unique_execution_ref_count - len(execution_gap_refs)
            ),
            "unmatched_intents_by_transition": dict(sorted(by_transition.items())),
            "completed_pairs_by_transition": dict(sorted(completed_counts.items())),
            "completion_audit_gaps_by_transition": dict(sorted(reconciled_counts.items())),
            "completion_audit_gap_evidence_refs": reconciliation_refs,
            "completion_audit_gap_evidence_refs_truncated": reconciliation_refs_truncated,
            "completion_audit_gap_evidence_refs_omitted_count": max(
                0, unique_reconciliation_ref_count - len(reconciliation_refs)
            ),
            "pairing_semantics": (
                "retention identities are indexed by (plan_sha256, attempt, "
                "intent_record_sha256); completions and reconciliations consume "
                "exactly the latest still-open intent in verified audit order; "
                "a valid terminal receipt may be consumed at most once; "
                "append-only reconciliations still bind the exact indexed intent; "
                "invalid, ambiguously ordered, or receipt-reusing reconciliation "
                "evidence keeps the affected intent visible as an execution_gap; "
                "records with both identity fields absent retain legacy FIFO behavior; "
                "other transition families use FIFO"
            ),
        },
        does_not_establish=[
            "effect_absence_outside_the_audit_chain",
            "causality",
            "safe_retry",
            "exact_cross-operation_identity_when_no_transaction_id_is_logged",
            "that_the_original_completion_audit_record_existed",
            "cause_of_the_completion_audit_gap",
        ],
    )
''',
)

test_path = Path("tests/test_pr992_retention_receipt_pairing.py")
if test_path.exists():
    raise RuntimeError("PR992 regression test path already exists")
test_path.write_text(r'''from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import grabowski_audit_signal as signal  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "maintain_runtime_state_pr992_pairing_test",
    ROOT / "tools" / "maintain_runtime_state.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load runtime retention module")
RETENTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RETENTION)


class RetentionReconciliationAdmissionTests(unittest.TestCase):
    PLAN = "1" * 64
    RECEIPT = "2" * 64
    INTENT_A = "a" * 64
    INTENT_B = "b" * 64
    COMPLETION = "c" * 64
    RECONCILIATION = "d" * 64

    def _item(self, digest: str, record: dict[str, object]) -> dict[str, object]:
        return {"evidence": {"record_sha256": digest}, "record": record}

    def _intent(self, digest: str) -> dict[str, object]:
        return self._item(
            digest,
            {
                "operation": "runtime-state-retention-intent",
                "plan_sha256": self.PLAN,
                "attempt": 1,
            },
        )

    def _completion(self) -> dict[str, object]:
        return self._item(
            self.COMPLETION,
            {
                "operation": "runtime-state-retention-complete",
                "plan_sha256": self.PLAN,
                "attempt": 1,
                "receipt_sha256": self.RECEIPT,
                "completed": True,
            },
        )

    def _reconciliation(self, intent_digest: str) -> dict[str, object]:
        return self._item(
            self.RECONCILIATION,
            {
                "operation": RETENTION.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                "plan_sha256": self.PLAN,
                "attempt": 1,
                "intent_record_sha256": intent_digest,
                "receipt_sha256": self.RECEIPT,
                "reconciliation_kind": "completion_audit_gap",
                "completed": True,
                "retention_effect_retried": False,
            },
        )

    def _state(self, items: list[dict[str, object]], *, target: str) -> dict[str, object]:
        fake_query = types.ModuleType("grabowski_audit_query")
        fake_query.capture_verified_audit_snapshot = lambda: object()
        fake_query._iter_snapshot_items = lambda _snapshot, order: iter(items)
        with patch.dict(sys.modules, {"grabowski_audit_query": fake_query}):
            return RETENTION._retention_audit_reconciliation_state(
                intent_record_sha256=target,
                plan_sha256=self.PLAN,
                attempt=1,
                receipt_sha256=self.RECEIPT,
            )

    def test_terminal_receipt_only_admits_latest_open_duplicate_intent(self) -> None:
        items = [self._intent(self.INTENT_A), self._intent(self.INTENT_B)]
        with self.assertRaisesRegex(RuntimeError, "ambiguous among duplicate intents"):
            self._state(items, target=self.INTENT_A)
        state = self._state(items, target=self.INTENT_B)
        self.assertIsNone(state["original_completion"])
        self.assertIsNone(state["existing_reconciliation"])

    def test_completion_consumes_latest_duplicate_only(self) -> None:
        items = [
            self._intent(self.INTENT_A),
            self._intent(self.INTENT_B),
            self._completion(),
        ]
        with self.assertRaisesRegex(RuntimeError, "already bound to another intent"):
            self._state(items, target=self.INTENT_A)
        state = self._state(items, target=self.INTENT_B)
        self.assertEqual(state["original_completion"]["record_sha256"], self.COMPLETION)
        self.assertIsNone(state["existing_reconciliation"])

    def test_existing_reconciliation_consumes_latest_duplicate_only(self) -> None:
        items = [
            self._intent(self.INTENT_A),
            self._intent(self.INTENT_B),
            self._reconciliation(self.INTENT_B),
        ]
        with self.assertRaisesRegex(RuntimeError, "already bound to another intent"):
            self._state(items, target=self.INTENT_A)
        state = self._state(items, target=self.INTENT_B)
        self.assertEqual(
            state["existing_reconciliation"]["record_sha256"],
            self.RECONCILIATION,
        )
        self.assertIsNone(state["original_completion"])

    def test_reconciliation_claiming_older_duplicate_is_rejected(self) -> None:
        items = [
            self._intent(self.INTENT_A),
            self._intent(self.INTENT_B),
            self._reconciliation(self.INTENT_A),
        ]
        with self.assertRaisesRegex(RuntimeError, "ambiguous among duplicate intents"):
            self._state(items, target=self.INTENT_A)


class RetentionSignalReceiptConsumptionTests(unittest.TestCase):
    def _intent(self, digest: str, now: int) -> tuple[dict[str, object], int]:
        return (
            {
                "operation": "runtime-state-retention-intent",
                "record_sha256": digest,
                "plan_sha256": "1" * 64,
                "attempt": 1,
            },
            now,
        )

    def _reconciliation(
        self,
        *,
        digest: str,
        intent_digest: str,
        receipt_digest: str,
        now: int,
    ) -> tuple[dict[str, object], int]:
        return (
            {
                "operation": signal.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                "record_sha256": digest,
                "plan_sha256": "1" * 64,
                "attempt": 1,
                "intent_record_sha256": intent_digest,
                "receipt_sha256": receipt_digest,
                "reconciliation_kind": "completion_audit_gap",
                "completed": True,
                "retention_effect_retried": False,
            },
            now,
        )

    def _completion(
        self,
        *,
        digest: str,
        receipt_digest: str,
        now: int,
    ) -> tuple[dict[str, object], int]:
        return (
            {
                "operation": "runtime-state-retention-complete",
                "record_sha256": digest,
                "plan_sha256": "1" * 64,
                "attempt": 1,
                "receipt_sha256": receipt_digest,
                "completed": True,
            },
            now,
        )

    def _signal(
        self,
        records: list[tuple[dict[str, object], int]],
        now: int,
    ) -> dict[str, object]:
        return signal._audit_transition_gap_signal(
            records,
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )

    def test_same_receipt_cannot_reconcile_two_duplicate_intents(self) -> None:
        now = 1_800_000_000
        receipt = "9" * 64
        intent_a = "a" * 64
        intent_b = "b" * 64
        result = self._signal(
            [
                self._intent(intent_a, now - 1_000),
                self._intent(intent_b, now - 999),
                self._reconciliation(
                    digest="c" * 64,
                    intent_digest=intent_b,
                    receipt_digest=receipt,
                    now=now - 998,
                ),
                self._reconciliation(
                    digest="d" * 64,
                    intent_digest=intent_a,
                    receipt_digest=receipt,
                    now=now - 997,
                ),
            ],
            now,
        )
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["details"]["execution_gap_count"], 1)
        self.assertEqual(result["details"]["completion_audit_gap_count"], 1)
        self.assertEqual(
            result["details"]["execution_gap_evidence_refs"],
            ["audit-record-sha256:" + intent_a],
        )

    def test_completion_receipt_cannot_be_reused_by_reconciliation(self) -> None:
        now = 1_800_000_000
        receipt = "8" * 64
        intent_a = "a" * 64
        intent_b = "b" * 64
        result = self._signal(
            [
                self._intent(intent_a, now - 1_000),
                self._intent(intent_b, now - 999),
                self._completion(
                    digest="c" * 64,
                    receipt_digest=receipt,
                    now=now - 998,
                ),
                self._reconciliation(
                    digest="d" * 64,
                    intent_digest=intent_a,
                    receipt_digest=receipt,
                    now=now - 997,
                ),
            ],
            now,
        )
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["details"]["execution_gap_count"], 1)
        self.assertEqual(result["details"]["completion_audit_gap_count"], 0)
        self.assertEqual(
            result["details"]["completed_pairs_by_transition"],
            {"runtime-state-retention-intent": 1},
        )

    def test_reconciliation_must_target_latest_open_duplicate(self) -> None:
        now = 1_800_000_000
        intent_a = "a" * 64
        intent_b = "b" * 64
        result = self._signal(
            [
                self._intent(intent_a, now - 1_000),
                self._intent(intent_b, now - 999),
                self._reconciliation(
                    digest="c" * 64,
                    intent_digest=intent_a,
                    receipt_digest="7" * 64,
                    now=now - 998,
                ),
            ],
            now,
        )
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["details"]["execution_gap_count"], 2)
        self.assertEqual(result["details"]["completion_audit_gap_count"], 0)


if __name__ == "__main__":
    unittest.main()
''', encoding="utf-8")
