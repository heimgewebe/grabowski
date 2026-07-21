from __future__ import annotations

import unittest

import grabowski_lifecycle_evidence as evidence


ALL_SOURCES = frozenset(evidence.REQUIRED_SOURCES)
SOURCE_SHA256S = {
    source: (format(index + 1, "x") * 64)
    for index, source in enumerate(sorted(ALL_SOURCES))
}


class LifecycleEvidenceAggregationTests(unittest.TestCase):
    def bundle(self, **overrides):
        values = {
            "identity": "task-a",
            "kind": "task",
            "observed_sources": ALL_SOURCES,
            "source_sha256s": SOURCE_SHA256S,
            "state": "completed",
            "closed": None,
            "receipt_integrity_valid": True,
        }
        values.update(overrides)
        return evidence.LifecycleObservationBundle(**values)

    def test_fully_observed_terminal_state_is_archivable(self) -> None:
        result = evidence.classify_observation_bundle(self.bundle())
        self.assertEqual(result["classification"], "terminal_archivable")
        self.assertTrue(result["safe_to_archive"])
        self.assertEqual(len(result["evidence_sha256"]), 64)

    def test_missing_process_observation_fails_closed(self) -> None:
        observed = ALL_SOURCES - {"process"}
        result = evidence.classify_observation_bundle(
            self.bundle(observed_sources=observed)
        )
        self.assertEqual(result["classification"], "ambiguous")
        self.assertIn(
            "observation_error:source_unobserved:process",
            result["reason_codes"],
        )

    def test_observed_source_without_digest_fails_closed(self) -> None:
        bindings = dict(SOURCE_SHA256S)
        bindings.pop("lease")
        result = evidence.classify_observation_bundle(
            self.bundle(source_sha256s=bindings)
        )
        self.assertEqual(result["classification"], "ambiguous")
        self.assertIn(
            "observation_error:source_unbound:lease",
            result["reason_codes"],
        )

    def test_open_workspace_role_is_active(self) -> None:
        result = evidence.classify_observation_bundle(
            self.bundle(kind="workspace", state=None, closed=True, open_task_role=True)
        )
        self.assertEqual(result["classification"], "active")
        self.assertIn("open_task_role", result["reason_codes"])

    def test_live_process_is_active(self) -> None:
        result = evidence.classify_observation_bundle(
            self.bundle(active_process=True)
        )
        self.assertEqual(result["classification"], "active")

    def test_active_exact_lease_blocks_archive(self) -> None:
        result = evidence.classify_observation_bundle(
            self.bundle(active_lease=True)
        )
        self.assertEqual(result["classification"], "blocking")
        self.assertIn("active_lease", result["reason_codes"])

    def test_dirty_checkout_is_untouchable(self) -> None:
        result = evidence.classify_observation_bundle(
            self.bundle(kind="checkout", state=None, closed=True, dirty=True)
        )
        self.assertEqual(result["classification"], "untouchable")

    def test_shared_workspace_reference_is_untouchable(self) -> None:
        result = evidence.classify_observation_bundle(
            self.bundle(kind="workspace", state=None, closed=True, shared_reference=True)
        )
        self.assertEqual(result["classification"], "untouchable")

    def test_active_foreign_retention_is_untouchable(self) -> None:
        result = evidence.classify_observation_bundle(
            self.bundle(
                kind="checkout",
                state=None,
                closed=True,
                foreign_retention=True,
                retention_expired=False,
            )
        )
        self.assertEqual(result["classification"], "untouchable")
        self.assertIn("foreign_retention", result["reason_codes"])

    def test_expired_foreign_retention_requires_recovery_archive(self) -> None:
        result = evidence.classify_observation_bundle(
            self.bundle(
                kind="checkout",
                state=None,
                closed=True,
                foreign_retention=True,
                retention_expired=True,
                retention_recovery_archived=False,
            )
        )
        self.assertEqual(result["classification"], "recovery_required")
        self.assertIn("retention_recovery_archive_required", result["reason_codes"])

    def test_expired_foreign_retention_with_recovery_archive_can_converge(self) -> None:
        result = evidence.classify_observation_bundle(
            self.bundle(
                kind="checkout",
                state=None,
                closed=True,
                foreign_retention=True,
                retention_expired=True,
                retention_recovery_archived=True,
            )
        )
        self.assertEqual(result["classification"], "terminal_archivable")

    def test_session_only_tmux_state_is_ambiguous_not_active(self) -> None:
        result = evidence.classify_observation_bundle(
            self.bundle(
                kind="workspace",
                state=None,
                closed=True,
                tmux_session_present=True,
                tmux_role_bound=False,
                active_process=False,
                open_task_role=False,
            )
        )
        self.assertEqual(result["classification"], "ambiguous")
        self.assertIn(
            "tmux_session_without_live_role_or_process",
            result["reason_codes"],
        )

    def test_role_bound_tmux_session_does_not_block_closed_state_by_itself(self) -> None:
        result = evidence.classify_observation_bundle(
            self.bundle(
                kind="workspace",
                state=None,
                closed=True,
                tmux_session_present=True,
                tmux_role_bound=True,
                open_task_role=False,
                active_process=False,
            )
        )
        self.assertEqual(result["classification"], "terminal_archivable")

    def test_unknown_process_observation_fails_closed(self) -> None:
        result = evidence.classify_observation_bundle(
            self.bundle(active_process=None)
        )
        self.assertEqual(result["classification"], "ambiguous")
        self.assertIn(
            "observation_unknown:active_process",
            result["reason_codes"],
        )

    def test_source_error_fails_closed(self) -> None:
        result = evidence.classify_observation_bundle(
            self.bundle(source_errors=("systemd-observation-failed",))
        )
        self.assertEqual(result["classification"], "ambiguous")
        self.assertIn(
            "observation_error:source_error:systemd-observation-failed",
            result["reason_codes"],
        )

    def test_evidence_digest_changes_with_bound_source(self) -> None:
        first = evidence.classify_observation_bundle(self.bundle())
        changed_bindings = dict(SOURCE_SHA256S)
        changed_bindings["process"] = "f" * 64
        second = evidence.classify_observation_bundle(
            self.bundle(source_sha256s=changed_bindings)
        )
        self.assertNotEqual(first["evidence_sha256"], second["evidence_sha256"])


if __name__ == "__main__":
    unittest.main()
