"""PR #1662: a terminally repaired cutover stays settled after an authentic successor.

The original failed job and its persisted owner-private completed receipt are
already validated by _verified_runtime_terminal_receipt.  A later completed
blue-green receipt must not resurrect it during a fresh deploy-index census.
"""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

import test_self_deploy as source
import test_midcutover_resume as fixture

SD = source.SELF_DEPLOY
HEAD_C = "c" * 40
HEAD_D = "d" * 40
RELEASE_C = "cccccccccccc-srcset001122334455-lock556677889900-contractaabbccddeeff"
RELEASE_D = "dddddddddddd-srcset001122334455-lock556677889900-contractaabbccddeeff"
INTEGRITY = (
    "manifest_parse_valid", "manifest_schema_valid", "release_path_valid",
    "release_id_valid", "repo_head_valid", "stable_runtime_manifest_valid",
    "runtime_pointer_valid", "artifact_integrity_valid",
    "runtime_asset_identity_valid", "release_python_identity_valid",
    "runtime_binding_valid", "environment_compatibility_valid",
    "provenance_valid",
)


def completed(
    cutover_id: str, head: str, blue: str, green: str,
) -> dict[str, object]:
    receipt = fixture.cutover_receipt(
        cutover_id=cutover_id,
        expected_head=head,
        blue_release_id=blue,
        green_release_id=green,
        outcome="completed",
        phase="completed",
    )
    routing = {
        "selected_slot": "canonical",
        "release_id": green,
        "repo_head": head,
        "selector_sha256": "cc" * 32,
    }
    readback = {
        "authoritative": True, "selector": dict(routing),
        "ingress": dict(routing),
    }
    readback["readback_sha256"] = SD._sha256_json(readback)
    receipt.update(final_routing=routing, authoritative_readback=readback)
    receipt["receipt_sha256"] = SD._sha256_json({
        k: v for k, v in receipt.items() if k != "receipt_sha256"
    })
    return receipt


class CompletedSuccessorTerminalTests(unittest.TestCase):
    def setUp(self):
        self.a = completed(
            fixture.CUTOVER_ID, fixture.HEAD_GREEN,
            fixture.BLUE_RELEASE, fixture.GREEN_RELEASE,
        )
        self.b = completed(
            "bgc-successor-b", HEAD_C,
            fixture.GREEN_RELEASE, RELEASE_C,
        )
        self.c = completed(
            "bgc-successor-c", HEAD_D, RELEASE_C, RELEASE_D,
        )
        self.fields = {
            "source_kind": "git-revision",
            "canonical_repository": str(SD.CANONICAL_REPOSITORY),
            "expected_head": fixture.HEAD_GREEN,
            "source_identity_sha256": fixture.SOURCE_IDENTITY_SHA256,
        }

    def result(self, receipts, *, release=RELEASE_C, head=HEAD_C,
               sidecars=True, deployment_integrity=True):
        deployed = {
            "completion_status": "complete", "release_id": release,
            "repo_head": head,
            **{k: deployment_integrity for k in INTEGRITY},
        }
        with (
            mock.patch.object(SD.base, "_deployment_metadata",
                              return_value=deployed, create=True),
            mock.patch.object(SD, "_sidecars_match_deploy_head",
                              return_value=sidecars) as checked,
        ):
            result = SD._repaired_completed_sidecars_are_terminal(
                self.a, receipts, self.fields,
            )
        return result, checked.call_args_list

    def test_one_authentic_completed_successor_keeps_old_job_terminal(self):
        terminal, checks = self.result([self.a, self.b])
        self.assertTrue(terminal)
        self.assertTrue(checks)
        self.assertEqual(checks[-1].args[0]["expected_head"], HEAD_C)

    def test_chain_to_next_authentic_completed_successor_is_terminal(self):
        terminal, checks = self.result(
            [self.a, self.b, self.c], release=RELEASE_D, head=HEAD_D,
        )
        self.assertTrue(terminal)
        self.assertEqual(checks[-1].args[0]["expected_head"], HEAD_D)

    def test_foreign_blue_release_or_missing_chain_stays_blocked(self):
        unrelated = completed(
            "bgc-unrelated", HEAD_C, fixture.BLUE_RELEASE, RELEASE_C,
        )
        self.assertFalse(self.result([self.a, unrelated])[0])
        self.assertFalse(self.result([self.a])[0])

    def _clean_rolled_back_sibling(self):
        rollback = fixture.cutover_receipt(
            cutover_id="bgc-rolledback-b1",
            expected_head=HEAD_D,
            blue_release_id=fixture.GREEN_RELEASE,
            green_release_id=RELEASE_D,
            outcome="rolled_back",
            phase="rolled_back",
            switched=False,
        )
        selector = {
            "selected_slot": "canonical",
            "release_id": fixture.GREEN_RELEASE,
            "repo_head": fixture.HEAD_GREEN,
        }
        readback = {
            "authoritative": True, "selector": dict(selector),
            "ingress": dict(selector),
        }
        readback["readback_sha256"] = SD._sha256_json(readback)
        rollback.update(
            selector_switch=None,
            snapshot_rebind=None,
            retirement=None,
            final_routing=None,
            authoritative_readback=readback,
            recovery={
                "action": "retry_from_clean_blue",
                "blue_preserved": True,
                "rollback": {"blue_preserved": True},
                "platform_publication_rollback": {
                    "state": "no_prepared_request_effect",
                },
            },
        )
        rollback["receipt_sha256"] = SD._sha256_json({
            key: value for key, value in rollback.items()
            if key != "receipt_sha256"
        })
        self.assertTrue(
            SD._signed_clean_blue_rollback_is_terminal(
                rollback, [self.a, rollback, self.b]
            )
        )
        return rollback

    def test_cleanly_rolled_back_sibling_does_not_fork_completed_successor(self):
        rollback = self._clean_rolled_back_sibling()
        terminal, checks = self.result([self.a, rollback, self.b])
        self.assertTrue(terminal, "a fully proven rollback B1 is not a competing deployment B2")
        self.assertEqual(checks[-1].args[0]["expected_head"], HEAD_C)

    def test_unproved_or_tampered_rollback_sibling_still_blocks_successor(self):
        rollback = self._clean_rolled_back_sibling()
        failed = {**rollback, "recovery": {
            **rollback["recovery"],
            "platform_publication_rollback": {
                "state": "failed", "error": "rollback was not confirmed",
            },
        }}
        mismatched_hash = {**rollback, "receipt_sha256": "0" * 64}
        wrong_blue_head = {
            **rollback,
            "authoritative_readback": {
                **rollback["authoritative_readback"],
                "selector": {
                    **rollback["authoritative_readback"]["selector"],
                    "repo_head": "f" * 40,
                },
                "ingress": {
                    **rollback["authoritative_readback"]["ingress"],
                    "repo_head": "f" * 40,
                },
            },
        }
        wrong_blue_head["authoritative_readback"]["readback_sha256"] = SD._sha256_json({
            k: v for k, v in wrong_blue_head["authoritative_readback"].items()
            if k != "readback_sha256"
        })
        wrong_blue_head["receipt_sha256"] = SD._sha256_json({
            k: v for k, v in wrong_blue_head.items() if k != "receipt_sha256"
        })
        self.assertTrue(
            SD._signed_clean_blue_rollback_is_terminal(
                wrong_blue_head, [self.a, wrong_blue_head, self.b]
            ),
            "generic clean blue predicate alone does not prove the predecessor head",
        )
        for sibling in (failed, mismatched_hash, wrong_blue_head):
            with self.subTest(
                state=sibling.get("recovery", {}).get(
                    "platform_publication_rollback", {}
                ).get("state"),
                blue_head=sibling.get("authoritative_readback", {}).get(
                    "selector", {}
                ).get("repo_head"),
            ):
                self.assertFalse(self.result([self.a, sibling, self.b])[0])

    def test_unfinished_tampered_or_ambiguous_successor_stays_blocked(self):
        unknown = {**self.b, "outcome": "outcome_unknown", "phase": "outcome_unknown"}
        tampered = {**self.b, "green_release_id": RELEASE_D}
        alternative = completed(
            "bgc-successor-branch", HEAD_D, fixture.GREEN_RELEASE, RELEASE_D,
        )
        for receipts in (
            [self.a, unknown],
            [self.a, tampered],
            [self.a, self.b, alternative],
        ):
            with self.subTest(receipt_count=len(receipts)):
                self.assertFalse(self.result(receipts)[0])

    def test_incomplete_current_sidecars_or_runtime_integrity_blocks(self):
        self.assertFalse(self.result([self.a, self.b], sidecars=False)[0])
        self.assertFalse(self.result(
            [self.a, self.b], deployment_integrity=False
        )[0])
        self.assertFalse(self.result(
            [self.a, self.b], release=fixture.GREEN_RELEASE, head=HEAD_C
        )[0])

    def test_existing_direct_repair_remains_terminal_and_missing_repair_blocks(self):
        self.assertTrue(self.result(
            [self.a], release=fixture.GREEN_RELEASE, head=fixture.HEAD_GREEN
        )[0])
        self.assertFalse(self.result(
            [self.a], release=fixture.GREEN_RELEASE,
            head=fixture.HEAD_GREEN, sidecars=False
        )[0])

    def test_full_census_rebuild_retires_old_authenticated_job_after_successor(self):
        """Prove the real bootstrap calls the terminal predicate, not just a helper."""
        import hashlib
        import json
        import tempfile

        repo = Path("/home/alex/repos/grabowski")
        unit = "grabowski-job-330033003300"
        command = SD._deploy_command(
            repo, repo / SD.RUNNER_RELATIVE_PATH, fixture.HEAD_GREEN, 8,
            source_identity_sha256=fixture.SOURCE_IDENTITY_SHA256,
        )
        argv_sha256 = SD._deploy_command_sha256(command)
        with tempfile.TemporaryDirectory(prefix="successor-rebuild-") as folder:
            root = Path(folder) / "jobs"
            entry = root / unit
            entry.mkdir(parents=True, mode=0o700)
            paths = {key: str(entry / filename) for key, filename in (
                ("metadata", "metadata.json"), ("stdout", "stdout.log"),
                ("stderr", "stderr.log"), ("finalization", "finalization.json"),
            )}
            metadata = {
                "unit": unit, "job_id": unit.removeprefix("grabowski-job-"),
                "argv": command, "argv_sha256": argv_sha256,
                "cwd": str(repo), "final_status": "launch_submitted",
                "finalization_contract": {
                    "kind": "grabowski_runtime_deploy_finalization",
                    "unit": unit, "job_id": unit.removeprefix("grabowski-job-"),
                    "argv_sha256": argv_sha256,
                    "expected_head": fixture.HEAD_GREEN,
                    "receipt_paths": paths,
                },
            }
            summary = source.RUNNER._blue_green_summary({
                "receipt": self.a, "receipt_persisted": True,
                "receipt_path": str(entry / "blue-green.json"),
            })
            material = {
                "schema_version": 1,
                "kind": "grabowski_runtime_deploy_finalization",
                "unit": unit, "job_id": metadata["job_id"],
                "argv_sha256": argv_sha256,
                "expected_head": fixture.HEAD_GREEN,
                "receipt_paths": paths,
                "final_status": "failed", "completion_status": "failed",
                "repo_head": None, "release_id": None,
                "failure_type": "RuntimeError",
                "blue_green": summary,
                "blue_green_receipt_sha256": self.a["receipt_sha256"],
                "blind_retry_allowed": None, "timestamp_unix": 1000,
            }
            payload = {
                **material, "payload_sha256": SD._sha256_json(material),
            }
            raw = json.dumps(payload, sort_keys=True).encode()
            (entry / "finalization.json").write_bytes(raw)
            (entry / "finalization.json").chmod(0o600)
            status = {
                "final_status": "failed",
                "finalization_receipt": {
                    "valid": True, "state": "valid", "final_status": "failed",
                    "expected_head": fixture.HEAD_GREEN,
                    "receipt_sha256": hashlib.sha256(raw).hexdigest(),
                    "payload_sha256": payload["payload_sha256"],
                    "blue_green_receipt_sha256": self.a["receipt_sha256"],
                    "blind_retry_allowed": None,
                },
            }
            deployed = {
                "completion_status": "complete",
                "release_id": RELEASE_C, "repo_head": HEAD_C,
                **{key: True for key in INTEGRITY},
            }
            with (
                mock.patch.object(SD.operator, "_read_job_metadata", return_value=metadata),
                mock.patch.object(SD.operator, "grabowski_job_status", return_value=status),
                mock.patch.object(SD.operator, "_read_finalization_receipt_file",
                                  return_value={"ok": True, "raw": raw}, create=True),
                mock.patch.object(SD.midcutover, "load_receipts", return_value={
                    "present": True, "unreadable": [], "receipts": [self.a, self.b],
                }),
                mock.patch.object(SD.base, "_deployment_metadata",
                                  return_value=deployed, create=True),
                mock.patch.object(SD, "_sidecars_match_deploy_head",
                                  return_value=True),
                mock.patch.object(SD, "_write_deploy_index") as write,
            ):
                result = SD._bootstrap_deploy_index(root, read_only=True)
                self.assertEqual(result["units"], [])
                self.assertIsNone(result["pending_unit"])
                write.assert_not_called()
            self.assertFalse(SD._deploy_index_path(root).exists())




class NeverStartedDeployContractTests(unittest.TestCase):
    def _original_nonstart(self):
        from test_pr1662_nonstarted_resume import NeverStartedResumeReservationTests
        case = NeverStartedResumeReservationTests(
            "test_launch_failed_after_verified_nonstart_can_retire_promoted_reservation"
        )
        case.setUp()
        self.addCleanup(case.doCleanups)
        repo = case.REPOSITORY
        command = SD._deploy_command(
            repo, repo / SD.RUNNER_RELATIVE_PATH, case.HEAD, 8,
            source_identity_sha256=fixture.SOURCE_IDENTITY_SHA256,
        )
        sha = SD._deploy_command_sha256(command)
        case.meta["argv"] = command
        case.meta["argv_sha256"] = sha
        case.meta["finalization_contract"] = {
            "kind": "grabowski_runtime_deploy_finalization",
            "unit": case.UNIT,
            "job_id": case.meta["job_id"],
            "argv_sha256": sha,
            "expected_head": case.HEAD,
            "receipt_paths": {
                key: str(case.entry / filename) for key, filename in (
                    ("metadata", "metadata.json"), ("stdout", "stdout.log"),
                    ("stderr", "stderr.log"), ("finalization", "finalization.json"),
                )
            },
        }
        case.status["metadata"] = case.meta
        return case

    def test_real_scheduled_deploy_nonstart_is_terminal(self):
        case = self._original_nonstart()
        self.assertTrue(
            case._classify(),
            "genuine never-started scheduled deploy has the runtime finalization "
            "contract, not the generic job finalization contract",
        )
        with (
            mock.patch.object(SD.operator, "_read_job_metadata", return_value=case.meta),
            mock.patch.object(SD.operator, "grabowski_job_status", return_value=case.status),
            mock.patch.object(SD.operator, "_unit_dispatch_readback",
                              return_value=case.dispatch),
        ):
            result = SD._bootstrap_deploy_index(case.root, read_only=True)
        self.assertEqual(result["units"], [])

    def test_mismatched_contract_kind_head_or_dispatch_proof_blocks(self):
        from copy import deepcopy
        case = self._original_nonstart()
        self.assertFalse(case._classify(metadata={
            **case.meta, "finalization_contract": {
                **case.meta["finalization_contract"],
                "kind": "grabowski_job_finalization",
            }
        }, status={
            **case.status,
            "metadata": {
                **case.meta, "finalization_contract": {
                    **case.meta["finalization_contract"],
                    "kind": "grabowski_job_finalization",
                },
            },
        }))
        for key, malformed in (
            ("expected_head", "f" * 40),
            ("unit", "grabowski-job-000000000000"),
            ("argv_sha256", "0" * 64),
        ):
            changed = deepcopy(case.meta)
            changed["finalization_contract"][key] = malformed
            with self.subTest(field=key):
                self.assertFalse(case._classify(
                    metadata=changed, status={**case.status, "metadata": changed}
                ))
        self.assertFalse(case._classify(
            status={**case.status, "systemd_visible": True}
        ))


class PublicationRollbackTerminalProofTests(unittest.TestCase):
    def setUp(self):
        self.original = fixture.cutover_receipt(
            outcome="rolled_back", phase="rolled_back", switched=False,
        )
        selector = {
            "selected_slot": "canonical",
            "release_id": fixture.BLUE_RELEASE,
            "repo_head": fixture.HEAD_BLUE,
        }
        readback = {
            "authoritative": True,
            "selector": dict(selector), "ingress": dict(selector),
        }
        readback["readback_sha256"] = SD._sha256_json(readback)
        self.original.update(
            selector_switch=None,
            snapshot_rebind=None,
            retirement=None,
            final_routing=None,
            authoritative_readback=readback,
            recovery={
                "action": "retry_from_clean_blue",
                "blue_preserved": True,
                "rollback": {"blue_preserved": True},
                "platform_publication_rollback": {
                    "state": "no_prepared_request_effect",
                },
            },
        )
        self._rehash()

    def _rehash(self):
        self.original["receipt_sha256"] = SD._sha256_json({
            k: v for k, v in self.original.items() if k != "receipt_sha256"
        })

    def _check(self, publication):
        self.original["recovery"]["platform_publication_rollback"] = publication
        self._rehash()
        return SD._signed_clean_blue_rollback_is_terminal(
            self.original, [self.original]
        )

    def test_actual_effect_free_and_verified_rollback_are_terminal(self):
        self.assertTrue(self._check({"state": "no_prepared_request_effect"}))
        self.assertTrue(self._check({
            "state": "rolled_back", "request_id": "gpp-rolledback-123",
            "restored_request_id": None,
            "resolution_sha256": "a" * 64,
        }))

    def test_failed_unknown_empty_or_unproved_publication_rollback_is_not_terminal(self):
        bad = (
            {},
            {"state": "failed", "error": "publication rollback unconfirmed"},
            {"state": "publication_pending", "request_id": "gpp-pending"},
            {"state": "not_current", "request_id": "gpp-new", "idempotent": True},
            {"state": "rolled_back"},
            {"state": "rolled_back", "request_id": "gpp-rolledback-123"},
            {"state": "no_prepared_request_effect", "error": "conflict"},
        )
        for state in bad:
            with self.subTest(state=state.get("state")):
                self.assertFalse(self._check(state))




if __name__ == "__main__":
    unittest.main()
