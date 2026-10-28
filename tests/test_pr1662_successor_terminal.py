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




if __name__ == "__main__":
    unittest.main()
