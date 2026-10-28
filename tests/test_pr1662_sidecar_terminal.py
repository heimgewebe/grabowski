"""PR1662: an authentic completed cutover can retire only after sidecar repair."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import test_self_deploy as source
import test_midcutover_resume as fixture

SD = source.SELF_DEPLOY
RUNNER = source.RUNNER


class CompletedCutoverSidecarRetirement(unittest.TestCase):
    def test_completed_cutover_requires_current_release_and_repaired_sidecars(self):
        original = fixture.cutover_receipt(outcome="completed", phase="completed")
        final_routing = {
            "selected_slot": "canonical",
            "release_id": fixture.GREEN_RELEASE,
            "repo_head": fixture.HEAD_GREEN,
            "selector_sha256": "cc" * 32,
        }
        readback = {
            "authoritative": True,
            "selector": dict(final_routing),
            "ingress": dict(final_routing),
        }
        readback["readback_sha256"] = SD._sha256_json(readback)
        original.update(final_routing=final_routing, authoritative_readback=readback)
        original["receipt_sha256"] = SD._sha256_json({
            k: v for k, v in original.items() if k != "receipt_sha256"
        })
        repo = Path("/home/alex/repos/grabowski")
        command = SD._deploy_command(
            repo, repo / SD.RUNNER_RELATIVE_PATH, fixture.HEAD_GREEN, 8,
            source_identity_sha256=fixture.SOURCE_IDENTITY_SHA256,
        )
        sha = SD._deploy_command_sha256(command)
        unit = "grabowski-job-220022002200"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            job = root / "jobs" / unit
            receipt_root = root / "cutovers"
            job.mkdir(parents=True, mode=0o700)
            receipt_root.mkdir(mode=0o700)
            target = receipt_root / f"{original['cutover_id']}.json"
            target.write_text(json.dumps(original), encoding="utf-8")
            target.chmod(0o600)
            paths = {key: str(job / file) for key, file in (
                ("metadata", "metadata.json"), ("stdout", "stdout.log"),
                ("stderr", "stderr.log"), ("finalization", "finalization.json"),
            )}
            metadata = {
                "unit": unit, "job_id": unit.removeprefix("grabowski-job-"),
                "argv": command, "argv_sha256": sha, "cwd": str(repo),
                "final_status": "launch_submitted",
                "finalization_contract": {
                    "kind": "grabowski_runtime_deploy_finalization",
                    "unit": unit, "job_id": unit.removeprefix("grabowski-job-"),
                    "argv_sha256": sha, "expected_head": fixture.HEAD_GREEN,
                    "receipt_paths": paths,
                },
            }
            summary = RUNNER._blue_green_summary({
                "receipt": original, "receipt_persisted": True,
                "receipt_path": str(target),
            })
            material = {
                "schema_version": 1,
                "kind": "grabowski_runtime_deploy_finalization",
                "unit": unit, "job_id": metadata["job_id"],
                "argv_sha256": sha, "expected_head": fixture.HEAD_GREEN,
                "receipt_paths": paths, "final_status": "failed",
                "completion_status": "failed",
                "repo_head": None, "release_id": None,
                "failure_type": "SidecarInstallOutstanding",
                "blue_green": summary,
                "blue_green_receipt_sha256": original["receipt_sha256"],
                "blind_retry_allowed": None, "timestamp_unix": 1000,
            }
            payload = {**material, "payload_sha256": SD._sha256_json(material)}
            raw = json.dumps(payload, sort_keys=True).encode()
            status = {
                "final_status": "failed",
                "finalization_receipt": {
                    "valid": True, "state": "valid", "final_status": "failed",
                    "expected_head": fixture.HEAD_GREEN,
                    "receipt_sha256": hashlib.sha256(raw).hexdigest(),
                    "payload_sha256": payload["payload_sha256"],
                    "blue_green_receipt_sha256": original["receipt_sha256"],
                    "blind_retry_allowed": None,
                },
            }
            integrity_keys = (
                "manifest_parse_valid", "manifest_schema_valid", "release_path_valid",
                "release_id_valid", "repo_head_valid", "stable_runtime_manifest_valid",
                "runtime_pointer_valid", "artifact_integrity_valid",
                "runtime_asset_identity_valid", "release_python_identity_valid",
                "runtime_binding_valid", "environment_compatibility_valid",
                "provenance_valid",
            )
            deployed = {
                "completion_status": "complete",
                "repo_head": fixture.HEAD_GREEN,
                "release_id": fixture.GREEN_RELEASE,
                **{k: True for k in integrity_keys},
            }
            loader = SD.midcutover.load_receipts
            with (
                mock.patch.object(SD.midcutover, "load_receipts",
                                  side_effect=lambda: loader(receipt_root)),
                mock.patch.object(SD.operator, "_read_finalization_receipt_file",
                                  return_value={"ok": True, "raw": raw}, create=True),
                mock.patch.object(SD.base, "_deployment_metadata", create=True,
                                  return_value=deployed),
                mock.patch.object(SD, "_sidecars_match_deploy_head",
                                  return_value=True) as checked,
            ):
                self.assertTrue(
                    SD._verified_runtime_terminal_receipt(job, metadata, command, status),
                    "completed blue-green with real verified repaired sidecars should retire",
                )
                checked.assert_called()
                with mock.patch.object(SD, "_sidecars_match_deploy_head", return_value=False):
                    self.assertFalse(SD._verified_runtime_terminal_receipt(
                        job, metadata, command, status
                    ), "missing or unreconciled sidecars must keep the old job blocking")
                with mock.patch.object(SD.base, "_deployment_metadata", create=True,
                                       return_value={**deployed, "release_id": fixture.BLUE_RELEASE}):
                    self.assertFalse(SD._verified_runtime_terminal_receipt(
                        job, metadata, command, status
                    ), "a foreign live release is not this completed cutover")
                with mock.patch.object(SD.midcutover, "unresolved_post_switch_receipts",
                                       return_value=[fixture.cutover_receipt()]):
                    self.assertFalse(SD._verified_runtime_terminal_receipt(
                        job, metadata, command, status
                    ), "a competing unresolved cutover blocks historical retirement")


if __name__ == "__main__":
    unittest.main()