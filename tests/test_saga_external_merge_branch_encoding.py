from __future__ import annotations

import json
import unittest

import test_grips


class SagaExternalMergeBranchEncodingTests(unittest.TestCase):
    """Verify the actual closeout GitHub request encodes a whole branch segment."""

    def test_slash_containing_base_is_percent_encoded_in_branch_endpoint(self) -> None:
        fixture = test_grips.SagaExternalMergeCloseoutGripTests(
            "test_external_merge_writes_only_authenticated_terminal_audit"
        )
        fixture.setUp()
        try:
            target = dict(fixture.parameters["target"])
            target["base"] = "release/2026"
            fixture.plan = test_grips.grip_orchestration.build_plan(
                "pr-settlement", target, "external-merge-closeout-1371"
            )
            fixture.run = test_grips._saga_run_stub(fixture.plan)
            fixture.run_ref = test_grips._saga_run_audit_record(
                fixture.plan, run=fixture.run
            )[1]
            fixture.captain_ref = test_grips._saga_audit_records(
                fixture.plan, status="blocked"
            )[4]
            fixture.parameters.update(
                target=target,
                expected_plan_sha256=fixture.plan["plan_sha256"],
                run_receipt=fixture.run_ref,
                captain_result=fixture.captain_ref,
            )
            original_github = fixture.github
            expected_path = (
                "repos/heimgewebe/grabowski/branches/release%2F2026"
            )

            def github(repository, arguments):
                if arguments[:2] == ["pr", "view"]:
                    response = original_github(repository, arguments)
                    body = json.loads(response["stdout"])
                    body["baseRefName"] = "release/2026"
                    return {**response, "stdout": json.dumps(body)}
                if (
                    arguments[0] == "api"
                    and "/branches/" in arguments[1]
                ):
                    fixture.calls.append(arguments)
                    if arguments[1] != expected_path:
                        return {
                            "returncode": 1,
                            "stdout": "",
                            "stderr": "branch path component was not encoded",
                        }
                    return {
                        "returncode": 0,
                        "stdout": json.dumps(
                            {
                                "name": "release/2026",
                                "sha": fixture.current_sha,
                                "protected": True,
                            }
                        ),
                        "stderr": "",
                    }
                return original_github(repository, arguments)

            fixture.github = github
            result, append = fixture.run_closeout()
            self.assertEqual("passed", result["status"], result.get("output"))
            branch_reads = [
                args for args in fixture.calls
                if args[0] == "api" and "/branches/" in args[1]
            ]
            self.assertEqual(4, len(branch_reads))
            self.assertTrue(all(args[1] == expected_path for args in branch_reads))
            append.assert_called_once()
        finally:
            fixture.doCleanups()

class SagaExternalMergeAuditLookupDriftTests(unittest.TestCase):
    """A protected base drifted inside the potentially slow audit lookup."""

    def make_fixture(self):
        class DriftFixture(test_grips.SagaExternalMergeCloseoutGripTests):
            drift_enabled = False

            def __getattribute__(self, key):
                if (
                    key == "persisted_terminal"
                    and object.__getattribute__(self, "drift_enabled")
                    and object.__getattribute__(self, "branch_reads") >= 3
                ):
                    object.__setattr__(self, "current_sha", "f" * 40)
                return super().__getattribute__(key)

        fixture = DriftFixture(
            "test_external_merge_writes_only_authenticated_terminal_audit"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_drift_during_audit_search_never_appends_terminal(self):
        fixture = self.make_fixture()
        fixture.drift_enabled = True
        outcome, append = fixture.run_closeout()
        self.assertEqual("blocked", outcome["status"])
        self.assertEqual(4, fixture.branch_reads)
        append.assert_not_called()

    def test_verified_immutable_terminal_reuses_without_new_append(self):
        fixture = self.make_fixture()
        first, append = fixture.run_closeout()
        self.assertEqual("passed", first["status"])
        fixture.drift_enabled = True
        replay, _ = fixture.run_closeout(audit_append=append)
        self.assertEqual("passed", replay["status"], replay.get("output"))
        self.assertTrue(replay["output"]["terminal_audit_reused"])
        append.assert_called_once()
