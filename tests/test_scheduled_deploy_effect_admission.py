"""Fail-closed effect-time admission regressions for delayed runtime deploy.

No synthetic review PASS in these tests grants real deployment authority.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import run_scheduled_deploy as worker  # noqa: E402

SERVING = "a" * 40
TARGET = "b" * 40
SOURCE_ID = "c" * 64


def active(head: str = SERVING, release: str = "release-blue") -> dict:
    """The actual trusted ingress observer uses canonical/green, never blue."""
    selector = {
        "selector_sha256": "2" * 64,
        "generation": 7,
        "selected_slot": "canonical",
        "upstream_port": 18181,
        "runtime_binding_sha256": "1" * 64,
        "release_id": release,
        "repo_head": head,
    }
    ingress = {
        "selector_sha256": "2" * 64,
        "selector_generation": 7,
        "selected_slot": "canonical",
        "upstream_port": 18181,
        "runtime_binding_sha256": "1" * 64,
        "repo_head": head,
        "release_id": release,
    }
    material = {"authoritative": True, "selector": selector, "ingress": ingress}
    return {**material, "readback_sha256": worker.canonical_json_sha256(material)}


class ScheduledGitObjectIdLengthTests(unittest.TestCase):
    def test_object_ids_are_exact_sha1_or_sha256_widths(self):
        # A 41–63-character hex value is neither a SHA-1 nor a SHA-256 OID.
        for valid_length in (40, 64):
            with self.subTest(valid=valid_length):
                self.assertIsNotNone(worker.OBJECT_ID_RE.fullmatch("a" * valid_length))
        for invalid_length in (0, 1, 39, 41, 52, 63, 65):
            with self.subTest(invalid=invalid_length):
                self.assertIsNone(worker.OBJECT_ID_RE.fullmatch("a" * invalid_length))
        self.assertIsNone(worker.OBJECT_ID_RE.fullmatch("A" * 40))


class DelayedRuntimeEffectAdmissionTests(unittest.TestCase):
    def test_worker_git_environment_neutralizes_git_odb_and_config_injections(self):
        """A delayed worker must not inherit alternate object stores, replace refs, or Git config."""
        injected = {
            "GIT_NO_REPLACE_OBJECTS": "0",
            "GIT_NO_LAZY_FETCH": "0",
            "GIT_DIR": "/tmp/foreign-git-dir",
            "GIT_WORK_TREE": "/tmp/foreign-git-tree",
            "GIT_COMMON_DIR": "/tmp/foreign-common",
            "GIT_INDEX_FILE": "/tmp/foreign-index",
            "GIT_OBJECT_DIRECTORY": "/tmp/foreign-odb",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/tmp/foreign-alternate",
            "GIT_NAMESPACE": "foreign",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": "foreign-fsmonitor",
            "GIT_CONFIG_PARAMETERS": "'core.fsmonitor=foreign'",
            "GIT_TRACE": "/tmp/foreign-git-trace",
        }
        for name in ("git_environment", "child_environment", "_validation_environment"):
            with self.subTest(builder=name), patch.dict(os.environ, injected):
                actual = (
                    worker._validation_environment(Path("/tmp/synthetic-validation"))
                    if name == "_validation_environment"
                    else getattr(worker, name)()
                )
                self.assertEqual("1", actual.get("GIT_NO_REPLACE_OBJECTS"))
                self.assertEqual("1", actual.get("GIT_NO_LAZY_FETCH"))
                self.assertEqual("0", actual.get("GIT_OPTIONAL_LOCKS"))
                for key in injected:
                    if key not in {"GIT_NO_REPLACE_OBJECTS", "GIT_NO_LAZY_FETCH"}:
                        self.assertNotIn(key, actual, f"{name} forwarded {key}")

    def test_real_git_replace_ref_does_not_hide_runtime_change_from_worker(self):
        """Exercise actual git diff, not only a patched subprocess object."""
        with tempfile.TemporaryDirectory(prefix="grabowski-delayed-worker-git-") as dirname:
            repo = Path(dirname)
            clean_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(repo)}

            def git(*argv: str) -> str:
                result = subprocess.run(
                    ["git", "-C", str(repo), *argv], check=True, timeout=12,
                    capture_output=True, text=True, env=clean_env,
                )
                return result.stdout.strip()

            git("init", "-q")
            (repo / "docs").mkdir()
            (repo / "docs" / "guide.md").write_text("stable\n", encoding="utf-8")
            git("add", "--", "docs/guide.md")
            git("-c", "user.name=Worker Fixture", "-c", "user.email=worker@invalid.example",
                "commit", "-qm", "original")
            original = git("rev-parse", "HEAD")
            (repo / "src").mkdir()
            (repo / "src" / "runtime.py").write_text("SOURCE_CHANGED = True\n", encoding="utf-8")
            git("add", "--", "src/runtime.py")
            git("-c", "user.name=Worker Fixture", "-c", "user.email=worker@invalid.example",
                "commit", "-qm", "runtime change")
            changed = git("rev-parse", "HEAD")
            git("replace", changed, original)
            self.assertEqual(
                "",
                subprocess.run(
                    ["git", "-C", str(repo), "diff", "--name-only", original, changed],
                    capture_output=True, text=True, check=True, env=clean_env, timeout=12,
                ).stdout.strip(),
            )
            with patch.dict(os.environ, clean_env, clear=True):
                observed = worker.run_capture(
                    ["git", "-C", str(repo), "diff", "--name-only", original, changed],
                    cwd=repo,
                )
            self.assertEqual("src/runtime.py", observed)

    def test_unchanged_serving_source_requires_authoritative_readback(self):
        with patch.object(worker.deploy_dual, "observe_authoritative_routing", return_value=active()):
            result = worker.require_effect_time_release_admission(
                expected_head=SERVING, source_identity_sha256=SOURCE_ID
            )
        self.assertEqual("already-serving-exact-source", result["status"])
        self.assertEqual(SERVING, result["serving_repo_head"])

    def test_green_slot_with_proven_authoritative_port_is_valid_already_serving(self):
        observed = active()
        observed["selector"]["selected_slot"] = "green"
        observed["ingress"]["selected_slot"] = "green"
        observed["selector"]["upstream_port"] = 18182
        observed["ingress"]["upstream_port"] = 18182
        material = {name: observed[name] for name in ("authoritative", "selector", "ingress")}
        observed["readback_sha256"] = worker.canonical_json_sha256(material)
        with patch.object(
            worker.deploy_dual, "observe_authoritative_routing", return_value=observed,
        ):
            result = worker.require_effect_time_release_admission(
                expected_head=SERVING, source_identity_sha256=SOURCE_ID
            )
        self.assertEqual("already-serving-exact-source", result["status"])

    def test_readback_rejects_consistently_missing_or_invalid_route_identities(self):
        """Even a self-consistent hash cannot license an incomplete selector."""
        invalid = (
            ("selected_slot", None),
            ("selected_slot", "blue"),
            ("selected_slot", ""),
            ("upstream_port", None),
            ("upstream_port", 0),
            ("upstream_port", 18182),
            ("upstream_port", True),
            ("generation", None),
            ("generation", False),
            ("generation", 0),
            ("runtime_binding_sha256", None),
            ("runtime_binding_sha256", "Z" * 64),
            ("runtime_binding_sha256", "1" * 63),
            ("selector_sha256", None),
            ("selector_sha256", "f" * 63),
        )
        for field, value in invalid:
            with self.subTest(field=field, value=value):
                observed = active()
                observed["selector"][field] = value
                ingress_field = "selector_generation" if field == "generation" else field
                observed["ingress"][ingress_field] = value
                material = {name: observed[name] for name in ("authoritative", "selector", "ingress")}
                observed["readback_sha256"] = worker.canonical_json_sha256(material)
                with patch.object(
                    worker.deploy_dual, "observe_authoritative_routing", return_value=observed,
                ):
                    with self.assertRaisesRegex(RuntimeError, "serving identity"):
                        worker.require_effect_time_release_admission(
                            expected_head=SERVING, source_identity_sha256=SOURCE_ID
                        )

    def test_readback_rejects_contradictory_selector_provenance(self):
        """The ingress and selector must agree beyond just the slot and binding."""
        mismatches = (
            ("selector_sha256", "f" * 64),
            ("generation", 8),
            ("upstream_port", 18182),
            ("repo_head", TARGET),
            ("release_id", "unrelated-release"),
        )
        for field, value in mismatches:
            with self.subTest(field=field):
                observed = active()
                observed["selector"][field] = value
                material = {name: observed[name] for name in ("authoritative", "selector", "ingress")}
                observed["readback_sha256"] = worker.canonical_json_sha256(material)
                with patch.object(
                    worker.deploy_dual, "observe_authoritative_routing", return_value=observed,
                ):
                    with self.assertRaisesRegex(RuntimeError, "serving identity"):
                        worker.require_effect_time_release_admission(
                            expected_head=SERVING, source_identity_sha256=SOURCE_ID
                        )

    def test_critical_change_requires_separate_protected_captain_authority(self):
        with patch.object(worker.deploy_dual, "observe_authoritative_routing", return_value=active()):
            with self.assertRaisesRegex(RuntimeError, "Captain|release admission|protected"):
                worker.require_effect_time_release_admission(
                    expected_head=TARGET, source_identity_sha256=SOURCE_ID
                )


    def test_sha256_git_object_ids_preserve_fail_closed_release_policy(self):
        serving_sha256 = "a" * 64
        target_sha256 = "b" * 64
        with patch.object(
            worker.deploy_dual, "observe_authoritative_routing",
            return_value=active(serving_sha256),
        ):
            result = worker.require_effect_time_release_admission(
                expected_head=serving_sha256, source_identity_sha256=SOURCE_ID
            )
            self.assertEqual("already-serving-exact-source", result["status"])
            self.assertEqual(serving_sha256, result["serving_repo_head"])
            with self.assertRaisesRegex(RuntimeError, "protected Captain"):
                worker.require_effect_time_release_admission(
                    expected_head=target_sha256, source_identity_sha256=SOURCE_ID
                )

    def test_nonstandard_git_object_id_lengths_rejected(self):
        for length in (39, 41, 63, 65):
            with self.subTest(target_length=length):
                with self.assertRaisesRegex(RuntimeError, "invalid exact target"):
                    worker.require_effect_time_release_admission(
                        expected_head="b" * length, source_identity_sha256=SOURCE_ID
                    )
            with self.subTest(serving_length=length), patch.object(
                worker.deploy_dual, "observe_authoritative_routing",
                return_value=active("a" * length),
            ):
                with self.assertRaisesRegex(RuntimeError, "serving identity"):
                    worker.require_effect_time_release_admission(
                        expected_head=SERVING, source_identity_sha256=SOURCE_ID
                    )

    def test_unauthenticated_or_unobservable_serving_blocks(self):
        for record in (
            None, {}, {"authoritative": False},
            {"authoritative": True, "ingress": {"repo_head": SERVING}},
            {"authoritative": True, "readback_sha256": "x" * 64,
             "ingress": {"repo_head": SERVING, "release_id": "release-blue"}},
            {"authoritative": True, "readback_sha256": "f" * 64,
             "ingress": {"repo_head": SERVING, "release_id": ""}},
        ):
            with self.subTest(record=record), patch.object(
                worker.deploy_dual, "observe_authoritative_routing", return_value=record
            ):
                with self.assertRaisesRegex(RuntimeError, "release admission|serving"):
                    worker.require_effect_time_release_admission(
                        expected_head=TARGET, source_identity_sha256=SOURCE_ID
                    )

    def test_replay_of_wrong_source_identity_blocks(self):
        with patch.object(worker.deploy_dual, "observe_authoritative_routing", return_value=active()):
            for value in ("", "f" * 40, "Z" * 64, None, True):
                with self.subTest(value=value):
                    with self.assertRaisesRegex(RuntimeError, "source identity"):
                        worker.require_effect_time_release_admission(
                            expected_head=TARGET, source_identity_sha256=value
                        )

    def test_delayed_wrapper_refuses_changed_release_before_start_green(self):
        with (
            patch.object(worker.deploy_dual, "observe_authoritative_routing", return_value=active()),
            patch.object(worker.deploy_dual, "run_production_blue_green_cutover") as effect,
        ):
            with self.assertRaisesRegex(RuntimeError, "Captain|release admission|protected"):
                worker.run_productive_blue_green(
                    repo=Path("/nonexistent-synthetic-target"),
                    expected_head=TARGET,
                    source_identity_sha256=SOURCE_ID,
                )
            effect.assert_not_called()

    def test_delayed_wrapper_reevaluates_serving_before_every_effect(self):
        with (
            patch.object(worker.deploy_dual, "observe_authoritative_routing", side_effect=[
                active(SERVING), active("d" * 40)
            ]) as readback,
            patch.object(worker.deploy_dual, "run_production_blue_green_cutover") as effect,
        ):
            for _ in range(2):
                with self.assertRaisesRegex(RuntimeError, "Captain|release admission|protected"):
                    worker.run_productive_blue_green(
                        repo=Path("/nonexistent-synthetic-target"),
                        expected_head=TARGET,
                        source_identity_sha256=SOURCE_ID,
                    )
            self.assertEqual(2, readback.call_count)
            effect.assert_not_called()


    def test_recovery_only_remains_separately_classified_without_productive_cutover(self):
        """A resume never turns into a fresh release; the effect gate is not a recovery substitute."""
        import sys
        decision = {
            "resume_required": True,
            "deploy_allowed": False,
            "resume_target_head": SERVING,
            "execution_head": TARGET,
            "classification": {"status": "resume-only"},
        }
        with (
            patch.object(sys, "argv", [
                "run_scheduled_deploy.py", "--repo", "/tmp/synthetic",
                "--canonical-repo", "/tmp/synthetic",
                "--source-kind", "canonical-main",
                "--source-identity-sha256", SOURCE_ID,
                "--expected-head", TARGET,
                "--delay-seconds", "5",
            ]),
            patch.object(worker, "load_finalization_binding", return_value=None),
            patch.object(worker, "assert_not_repoground_managed_source"),
            patch.object(worker, "emit"),
            patch.object(worker.time, "sleep"),
            patch.object(worker, "wait_for_deployment_window"),
            patch.object(worker, "run_streamed"),
            patch.object(worker, "verify_repository"),
            patch.object(worker, "classify_recovery_before_deploy", return_value=decision),
            patch.object(worker, "run_resume_only", return_value=0) as recovery,
            patch.object(worker, "run_productive_blue_green") as fresh_deploy,
        ):
            self.assertEqual(0, worker.main())
        recovery.assert_called_once()
        fresh_deploy.assert_not_called()


if __name__ == "__main__":
    unittest.main()