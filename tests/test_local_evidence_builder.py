from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "build_local_evidence.py"
JOB_SCHEMA = ROOT / "contracts" / "local-evidence-job.v1.schema.json"
RESULT_SCHEMA = ROOT / "contracts" / "local-evidence-result.v1.schema.json"


def _load_builder_module():
    spec = importlib.util.spec_from_file_location("build_local_evidence", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load local evidence builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILDER = _load_builder_module()


class LocalEvidenceBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repos_root = self.root / "repos"
        self.repo = self.repos_root / "demo"
        self.workspace_root = self.root / "workspace" / "jobs"
        self.jobs_root = self.root / "job-inputs"
        self.repos_root.mkdir()
        self.workspace_root.mkdir(parents=True)
        self.jobs_root.mkdir()
        self._git("init", "-b", "main")
        self._git("config", "user.name", "Grabowski Test")
        self._git("config", "user.email", "grabowski@example.invalid")
        self._write("src/app.py", "def answer():\n    return 42\n")
        self._write(
            "tests/test_app.py",
            "from src.app import answer\n\n\ndef test_answer():\n    assert answer() == 42\n",
        )
        self._write(
            ".github/workflows/validate.yml",
            "name: validate\nsteps: []\n# src/app.py\n",
        )
        self._write(
            "contracts/app.schema.json",
            '{"title": "app.py contract", "type": "object"}\n',
        )
        self._write("docs/app.md", "The implementation is src/app.py.\n")
        self._git("add", ".")
        self._git("commit", "-m", "initial")
        self.head = self._git("rev-parse", "HEAD").stdout.strip()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        self.repo.mkdir(parents=True, exist_ok=True)
        return subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def _write(self, relative: str, content: str) -> None:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _job(self, job_id: str, **overrides):
        payload = {
            "schema_version": 1,
            "job_id": job_id,
            "mode": "repo-evidence",
            "repo": str(self.repo),
            "task": "Build local evidence for the demo repository.",
            "expected_branch": "main",
            "expected_head": self.head,
            "allowed_paths": [],
            "max_patch_bytes": 200000,
        }
        payload.update(overrides)
        path = self.jobs_root / f"{job_id}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _invoke(self, job: Path, output_name: str):
        output = self.workspace_root / output_name
        environment = os.environ.copy()
        environment.update(
            {
                "GRABOWSKI_REPO_ROOT": str(self.repos_root),
                "GRABOWSKI_WORKSPACE_ROOT": str(self.workspace_root),
                "GRABOWSKI_POLICY_PATH": str(self.root / "missing-policy.json"),
            }
        )
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--job",
                str(job),
                "--output",
                str(output),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        return completed, output

    def _build_direct(self, job: Path, output_name: str):
        output = self.workspace_root / output_name
        environment = {
            "GRABOWSKI_REPO_ROOT": str(self.repos_root),
            "GRABOWSKI_WORKSPACE_ROOT": str(self.workspace_root),
            "GRABOWSKI_POLICY_PATH": str(self.root / "missing-policy.json"),
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            return BUILDER.build(job, str(output))

    @staticmethod
    def _json(path: Path):
        return json.loads(path.read_text(encoding="utf-8"))

    def _verify_hash_manifest(self, bundle: Path) -> None:
        lines = (bundle / "hashes.sha256").read_text(encoding="utf-8").splitlines()
        recorded = {}
        for line in lines:
            digest, relative = line.split("  ", 1)
            recorded[relative] = digest
        expected_paths = {
            path.relative_to(bundle).as_posix()
            for path in bundle.rglob("*")
            if path.is_file() and path.name != "hashes.sha256"
        }
        self.assertEqual(expected_paths, set(recorded))
        for relative, digest in recorded.items():
            actual = hashlib.sha256((bundle / relative).read_bytes()).hexdigest()
            self.assertEqual(digest, actual, relative)

    def test_contract_schemas_match_builder_field_boundaries(self) -> None:
        job_schema = self._json(JOB_SCHEMA)
        result_schema = self._json(RESULT_SCHEMA)
        self.assertFalse(job_schema["additionalProperties"])
        self.assertEqual(set(job_schema["properties"]), BUILDER.JOB_FIELDS)
        self.assertTrue({"expected_branch", "expected_head"} <= set(job_schema["required"]))
        self.assertEqual(1, job_schema["properties"]["schema_version"]["const"])
        self.assertFalse(result_schema["additionalProperties"])
        self.assertEqual(
            {"complete", "partial", "rejected", "failed"},
            set(result_schema["properties"]["status"]["enum"]),
        )

    def test_clean_repo_builds_complete_hashed_bundle_without_index_mutation(self) -> None:
        before_status = self._git(
            "status", "--porcelain=v1", "-z", "--untracked-files=all"
        ).stdout
        index_path = Path(self._git("rev-parse", "--git-path", "index").stdout.strip())
        if not index_path.is_absolute():
            index_path = self.repo / index_path
        before_index = hashlib.sha256(index_path.read_bytes()).hexdigest()

        completed, bundle = self._invoke(self._job("clean"), "clean")

        self.assertEqual(0, completed.returncode, completed.stderr)
        result = self._json(bundle / "result.json")
        state = self._json(bundle / "repo-state.json")
        self.assertEqual("complete", result["status"])
        self.assertEqual(self.head, result["head"])
        self.assertEqual("main", result["branch"])
        self.assertTrue(state["stable_during_collection"])
        self.assertFalse(state["dirty"])
        self.assertEqual(b"", (bundle / "diff.patch").read_bytes())
        self._verify_hash_manifest(bundle)

        after_status = self._git(
            "status", "--porcelain=v1", "-z", "--untracked-files=all"
        ).stdout
        after_index = hashlib.sha256(index_path.read_bytes()).hexdigest()
        self.assertEqual(before_status, after_status)
        self.assertEqual(before_index, after_index)

    def test_dirty_repo_records_changes_references_and_safe_untracked_content(self) -> None:
        self._write("src/app.py", "def answer():\n    return 43\n")
        self._write("src/new.py", "VALUE = 1\n")

        completed, bundle = self._invoke(self._job("dirty"), "dirty")

        self.assertEqual(0, completed.returncode, completed.stderr)
        result = self._json(bundle / "result.json")
        changes = self._json(bundle / "changed-paths.json")["entries"]
        paths = {entry["path"] for entry in changes}
        self.assertEqual("complete", result["status"])
        self.assertEqual({"src/app.py", "src/new.py"}, paths)
        self.assertIn("return 43", (bundle / "diff.patch").read_text(encoding="utf-8"))
        self.assertNotIn("VALUE = 1", (bundle / "diff.patch").read_text(encoding="utf-8"))
        untracked = self._json(bundle / "untracked-files.json")["records"]
        new_record = next(record for record in untracked if record["path"] == "src/new.py")
        self.assertTrue(new_record["captured"])
        self.assertEqual(
            "VALUE = 1\n",
            (bundle / new_record["artifact"]).read_text(encoding="utf-8"),
        )
        tests = self._json(bundle / "references" / "tests.json")["records"]
        workflows = self._json(bundle / "references" / "workflows.json")["records"]
        contracts = self._json(bundle / "references" / "contracts.json")["records"]
        docs = self._json(bundle / "references" / "docs.json")["records"]
        self.assertIn("tests/test_app.py", {record["path"] for record in tests})
        self.assertIn(
            ".github/workflows/validate.yml",
            {record["path"] for record in workflows},
        )
        self.assertIn(
            "contracts/app.schema.json",
            {record["path"] for record in contracts},
        )
        self.assertIn("docs/app.md", {record["path"] for record in docs})

    def test_allowed_paths_omit_out_of_scope_changes_and_mark_partial(self) -> None:
        self._write("src/app.py", "def answer():\n    return 43\n")
        self._write("docs/app.md", "Changed outside the requested scope.\n")
        job = self._job("scoped", allowed_paths=["src"])

        completed, bundle = self._invoke(job, "scoped")

        self.assertEqual(0, completed.returncode, completed.stderr)
        result = self._json(bundle / "result.json")
        changed = self._json(bundle / "changed-paths.json")
        self.assertEqual("partial", result["status"])
        self.assertEqual(["src/app.py"], [item["path"] for item in changed["entries"]])
        self.assertEqual(1, changed["outside_allowed_change_count_omitted"])
        patch = (bundle / "diff.patch").read_text(encoding="utf-8")
        self.assertIn("src/app.py", patch)
        self.assertNotIn("docs/app.md", patch)

    def test_forbidden_path_is_omitted_without_content_disclosure(self) -> None:
        self._write(".env", "TOKEN=initial\n")
        self._git("add", ".env")
        self._git("commit", "-m", "add sensitive fixture")
        self.head = self._git("rev-parse", "HEAD").stdout.strip()
        secret = "TOKEN=super-secret-fixture-value"
        self._write(".env", secret + "\n")

        completed, bundle = self._invoke(self._job("sensitive"), "sensitive")

        self.assertEqual(0, completed.returncode, completed.stderr)
        result = self._json(bundle / "result.json")
        changed = self._json(bundle / "changed-paths.json")
        self.assertEqual("partial", result["status"])
        self.assertEqual([], changed["entries"])
        self.assertEqual(1, changed["sensitive_change_count_omitted"])
        for path in bundle.rglob("*"):
            if path.is_file():
                self.assertNotIn(secret, path.read_text(encoding="utf-8", errors="replace"))

    def test_patch_redaction_marks_bundle_partial(self) -> None:
        secret = "sk-" + "abcdefghijklmnopqrstuvwx"
        self._write(
            "src/app.py",
            f'def answer():\n    token = "{secret}"\n    return 42\n',
        )

        completed, bundle = self._invoke(self._job("redacted"), "redacted")

        self.assertEqual(0, completed.returncode, completed.stderr)
        result = self._json(bundle / "result.json")
        patch = (bundle / "diff.patch").read_text(encoding="utf-8")
        self.assertEqual("partial", result["status"])
        self.assertNotIn(secret, patch)
        self.assertIn("<REDACTED_OPENAI_KEY>", patch)
        self.assertTrue(any("redacted" in item for item in result["limitations"]))

    def test_untracked_binary_is_hashed_but_omitted_and_marks_partial(self) -> None:
        binary = self.repo / "src" / "payload.bin"
        binary.write_bytes(b"\x00\x01fixture")

        completed, bundle = self._invoke(self._job("binary"), "binary")

        self.assertEqual(0, completed.returncode, completed.stderr)
        result = self._json(bundle / "result.json")
        records = self._json(bundle / "untracked-files.json")["records"]
        record = next(item for item in records if item["path"] == "src/payload.bin")
        self.assertEqual("partial", result["status"])
        self.assertFalse(record["captured"])
        self.assertEqual("binary-content", record["reason"])
        self.assertEqual(
            hashlib.sha256(binary.read_bytes()).hexdigest(),
            record["source_sha256"],
        )
        self.assertTrue(any("binary content" in item for item in result["limitations"]))

    def test_expected_head_mismatch_rejects_without_patch_or_references(self) -> None:
        job = self._job("mismatch", expected_head="0" * 40)

        completed, bundle = self._invoke(job, "mismatch")

        self.assertEqual(2, completed.returncode)
        result = self._json(bundle / "result.json")
        self.assertEqual("rejected", result["status"])
        self.assertEqual(b"", (bundle / "diff.patch").read_bytes())
        for category in ("tests", "workflows", "contracts", "docs"):
            payload = self._json(bundle / "references" / f"{category}.json")
            self.assertEqual([], payload["records"])

    def test_unknown_job_field_fails_closed_before_output_creation(self) -> None:
        job = self._job("unknown")
        payload = self._json(job)
        payload["invented"] = True
        job.write_text(json.dumps(payload), encoding="utf-8")

        completed, bundle = self._invoke(job, "unknown")

        self.assertEqual(2, completed.returncode)
        self.assertIn("Unknown job fields", completed.stderr)
        self.assertFalse(bundle.exists())

    def test_job_task_redaction_marks_bundle_partial(self) -> None:
        secret = "TOKEN" + "=credential-fixture-value"
        job = self._job("task-secret", task=secret)

        completed, bundle = self._invoke(job, "task-secret")

        self.assertEqual(0, completed.returncode, completed.stderr)
        result = self._json(bundle / "result.json")
        stored_job = self._json(bundle / "job.json")
        self.assertEqual("partial", result["status"])
        self.assertNotIn(secret, json.dumps(stored_job))
        self.assertEqual("TOKEN=<REDACTED>", stored_job["task"])

    def test_job_symlink_is_rejected_before_output_creation(self) -> None:
        job = self._job("job-target")
        link = self.jobs_root / "job-link.json"
        link.symlink_to(job)

        completed, bundle = self._invoke(link, "job-link")

        self.assertEqual(2, completed.returncode)
        self.assertIn("Symlink path component is forbidden", completed.stderr)
        self.assertFalse(bundle.exists())

    def test_workspace_symlink_component_is_rejected(self) -> None:
        job = self._job("workspace-link")
        actual = self.root / "actual-workspace"
        actual.mkdir()
        linked = self.root / "linked-workspace"
        linked.symlink_to(actual, target_is_directory=True)
        environment = {
            "GRABOWSKI_REPO_ROOT": str(self.repos_root),
            "GRABOWSKI_WORKSPACE_ROOT": str(linked),
            "GRABOWSKI_POLICY_PATH": str(self.root / "missing-policy.json"),
        }

        with mock.patch.dict(os.environ, environment, clear=False):
            with self.assertRaisesRegex(
                BUILDER.EvidenceError,
                "Symlink path component is forbidden",
            ):
                BUILDER.build(job, str(linked / "blocked"))

    def test_tracked_content_drift_marks_patch_source_unstable(self) -> None:
        self._write("src/app.py", "def answer():\n    return 43\n")
        original = BUILDER._build_references

        def drift_after_patch(*args, **kwargs):
            result = original(*args, **kwargs)
            self._write("src/app.py", "def answer():\n    return 44\n")
            return result

        with mock.patch.object(
            BUILDER,
            "_build_references",
            side_effect=drift_after_patch,
        ):
            bundle, result = self._build_direct(
                self._job("tracked-drift"),
                "tracked-drift",
            )

        state = self._json(bundle / "repo-state.json")
        patch = (bundle / "diff.patch").read_text(encoding="utf-8")
        self.assertEqual("partial", result["status"])
        self.assertTrue(state["status_stable"])
        self.assertFalse(state["patch_source_stable"])
        self.assertFalse(state["stable_during_collection"])
        self.assertIn("return 43", patch)
        self.assertNotIn("return 44", patch)

    def test_untracked_content_drift_marks_source_unstable(self) -> None:
        self._write("src/new.py", "VALUE = 1\n")
        original = BUILDER._capture_untracked

        def drift_after_capture(*args, **kwargs):
            result = original(*args, **kwargs)
            self._write("src/new.py", "VALUE = 2\n")
            return result

        with mock.patch.object(
            BUILDER,
            "_capture_untracked",
            side_effect=drift_after_capture,
        ):
            bundle, result = self._build_direct(
                self._job("untracked-drift"),
                "untracked-drift",
            )

        state = self._json(bundle / "repo-state.json")
        records = self._json(bundle / "untracked-files.json")["records"]
        record = next(item for item in records if item["path"] == "src/new.py")
        self.assertEqual("partial", result["status"])
        self.assertTrue(state["status_stable"])
        self.assertFalse(state["untracked_sources_stable"])
        self.assertFalse(state["stable_during_collection"])
        self.assertEqual(
            "VALUE = 1\n",
            (bundle / record["artifact"]).read_text(encoding="utf-8"),
        )

    def test_core_artifacts_are_deterministic_for_identical_repo_state(self) -> None:
        job = self._job("repeatable")
        first, first_bundle = self._invoke(job, "repeatable-a")
        second, second_bundle = self._invoke(job, "repeatable-b")
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(0, second.returncode, second.stderr)
        stable_artifacts = [
            "job.json",
            "repo-state.json",
            "changed-paths.json",
            "diff.patch",
            "untracked-files.json",
            "references/tests.json",
            "references/workflows.json",
            "references/contracts.json",
            "references/docs.json",
            "limitations.md",
        ]
        for relative in stable_artifacts:
            self.assertEqual(
                (first_bundle / relative).read_bytes(),
                (second_bundle / relative).read_bytes(),
                relative,
            )


if __name__ == "__main__":
    unittest.main()
