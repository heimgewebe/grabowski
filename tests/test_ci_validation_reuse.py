"""Exercise the actual CI tier script, including incomplete provider evidence."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
REPO = "heimgewebe/grabowski"


def proof():
    run = {
        "id": 123,
        "run_attempt": 1,
        "head_sha": SHA,
        "repository": {"full_name": REPO},
        "head_repository": {"full_name": REPO},
        "event": "merge_group",
        "path": ".github/workflows/validate.yml",
        "head_branch": "gh-readonly-queue/main/pr-1-" + "b" * 40,
        "status": "completed",
        "conclusion": "success",
    }
    jobs = [
        {
            "run_id": 123,
            "head_sha": SHA,
            "run_attempt": 1,
            "name": f"validate ({version})",
            "status": "completed",
            "conclusion": "success",
            "steps": [
                {"name": name, "status": "completed", "conclusion": "success"}
                for name in ("Validate repository", "Prove reproducible deployment staging")
            ],
        }
        for version in ("3.10", "3.12")
    ]
    return {"total_count": 1, "workflow_runs": [run]}, {"total_count": 2, "jobs": jobs}


class MainValidationReuseTests(unittest.TestCase):
    def run_selector(self, runs, jobs, *, event="push", repo=REPO,
                     ref="refs/heads/main", sha=SHA, runs_exit=0, jobs_exit=0):
        workflow = (ROOT / ".github/workflows/validate.yml").read_text()
        step = workflow.split("- name: Choose validation tier\n", 1)[1]
        script = textwrap.dedent(
            step.split("\n      - name:", 1)[0].split("        run: |\n", 1)[1]
        )
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            gh = tmp / "gh"
            gh.write_text(
                "#!/bin/sh\n"
                'printf "%s\\n" "$*" >> "$GH_CALLS"\n'
                'case "$2" in\n'
                '  */actions/runs?head_sha=*) printf "%s\\n" "$GH_RUNS"; exit "$GH_RUNS_EXIT";;\n'
                '  */actions/runs/123/attempts/1/jobs?per_page=100) printf "%s\\n" "$GH_JOBS"; exit "$GH_JOBS_EXIT";;\n'
                '  *) exit 2;;\n'
                'esac\n'
            )
            gh.chmod(0o700)
            output, calls = tmp / "output", tmp / "calls"
            env = dict(
                os.environ, PATH=f"{tmp}:{os.environ['PATH']}",
                GITHUB_OUTPUT=str(output), GH_CALLS=str(calls),
                EVENT_NAME=event, REPOSITORY=repo, REF_NAME=ref, HEAD_SHA=sha,
                GH_RUNS=runs if isinstance(runs, str) else json.dumps(runs),
                GH_JOBS=jobs if isinstance(jobs, str) else json.dumps(jobs),
                GH_RUNS_EXIT=str(runs_exit), GH_JOBS_EXIT=str(jobs_exit),
            )
            subprocess.run(
                [sys.executable, "-c", script], env=env, check=True, capture_output=True
            )
            return output.read_text().strip(), calls.read_text().splitlines() if calls.exists() else []

    def test_complete_exact_group_reuses_suite(self):
        tier, calls = self.run_selector(*proof())
        self.assertEqual("tier=main-reuse", tier)
        self.assertEqual([
            f"api repos/{REPO}/actions/runs?head_sha={SHA}&per_page=30",
            f"api repos/{REPO}/actions/runs/123/attempts/1/jobs?per_page=100",
        ], calls)

    def test_other_contexts_never_query_or_reuse(self):
        for kwargs in (
            {"event": "pull_request"}, {"event": "merge_group"},
            {"repo": "other/grabowski"}, {"ref": "refs/heads/feature"},
            {"sha": "bad"},
        ):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(("tier=full", []), self.run_selector(*proof(), **kwargs))

    def test_missing_ambiguous_or_failed_proof_keeps_full_suite(self):
        cases = (
            "missing", "truncated", "wrong-sha", "wrong-repo", "wrong-head-repo",
            "wrong-event", "wrong-workflow", "wrong-queue", "failed-run",
            "running-run", "ambiguous", "ambiguous-failed", "bad-attempt",
            "missing-job", "duplicate-job", "wrong-job-sha", "wrong-job-run",
            "wrong-job-attempt", "failed-job", "skipped-suite",
            "skipped-deploy", "duplicate-step", "missing-step",
            "truncated-jobs", "invalid-runs", "invalid-jobs",
            "runs-unavailable", "jobs-unavailable",
        )
        for case in cases:
            with self.subTest(case=case):
                runs, jobs = proof()
                run = runs["workflow_runs"][0]
                job = jobs["jobs"][0]
                kwargs = {}
                if case == "missing":
                    runs = {"total_count": 0, "workflow_runs": []}
                elif case == "truncated":
                    runs["total_count"] = 2
                elif case == "wrong-sha":
                    run["head_sha"] = "c" * 40
                elif case == "wrong-repo":
                    run["repository"]["full_name"] = "other/grabowski"
                elif case == "wrong-head-repo":
                    run["head_repository"]["full_name"] = "other/grabowski"
                elif case == "wrong-event":
                    run["event"] = "push"
                elif case == "wrong-workflow":
                    run["path"] = ".github/workflows/other.yml"
                elif case == "wrong-queue":
                    run["head_branch"] = "gh-readonly-queue/other/pr-1"
                elif case == "failed-run":
                    run["conclusion"] = "failure"
                elif case == "running-run":
                    run["status"] = "in_progress"
                elif case.startswith("ambiguous"):
                    extra = copy.deepcopy(run)
                    extra["id"] = 124
                    if case == "ambiguous-failed":
                        extra["conclusion"] = "failure"
                    runs["workflow_runs"].append(extra)
                    runs["total_count"] = 2
                elif case == "bad-attempt":
                    run["run_attempt"] = True
                elif case == "missing-job":
                    jobs["jobs"].pop()
                    jobs["total_count"] = 1
                elif case == "duplicate-job":
                    jobs["jobs"][1]["name"] = job["name"]
                elif case == "wrong-job-sha":
                    job["head_sha"] = "c" * 40
                elif case == "wrong-job-run":
                    job["run_id"] = 124
                elif case == "wrong-job-attempt":
                    job["run_attempt"] = 2
                elif case == "failed-job":
                    job["conclusion"] = "failure"
                elif case == "skipped-suite":
                    job["steps"][0]["conclusion"] = "skipped"
                elif case == "skipped-deploy":
                    job["steps"][1]["conclusion"] = "skipped"
                elif case == "duplicate-step":
                    job["steps"].append(copy.deepcopy(job["steps"][0]))
                elif case == "missing-step":
                    job["steps"].pop()
                elif case == "truncated-jobs":
                    jobs["total_count"] = 3
                elif case == "invalid-runs":
                    runs = "invalid JSON"
                elif case == "invalid-jobs":
                    jobs = "invalid JSON"
                elif case == "runs-unavailable":
                    kwargs["runs_exit"] = 1
                elif case == "jobs-unavailable":
                    kwargs["jobs_exit"] = 1
                tier, _ = self.run_selector(runs, jobs, **kwargs)
                self.assertEqual("tier=full", tier)

    def test_main_keeps_fresh_checks_and_deployment_staging(self):
        workflow = (ROOT / ".github/workflows/validate.yml").read_text()
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("steps.tier.outputs.tier != 'main-reuse'", workflow)
        self.assertIn("steps.tier.outputs.tier == 'main-reuse'", workflow)
        self.assertIn("run: make validate\n", workflow)
        self.assertIn("run: make validate-main-reuse", workflow)
        self.assertIn("run: make deploy-check", workflow)
        self.assertIn("validate: $(VALIDATE_PRECHECKS) test $(VALIDATE_CONTRACT_CHECKS)", makefile)
        prechecks = next(
            line for line in makefile.splitlines()
            if line.startswith("VALIDATE_PRECHECKS :=")
        ).split(":=", 1)[1].split()
        self.assertIn("context-check", prechecks)
        self.assertIn("profiles-check", prechecks)
        self.assertIn("validate-main-reuse: $(VALIDATE_PRECHECKS) $(VALIDATE_CONTRACT_CHECKS)", makefile)
