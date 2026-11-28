"""Exercise the actual CI tier script, including incomplete provider evidence."""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

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
                BASE_REF='', BASE_SHA='', PR_HEAD='', HEAD_REPOSITORY='',
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

class QueueAdmissionTests(unittest.TestCase):
    BASE = "b" * 40
    PR_HEAD = "c" * 40

    @staticmethod
    def rules():
        identity = {
            "ruleset_id": 18801517,
            "ruleset_source_type": "Repository",
            "ruleset_source": REPO,
        }
        return [
            dict(identity, type="merge_queue", parameters={
                "grouping_strategy": "ALLGREEN", "merge_method": "SQUASH",
            }),
            dict(identity, type="required_status_checks", parameters={
                "strict_required_status_checks_policy": True,
                "do_not_enforce_on_create": False,
                "required_status_checks": [
                    {"context": name, "integration_id": 15368}
                    for name in ("validate (3.10)", "validate (3.12)")
                ],
            }),
        ]

    def select(self, *, env=None, rules=None, base=None, parents=None,
               diff_rc=0, failed=False):
        workflow = (ROOT / ".github/workflows/validate.yml").read_text()
        selector = workflow.split("- name: Choose validation tier\n", 1)[1]
        script = textwrap.dedent(selector.split("\n      - name:", 1)[0].split("        run: |\n", 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            variables = {
                "EVENT_NAME": "pull_request", "REPOSITORY": REPO, "BASE_REF": "main",
                "HEAD_REPOSITORY": REPO, "BASE_SHA": self.BASE, "HEAD_SHA": SHA,
                "PR_HEAD": self.PR_HEAD, "REF_NAME": "refs/pull/12/merge",
                "GITHUB_OUTPUT": str(output),
            }
            variables.update(env or {})
            responses = [
                subprocess.CompletedProcess([], 0, json.dumps({
                    "object": {"sha": self.BASE if base is None else base}
                }), ""),
                subprocess.CompletedProcess([], 0, " ".join(
                    [SHA, self.BASE, self.PR_HEAD] if parents is None else parents
                ), ""),
                subprocess.CompletedProcess([], diff_rc, "", ""),
                subprocess.CompletedProcess([], 0, json.dumps(
                    self.rules() if rules is None else rules
                ), ""),
            ]
            with patch.dict(os.environ, variables), patch(
                "subprocess.run", side_effect=(
                    subprocess.TimeoutExpired("gh", 10) if failed else responses
                )
            ) as api, patch("sys.stdout", new_callable=io.StringIO):
                exec(compile(script, "<workflow admission selector>", "exec"), {})
            return output.read_text().strip(), [call.args[0] for call in api.call_args_list]

    def test_exact_queued_main_pr_admission(self):
        result, calls = self.select()
        self.assertEqual("tier=admission", result)
        self.assertEqual([
            ["gh", "api", f"repos/{REPO}/git/ref/heads/main"],
            ["git", "rev-list", "--parents", "-n", "1", "HEAD"],
            ["git", "diff", "--quiet", "--no-renames", self.BASE, SHA, "--",
             ".github", "Makefile", "requirements", "config", "tools",
             "tests/test_ci_validation_reuse.py"],
            ["gh", "api", f"repos/{REPO}/rules/branches/main?per_page=100"],
        ], calls)

    def test_never_admit_other_contexts(self):
        for env in (
            {"EVENT_NAME": "merge_group"}, {"EVENT_NAME": "workflow_dispatch"},
            {"REPOSITORY": "other/repo"}, {"BASE_REF": "other"},
            {"HEAD_REPOSITORY": "fork/repo"}, {"BASE_SHA": "invalid"},
            {"PR_HEAD": "invalid"}, {"HEAD_SHA": "invalid"}, {"HEAD_SHA": self.BASE},
        ):
            with self.subTest(env=env):
                self.assertEqual(("tier=full", []), self.select(env=env))

    def test_base_control_and_api_failures_require_full_validation(self):
        for kwargs in (
            {"base": "d" * 40}, {"parents": [SHA, self.PR_HEAD, self.BASE]},
            {"parents": [SHA]}, {"diff_rc": 1}, {"diff_rc": 128}, {"failed": True},
            {"rules": []}, {"rules": {"bad": True}}, {"rules": [None]},
            {"rules": self.rules() * 50},
        ):
            with self.subTest(kwargs=kwargs):
                self.assertEqual("tier=full", self.select(**kwargs)[0])

    def test_invalid_rules_require_full_validation(self):
        for case in ("no-queue", "duplicate-queue", "no-checks", "wrong-id", "wrong-source",
                     "wrong-method", "wrong-grouping", "loose-checks", "creation-exempt",
                     "missing-check", "wrong-integration"):
            rules = self.rules()
            with self.subTest(case=case):
                if case == "no-queue":
                    rules.pop(0)
                elif case == "duplicate-queue":
                    rules.append(copy.deepcopy(rules[0]))
                elif case == "no-checks":
                    rules.pop(1)
                elif case == "wrong-id":
                    rules[0]["ruleset_id"] = 1
                elif case == "wrong-source":
                    rules[0]["ruleset_source"] = "other/repo"
                elif case == "wrong-method":
                    rules[0]["parameters"]["merge_method"] = "MERGE"
                elif case == "wrong-grouping":
                    rules[0]["parameters"]["grouping_strategy"] = "HEADGREEN"
                elif case == "loose-checks":
                    rules[1]["parameters"]["strict_required_status_checks_policy"] = False
                elif case == "creation-exempt":
                    rules[1]["parameters"]["do_not_enforce_on_create"] = True
                elif case == "missing-check":
                    rules[1]["parameters"]["required_status_checks"].pop()
                else:
                    rules[1]["parameters"]["required_status_checks"][-1]["integration_id"] = 1
                self.assertEqual("tier=full", self.select(rules=rules)[0])

    def test_workflow_keeps_full_group_and_deploy_checks(self):
        workflow = (ROOT / ".github/workflows/validate.yml").read_text()
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("fetch-depth: 2", workflow)
        self.assertIn("steps.tier.outputs.tier != 'main-reuse' && steps.tier.outputs.tier != 'admission'", workflow)
        self.assertIn("steps.tier.outputs.tier == 'admission'", workflow)
        self.assertIn("run: make validate-admission", workflow)
        self.assertIn("validate-admission: validate-main-reuse", makefile)
        self.assertIn("run: make deploy-check", workflow)
