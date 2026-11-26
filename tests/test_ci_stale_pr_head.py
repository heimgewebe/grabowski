"""Run the actual CI stale-head step with controlled Git responses."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
STEP = "- name: Reject proven superseded initial PR head"
WORKFLOW = ROOT / ".github/workflows/validate.yml"
HEAD = "a" * 40
NEW = "b" * 40
REF = "refs/pull/42/head"


class StalePrHeadTests(unittest.TestCase):
    def run_gate(self, reply=None, status=0, **overrides):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(STEP, workflow)
        step = workflow.split(STEP + "\n", 1)[1].split("\n      - name:", 1)[0]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            git = tmp / "git"
            git.write_text(
                "#!/bin/sh\n"
                'printf "%s\\n" "$*" >> "$GIT_CALLS"\n'
                'printf "%s" "$GIT_REPLY"\n'
                'exit "$GIT_STATUS"\n',
                encoding="utf-8",
            )
            git.chmod(0o700)
            calls = tmp / "calls"
            env = dict(
                os.environ,
                PATH=f"{tmp}:{os.environ['PATH']}",
                GIT_CALLS=str(calls),
                GIT_REPLY=f"{NEW}\t{REF}\n" if reply is None else reply,
                GIT_STATUS=str(status),
                EVENT_NAME="pull_request",
                REPOSITORY="heimgewebe/grabowski",
                RUN_ATTEMPT="1",
                PR_NUMBER="42",
                PR_HEAD=HEAD,
            )
            env.update(overrides)
            bash = shutil.which("bash")
            self.assertIsNotNone(bash)
            result = subprocess.run(
                [bash, "-c", script], env=env, capture_output=True,
                text=True, timeout=15,
            )
            observed = calls.read_text().splitlines() if calls.exists() else []
            return result, observed

    def test_proven_stale_head_is_not_green(self):
        result, calls = self.run_gate()
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertIn("PR head superseded", result.stdout)
        self.assertEqual(
            ["ls-remote --exit-code --refs origin refs/pull/42/head"], calls
        )

    def test_matching_current_head_preserves_full_validation(self):
        result, calls = self.run_gate(reply=f"{HEAD}\t{REF}\n")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(1, len(calls))

    def test_other_contexts_make_no_probe(self):
        for overrides in (
            {"EVENT_NAME": "push"}, {"EVENT_NAME": "merge_group"},
            {"RUN_ATTEMPT": "2"}, {"REPOSITORY": "example/grabowski"},
            {"PR_NUMBER": "0"}, {"PR_NUMBER": ""}, {"PR_HEAD": "abc"},
        ):
            with self.subTest(overrides=overrides):
                result, calls = self.run_gate(**overrides)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual([], calls)

    def test_uncertain_ref_always_preserves_full_validation(self):
        good = f"{NEW}\t{REF}\n"
        for reply, status in (
            (good, 128), (good, 124), ("", 2), ("", 0),
            (f"{NEW}\trefs/pull/1/head\n", 0), (good + good, 0),
            (f"not-a-sha\t{REF}\n", 0), (good.rstrip() + "\textra\n", 0),
        ):
            with self.subTest(reply=reply, status=status):
                result, calls = self.run_gate(reply=reply, status=status)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(1, len(calls))

    def test_gate_precedes_expensive_steps_and_keeps_full_checks(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertLess(workflow.index("- name: Checkout Grabowski"), workflow.index(STEP))
        self.assertLess(workflow.index(STEP), workflow.index("- name: Checkout pinned convergence protocol"))
        self.assertIn("PR_HEAD: ${{ github.event.pull_request.head.sha }}", workflow)
        self.assertIn("PR_NUMBER: ${{ github.event.pull_request.number }}", workflow)
        self.assertIn("RUN_ATTEMPT: ${{ github.run_attempt }}", workflow)
        self.assertIn("run: make validate\n", workflow)
        self.assertIn("run: make deploy-check", workflow)
        self.assertIn("run: make validate-main-reuse", workflow)


if __name__ == "__main__":
    unittest.main()
