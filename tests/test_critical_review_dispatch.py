from __future__ import annotations
import pathlib,sys,tempfile,unittest
from unittest.mock import Mock
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"src"))
from grabowski_critical_review_dispatch import maybe_start_claude_review

BINDING={"repo":"heimgewebe/grabowski","pr":101,"head_sha":"a"*40,"base_sha":"b"*40,"diff_sha256":"c"*64,"review_batch_id":"d"*32,"review_purpose":"pull_request"}
ROUTE={"route":"claude-opus-5.5-high","model":"claude-opus-5.5","harness":"claude","review_only":True,"paid_only":False,"execution_eligible_if_separately_authorized":True,"argv_prefix":["claude","--model","claude-opus-5-5","--effort","high","--permission-mode","plan"]}

class CriticalClaudeDispatchTest(unittest.TestCase):
 def test_dispatcher_is_installed_as_setuptools_module(self):
  import ast
  raw=(ROOT/"pyproject.toml").read_text(encoding="utf-8")
  line=next(line for line in raw.splitlines() if line.startswith("py-modules = "))
  modules=ast.literal_eval(line.partition("=")[2].strip())
  self.assertIn("grabowski_critical_review_dispatch",modules)
  self.assertTrue((ROOT/"src/grabowski_critical_review_dispatch.py").is_file())

 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory()
  self.addCleanup(self.tmp.cleanup)
  self.repo=pathlib.Path(self.tmp.name)/"repo"
  self.repo.mkdir()
  self.plan={"kind":"grabowski_first_party_review_plan","binding":dict(BINDING),"worktree":str(self.repo)}
  self.route=Mock(return_value={"reviewers":[dict(ROUTE)],"review_fallbacks":[]})
  self.reader=Mock(return_value=(BINDING["head_sha"],"e"*64,False))
  self.history=Mock(return_value={"attempts":[],"errors":[]})
  self.starter=Mock(return_value={"unit":"grabowski-job-abcdef123456"})
 def run_dispatch(self,**overrides):
  opts={"route_selector":self.route,"binding_reader":self.reader,"reconcile":self.history,"job_start":self.starter,"lock_root":pathlib.Path(self.tmp.name)/"locks"}
  return maybe_start_claude_review(self.plan,**(opts|overrides))
 def test_launches_only_read_only_opaque_quota_eligible_claude(self):
  result=self.run_dispatch()
  self.assertEqual(result["state"],"dispatched")
  self.assertGreaterEqual(self.route.call_args.kwargs["duration_minutes"],20)
  cmd=self.starter.call_args.args[0]
  self.assertEqual(cmd[cmd.index("--role")+1],"review")
  self.assertEqual(cmd[cmd.index("--expected-diff-sha256")+1],"e"*64)
  self.assertIn("claude",cmd)
  self.assertEqual(self.starter.call_args.kwargs["decision_review_binding"]["slot"],"independent-claude")
  self.assertFalse(result["independent_review_required"])
 def test_no_duplicate_once_revision_has_attempt(self):
  self.history.return_value={"attempts":[{"slot":"independent-claude"}],"errors":[]}
  self.assertEqual(self.run_dispatch()["state"],"already_attempted")
  self.starter.assert_not_called()
 def test_ineligible_quota_does_not_block_first_party(self):
  bad=dict(ROUTE,execution_eligible_if_separately_authorized=False)
  self.route.return_value={"reviewers":[bad],"review_fallbacks":[]}
  result=self.run_dispatch()
  self.assertEqual(result["state"],"unavailable")
  self.assertFalse(result["mandatory_external_pass"])
  self.starter.assert_not_called()
 def test_no_grok_fallback(self):
  self.route.return_value={"reviewers":[dict(ROUTE,route="grok-4.7-review-high",harness="grok")],"review_fallbacks":[]}
  self.assertEqual(self.run_dispatch()["state"],"unavailable")
  self.starter.assert_not_called()
 def test_non_pr_plan_does_not_consume_quota(self):
  self.plan["binding"]["review_purpose"]="post_merge_release"
  self.assertEqual(self.run_dispatch()["state"],"not_applicable")
  self.starter.assert_not_called()
 def test_dirty_worktree_never_starts(self):
  self.reader.return_value=(BINDING["head_sha"],"e"*64,True)
  self.assertEqual(self.run_dispatch()["reason"],"frozen_worktree_identity_not_clean")
  self.starter.assert_not_called()
 def test_start_failure_does_not_kill_signed_first_party_session(self):
  self.starter.side_effect=OSError("provider absent")
  result=self.run_dispatch()
  self.assertEqual(result["state"],"unavailable")
  self.assertEqual(result["error_type"],"OSError")
  self.assertFalse(result["mandatory_external_pass"])
 def test_history_failure_does_not_retry_uncertain_effect(self):
  self.history.return_value={"attempts":[],"errors":["decision_review_history_ambiguous"]}
  self.assertEqual(self.run_dispatch()["reason"],"existing_review_history_unsettled")
  self.starter.assert_not_called()

if __name__=="__main__":
 unittest.main()
