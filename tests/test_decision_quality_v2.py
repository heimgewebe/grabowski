from __future__ import annotations
import json, os, sys, tempfile, threading, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
import grabowski_operator_obligation as obligation

class DecisionQualityV2Tests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name)/"operator-obligations"
        self.e=patch.dict(os.environ,{"GRABOWSKI_OPERATOR_OBLIGATION_ROOT":str(self.root)})
        self.e.start(); self.addCleanup(self.e.stop)
        self.a=patch.object(obligation.alert_outbox,"enqueue_and_schedule")
        self.a.start(); self.addCleanup(self.a.stop)
    @staticmethod
    def op(i="goo-decision-quality-test-0001"):
        return {"obligation_id":i,"objective":"Reach user outcome without invented continuation.",
                "acceptance":[{"id":"outcome","description":"User outcome reached."}],
                "origin":{"source":"test","repo":"/home/alex/repos/grabowski"},"references":[]}

    def test_direct_defer_is_historical_without_fake_close(self):
        opened=obligation.open_obligation(self.op())
        d=self.root/"goo-decision-quality-test-0001"; f=d/"open.json"; before=f.read_bytes()
        req={"obligation_id":"goo-decision-quality-test-0001","disposition":"deferred",
             "evidence":[{"source":"decision","reference":"decision:park","sha256":"a"*64}],
             "next_action":"Reassess only when new evidence changes the decision."}
        first=obligation.resolve_obligation(req); replay=obligation.resolve_obligation(req)
        self.assertEqual(("open","historical","deferred"),(first["state"],first["attention_class"],first["resolution_disposition"]))
        self.assertFalse(first["continuation_required"]); self.assertTrue(first["response_may_end"]); self.assertFalse(first["work_complete"])
        self.assertIsNone(first["closed_at"]); self.assertIsNone(first["close_file_sha256"])
        self.assertEqual(opened["open_file_sha256"],first["open_file_sha256"]); self.assertEqual(before,f.read_bytes())
        self.assertFalse((d/"close.json").exists()); self.assertTrue(replay["replayed"]); self.assertEqual(1,replay["resolution_revision_count"])
        self.assertEqual(0,obligation.list_obligations({"state":"attention"})["record_count"])
        self.assertEqual("historical",obligation.list_obligations({"state":"open"})["records"][0]["attention_class"])
        with self.assertRaises(obligation.OperatorObligationConflictError):
            obligation.resolve_obligation({"obligation_id":"goo-decision-quality-test-0001","disposition":"superseded",
                "evidence":[{"source":"decision","reference":"decision:change","sha256":"b"*64}]})
        with self.assertRaises(obligation.OperatorObligationConflictError):
            obligation.close_obligation({"obligation_id":"goo-decision-quality-test-0001","outcome":"blocked","evidence":[]})

    def test_direct_supersede_binds_successor(self):
        obligation.open_obligation(self.op())
        successor=obligation.open_obligation(self.op("goo-decision-quality-successor-0002"))
        r=obligation.resolve_obligation({"obligation_id":"goo-decision-quality-test-0001","disposition":"superseded",
            "evidence":[{"source":"operator-obligation","reference":"goo-decision-quality-successor-0002","sha256":successor["open_file_sha256"]}]})
        self.assertEqual("historical",r["attention_class"]); self.assertFalse(r["continuation_required"]); self.assertFalse(r["work_complete"])
        ids={x["obligation_id"] for x in obligation.list_obligations({"state":"attention"})["records"]}
        self.assertNotIn("goo-decision-quality-test-0001",ids); self.assertIn("goo-decision-quality-successor-0002",ids)

    def test_direct_open_rejects_completion_and_bad_evidence(self):
        obligation.open_obligation(self.op())
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.resolve_obligation({"obligation_id":"goo-decision-quality-test-0001","disposition":"resolved",
                "evidence":[{"source":"test","reference":"fake","sha256":"c"*64}]})
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.resolve_obligation({"obligation_id":"goo-decision-quality-test-0001","disposition":"deferred",
                "evidence":[{"source":"test","reference":"bad","sha256":"stale"}],"next_action":"Later."})

    def test_direct_supersede_rejects_unbound_missing_self_and_mismatched_successor(self):
        current=obligation.open_obligation(self.op())
        successor=obligation.open_obligation(self.op("goo-decision-quality-successor-0004"))
        bad_requests=[
            {"obligation_id":"goo-decision-quality-test-0001","disposition":"superseded",
             "evidence":[{"source":"decision","reference":"change","sha256":"a"*64}]},
            {"obligation_id":"goo-decision-quality-test-0001","disposition":"superseded",
             "evidence":[{"source":"operator-obligation","reference":"goo-decision-quality-missing-0009","sha256":"b"*64}]},
            {"obligation_id":"goo-decision-quality-test-0001","disposition":"superseded",
             "evidence":[{"source":"operator-obligation","reference":"goo-decision-quality-test-0001","sha256":current["open_file_sha256"]}]},
            {"obligation_id":"goo-decision-quality-test-0001","disposition":"superseded",
             "evidence":[{"source":"operator-obligation","reference":"goo-decision-quality-successor-0004","sha256":"c"*64}]},
        ]
        for index, request in enumerate(bad_requests):
            with self.subTest(index=index):
                with self.assertRaises(obligation.OperatorObligationInputError):
                    obligation.resolve_obligation(request)
        self.assertFalse((self.root/"goo-decision-quality-test-0001"/"resolution.json").exists())
        valid=obligation.resolve_obligation({
            "obligation_id":"goo-decision-quality-test-0001","disposition":"superseded",
            "evidence":[{"source":"operator-obligation","reference":"goo-decision-quality-successor-0004","sha256":successor["open_file_sha256"]}],
        })
        self.assertEqual("superseded",valid["resolution_disposition"])

    def test_tampered_successor_binding_fails_closed(self):
        obligation.open_obligation(self.op())
        successor=obligation.open_obligation(self.op("goo-decision-quality-successor-0005"))
        obligation.resolve_obligation({
            "obligation_id":"goo-decision-quality-test-0001","disposition":"superseded",
            "evidence":[{"source":"operator-obligation","reference":"goo-decision-quality-successor-0005","sha256":successor["open_file_sha256"]}],
        })
        p=self.root/"goo-decision-quality-test-0001"/"resolution.json"; q=json.loads(p.read_text())
        q["evidence"][0]["sha256"]="f"*64
        m={k:v for k,v in q.items() if k not in {"resolved_at","material_sha256","record_sha256"}}
        q["material_sha256"]=obligation._sha256(m); q["record_sha256"]=obligation._sha256({k:v for k,v in q.items() if k!="record_sha256"})
        p.write_text(json.dumps(q))
        with self.assertRaises(obligation.OperatorObligationIntegrityError):
            obligation.status_obligation("goo-decision-quality-test-0001")

    def test_stale_open_binding_fails_closed(self):
        obligation.open_obligation(self.op())
        obligation.resolve_obligation({"obligation_id":"goo-decision-quality-test-0001","disposition":"deferred",
            "evidence":[{"source":"test","reference":"decision:park","sha256":"d"*64}],"next_action":"Later."})
        p=self.root/"goo-decision-quality-test-0001"/"resolution.json"; q=json.loads(p.read_text())
        q["open_file_sha256"]="e"*64
        m={k:v for k,v in q.items() if k not in {"resolved_at","material_sha256","record_sha256"}}
        q["material_sha256"]=obligation._sha256(m); q["record_sha256"]=obligation._sha256({k:v for k,v in q.items() if k!="record_sha256"})
        p.write_text(json.dumps(q))
        with self.assertRaises(obligation.OperatorObligationIntegrityError):
            obligation.status_obligation("goo-decision-quality-test-0001")

    def test_concurrent_direct_decisions_have_one_winner(self):
        obligation.open_obligation(self.op()); successor=obligation.open_obligation(self.op("goo-decision-quality-successor-0003")); b=threading.Barrier(2); rs=[]; es=[]
        reqs=[
          {"obligation_id":"goo-decision-quality-test-0001","disposition":"deferred","evidence":[{"source":"test","reference":"park","sha256":"1"*64}],"next_action":"Later."},
          {"obligation_id":"goo-decision-quality-test-0001","disposition":"superseded","evidence":[{"source":"operator-obligation","reference":"goo-decision-quality-successor-0003","sha256":successor["open_file_sha256"]}]},
        ]
        def run(r):
            b.wait()
            try: rs.append(obligation.resolve_obligation(r))
            except BaseException as e: es.append(e)
        ts=[threading.Thread(target=run,args=(r,)) for r in reqs]
        [t.start() for t in ts]; [t.join(5) for t in ts]
        self.assertTrue(all(not t.is_alive() for t in ts)); self.assertEqual((1,1),(len(rs),len(es)))
        self.assertIsInstance(es[0],obligation.OperatorObligationConflictError)
        st=obligation.status_obligation("goo-decision-quality-test-0001")
        self.assertEqual("historical",st["attention_class"]); self.assertFalse(st["continuation_required"]); self.assertFalse(st["work_complete"])

if __name__=="__main__": unittest.main()
