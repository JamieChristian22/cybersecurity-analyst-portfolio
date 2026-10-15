import json
import unittest
from pathlib import Path
from lab.rolling import detect_rolling
from test_detections import event

class RollingTests(unittest.TestCase):
    def test_labeled_scenarios(self):
        cases=json.loads((Path(__file__).resolve().parents[1]/'lab/fixtures/benchmark/scenarios.json').read_text())
        self.assertEqual(len(cases),72)
        for c in cases:
            with self.subTest(case=c['case_id']):
                result=detect_rolling(c['events'])
                self.assertEqual(any(a['rule_id']==c['target_rule'] for a in result),c['expected_positive'])
    def test_crosses_fixed_bin_boundary(self):
        self.assertEqual([a['rule_id'] for a in detect_rolling([event(i,298+i) for i in range(5)])],['ROLL-001'])
    def test_same_time_failures_do_not_precede_success(self):
        result=detect_rolling([event(i,0) for i in range(3)]+[event(4,0,'success')])
        self.assertNotIn('ROLL-002',[a['rule_id'] for a in result])
    def test_success_current_event_order_independent(self):
        events=[event(i,i) for i in range(3)]+[event(4,4,'success')]
        self.assertEqual(detect_rolling(events),detect_rolling(events[::-1]))
    def test_long_burst_emits_once(self):
        self.assertEqual(len(detect_rolling([event(i,i) for i in range(20)])),1)
    def test_expired_burst_rearms(self):
        events=[event(i,i) for i in range(5)]+[event(10+i,1000+i) for i in range(5)]
        self.assertEqual(len(detect_rolling(events)),2)
    def test_spray_counts_expire(self):
        result=detect_rolling([event(i,i*601,user=str(i)) for i in range(8)])
        self.assertNotIn('ROLL-003',[a['rule_id'] for a in result])
    def test_window_inclusive_boundary(self):
        result=detect_rolling([event(i,i) for i in range(3)]+[event(4,300,'success')])
        self.assertEqual(len(result),1)
    def test_window_exclusive_outside(self):
        result=detect_rolling([event(i,i) for i in range(3)]+[event(4,301,'success')])
        self.assertEqual(result,[])
    def test_evidence_keys_are_exact(self):
        result=detect_rolling([event(i,i) for i in range(3)]+[event(4,4,'success')])
        self.assertEqual(result[0]['evidence_event_ids'],['0','1','2','4'])
