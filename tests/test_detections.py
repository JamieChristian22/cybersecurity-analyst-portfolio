import csv
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from lab.detections import detect, read_events, timestamp

ROOT=Path(__file__).resolve().parents[1]

def event(n, seconds, action='failure', user='alex', ip='203.0.113.10', geo='US-NC'):
    return {'event_id': str(n), 'timestamp': (datetime(2026,10,1,tzinfo=timezone.utc)+timedelta(seconds=seconds)).isoformat(),
            'username': user, 'src_ip': ip, 'action': action, 'geo': geo}

def correlated(events):
    return [a for a in detect(events) if a['rule_id']=='AUTH-002']

class DetectionTests(unittest.TestCase):
    def test_fixture_exact_alerts(self):
        result=detect(read_events(ROOT/'lab/auth_events.csv'))
        self.assertEqual([{'rule_id':a['rule_id'],'event_id':a['event_id']} for a in result],
                         json.loads((ROOT/'lab/expected_alerts.json').read_text()))
    def test_out_of_order_events(self):
        events=read_events(ROOT/'lab/auth_events.csv')
        self.assertEqual(detect(events),detect(list(reversed(events))))
    def test_empty(self): self.assertEqual(detect([]),[])
    def test_failure_then_success(self):
        self.assertEqual(len(correlated([event(i,i) for i in range(3)]+[event(4,4,'success')])),1)
    def test_success_before_failures(self):
        self.assertEqual(correlated([event(0,0,'success')]+[event(i,i) for i in range(1,4)]),[])
    def test_two_failures_insufficient(self):
        self.assertEqual(correlated([event(0,0),event(1,1),event(2,2,'success')]),[])
    def test_window_includes_300_seconds(self):
        self.assertEqual(len(correlated([event(i,i) for i in range(3)]+[event(4,300,'success')])),1)
    def test_window_excludes_301_seconds(self):
        self.assertEqual(correlated([event(i,i) for i in range(3)]+[event(4,301,'success')]),[])
    def test_equal_timestamps_not_prior(self):
        self.assertEqual(correlated([event(i,0) for i in range(3)]+[event(4,0,'success')]),[])
    def test_user_isolation(self):
        self.assertEqual(correlated([event(i,i) for i in range(3)]+[event(4,4,'success',user='other')]),[])
    def test_source_isolation(self):
        self.assertEqual(correlated([event(i,i) for i in range(3)]+[event(4,4,'success',ip='192.0.2.9')]),[])
    def test_repeated_failure_one_per_bucket(self):
        result=detect([event(i,i) for i in range(8)])
        self.assertEqual(len([a for a in result if a['rule_id']=='AUTH-001']),1)
    def test_spray_requires_distinct_users(self):
        self.assertNotIn('AUTH-003',[a['rule_id'] for a in detect([event(i,i) for i in range(8)])])
    def test_spray_threshold(self):
        self.assertIn('AUTH-003',[a['rule_id'] for a in detect([event(i,i,user=str(i)) for i in range(5)])])
    def test_fixed_bin_boundary_limitation(self):
        self.assertNotIn('AUTH-001',[a['rule_id'] for a in detect([event(i,298+i) for i in range(5)])])
    def test_same_geography_not_flagged(self):
        self.assertEqual(detect([event(1,0,'success'),event(2,10,'success')]),[])
    def test_geo_change_at_hour(self):
        self.assertEqual(len(detect([event(1,0,'success'),event(2,3600,'success',geo='DE-BE')])),1)
    def test_geo_change_after_hour(self):
        self.assertEqual(detect([event(1,0,'success'),event(2,3601,'success',geo='DE-BE')]),[])
    def test_evidence_resolves(self):
        events=read_events(ROOT/'lab/auth_events.csv'); ids={e['event_id'] for e in events}
        for alert in detect(events): self.assertTrue(set(alert['evidence_event_ids']) <= ids)
    def test_timezone_normalization(self):
        self.assertEqual(timestamp('2026-10-01T01:00:00+01:00'),timestamp('2026-10-01T00:00:00Z'))
    def test_naive_time_rejected(self):
        with self.assertRaises(ValueError): timestamp('2026-10-01T00:00:00')

class InputTests(unittest.TestCase):
    def load(self, rows, fields=None):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'events.csv'
            with p.open('w',newline='') as f:
                w=csv.DictWriter(f,fieldnames=fields or list(event(1,0)));w.writeheader();w.writerows(rows)
            return read_events(p)
    def test_missing_columns(self):
        with self.assertRaises(ValueError): self.load([],['timestamp'])
    def test_duplicate_id(self):
        with self.assertRaises(ValueError): self.load([event(1,0),event(1,1)])
    def test_invalid_ip(self):
        with self.assertRaises(ValueError): self.load([event(1,0,ip='invalid')])
    def test_invalid_action(self):
        with self.assertRaises(ValueError): self.load([event(1,0,action='unknown')])
    def test_empty_username(self):
        with self.assertRaises(ValueError): self.load([event(1,0,user='')])
    def test_bad_date(self):
        e=event(1,0);e['timestamp']='nonsense'
        with self.assertRaises(ValueError): self.load([e])
    def test_header_only(self): self.assertEqual(self.load([]),[])
