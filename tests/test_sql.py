import sqlite3
import unittest
from pathlib import Path
from test_detections import event
SQL=(Path(__file__).resolve().parents[1]/'lab/correlation.sql').read_text()

class SQLTests(unittest.TestCase):
    def query(self,events):
        with sqlite3.connect(':memory:') as c:
            c.execute('CREATE TABLE auth_events (event_id TEXT, timestamp TEXT, username TEXT, src_ip TEXT, action TEXT, geo TEXT)')
            c.executemany('INSERT INTO auth_events VALUES (:event_id,:timestamp,:username,:src_ip,:action,:geo)',events)
            return c.execute(SQL).fetchall()
    def test_success_after_three_failures(self):
        rows=self.query([event(i,i) for i in range(3)]+[event(4,4,'success')])
        self.assertEqual(len(rows),1);self.assertEqual(rows[0][-1],3)
    def test_success_first(self):
        self.assertEqual(self.query([event(0,0,'success')]+[event(i,i) for i in range(1,4)]),[])
    def test_time_boundary_included(self):
        self.assertEqual(len(self.query([event(i,i) for i in range(3)]+[event(4,300,'success')])),1)
    def test_expired_failure(self):
        self.assertEqual(self.query([event(i,i) for i in range(3)]+[event(4,301,'success')]),[])
    def test_equal_times_excluded(self):
        self.assertEqual(self.query([event(i,0) for i in range(3)]+[event(4,0,'success')]),[])
    def test_different_user(self):
        self.assertEqual(self.query([event(i,i) for i in range(3)]+[event(4,4,'success',user='other')]),[])
