"""Malformed CSV regression cases must fail before SOC alert generation."""
import tempfile
import unittest
from pathlib import Path

from lab.detections import read_events

HEADER="event_id,timestamp,username,src_ip,action,geo"
VALID="E01,2026-10-01T00:00:00Z,alex,203.0.113.10,failure,US-NC"

class StrictCSVIngestionTests(unittest.TestCase):
    def parse(self,text):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"events.csv"
            p.write_text(text,encoding="utf-8")
            return read_events(p)

    def test_unnamed_extra_column_rejected(self):
        with self.assertRaisesRegex(ValueError,"unexpected extra CSV fields"):
            self.parse(HEADER+"\n"+VALID+",attacker-injected-field\n")

    def test_duplicate_header_rejected(self):
        with self.assertRaisesRegex(ValueError,"duplicate CSV header"):
            self.parse(HEADER+",username\n"+VALID+",an-ambiguous-name\n")

    def test_valid_fixture_still_parses(self):
        events=self.parse(HEADER+"\n"+VALID+"\n")
        self.assertEqual(len(events),1)
        self.assertEqual(events[0]["event_id"],"E01")
