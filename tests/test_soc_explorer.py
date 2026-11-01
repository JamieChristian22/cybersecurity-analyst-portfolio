"""Ensure browser triage evidence remains identical to the tested SOC fixtures."""
import csv
import json
import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

from lab.detections import detect, read_events

ROOT=Path(__file__).resolve().parents[1]
HTML=ROOT/"demo/soc-investigation.html"

class Markup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids=set()
        self.labels=set()
        self.remote=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if "id" in a:
            assert a["id"] not in self.ids
            self.ids.add(a["id"])
        if tag=="label" and "for" in a:
            self.labels.add(a["for"])
        if tag=="script" and "src" in a:
            self.remote.append(a["src"])

class SOCExplorerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page=HTML.read_text(encoding="utf-8")
        match=re.search(r'<script id="soc-data" type="application/json">(.*?)</script>',cls.page,re.DOTALL)
        if not match:
            raise AssertionError("Missing embedded SOC evidence")
        cls.data=json.loads(match.group(1))

    def test_every_event_matches_canonical_csv(self):
        with (ROOT/"lab/auth_events.csv").open(encoding="utf-8",newline="") as f:
            truth=list(csv.DictReader(f))
        self.assertEqual(self.data["events"],truth)
        self.assertEqual(len(truth),23)
        self.assertEqual(len({e["event_id"] for e in truth}),23)

    def test_alerts_match_committed_evidence_and_expected_identities(self):
        alerts=self.data["alerts"]
        self.assertEqual(alerts,json.loads((ROOT/"evidence/alerts.json").read_text()))
        self.assertEqual(self.data["expected"],json.loads((ROOT/"lab/expected_alerts.json").read_text()))
        self.assertEqual(len(alerts),4)
        self.assertEqual([{"rule_id":a["rule_id"],"event_id":a["event_id"]} for a in alerts],self.data["expected"])

    def test_reference_detector_agrees_with_embedded_alerts(self):
        self.assertEqual(detect(read_events(ROOT/"lab/auth_events.csv")),self.data["alerts"])

    def test_evidence_links_are_complete_and_timestamps_ordered(self):
        by_id={e["event_id"]:e for e in self.data["events"]}
        for a in self.data["alerts"]:
            with self.subTest(rule=a["rule_id"]):
                self.assertIn(a["event_id"],by_id)
                self.assertEqual(a["timestamp"],by_id[a["event_id"]]["timestamp"])
                self.assertIn(a["event_id"],a["evidence_event_ids"])
                self.assertTrue(set(a["evidence_event_ids"]).issubset(by_id))
                self.assertEqual(len(a["evidence_event_ids"]),len(set(a["evidence_event_ids"])))

    def test_accessible_safe_offline_controls(self):
        parser=Markup()
        parser.feed(self.page)
        self.assertTrue({"search","rule","severity","disposition","notes"}.issubset(parser.ids))
        self.assertTrue({"search","rule","severity","disposition","notes"}.issubset(parser.labels))
        self.assertTrue({"copy","clear"}.issubset(parser.ids))
        self.assertIn('aria-live="polite"',self.page)
        self.assertIn("textContent",self.page)
        self.assertIn("replaceChildren",self.page)
        self.assertNotIn("innerHTML",self.page)
        self.assertNotIn("fetch(",self.page)
        self.assertFalse(parser.remote)
        self.assertIn("no production telemetry",self.data["scope"].lower())
