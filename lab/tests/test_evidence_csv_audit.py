"""Offline regression tests for the CSV evidence checker."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "tools/evidence_csv_audit.py"
spec = importlib.util.spec_from_file_location("evidence_csv_audit", MODULE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class EvidenceAuditTests(unittest.TestCase):
    def test_valid(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "events.csv"
            p.write_text("event_id,status\\n1,ok\\n2,fail\\n".replace("\\n", "\n"))
            result = module.audit(p, ["event_id", "status"], ["event_id"])
            self.assertEqual(result["rows"], 2)
            self.assertEqual(result["duplicate_keys"], 0)
            self.assertEqual(len(result["sha256"]), 64)

    def test_duplicate_and_blank(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "events.csv"
            p.write_text("event_id,status\\n1,ok\\n1,\\n".replace("\\n", "\n"))
            result = module.audit(p, ["event_id", "status"], ["event_id"])
            self.assertEqual(result["duplicate_keys"], 1)
            self.assertEqual(result["blank_required"]["status"], 1)

    def test_missing_key_column(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "events.csv"
            p.write_text("status\\nok\\n".replace("\\n", "\n"))
            with self.assertRaises(ValueError):
                module.audit(p, [], ["event_id"])

if __name__ == "__main__":
    unittest.main()
