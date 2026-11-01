"""Security regression: never broadly exempt secrets from historical scanning."""
import tomllib
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
EXACT="6713e7d969f060862a94b03db103d6d7a02b10ee:evidence/manifest.json:generic-api-key:12"

class LeakPolicyTests(unittest.TestCase):
    def test_default_gitleaks_rules_remain_enabled(self):
        config=tomllib.loads((ROOT/".gitleaks.toml").read_text(encoding="utf-8"))
        self.assertTrue(config["extend"]["useDefault"])

    def test_only_exact_historical_checksum_fingerprint_is_exempted(self):
        config=tomllib.loads((ROOT/".gitleaks.toml").read_text(encoding="utf-8"))
        self.assertEqual(len(config["allowlists"]),1)
        entry=config["allowlists"][0]
        self.assertEqual(entry["fingerprints"],[EXACT])
        self.assertNotIn("paths",entry)
        self.assertNotIn("regexes",entry)
        self.assertNotIn("stopwords",entry)
        self.assertNotIn("commits",entry)
