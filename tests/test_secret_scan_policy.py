"""Security regression: default detection rules and one fingerprint-level false positive."""
import tomllib
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
EXACT="6713e7d969f060862a94b03db103d6d7a02b10ee:evidence/manifest.json:generic-api-key:12"

class LeakPolicyTests(unittest.TestCase):
    def test_default_gitleaks_rules_remain_enabled(self):
        config=tomllib.loads((ROOT/".gitleaks.toml").read_text(encoding="utf-8"))
        self.assertTrue(config["extend"]["useDefault"])
        self.assertNotIn("allowlists",config)
        self.assertNotIn("rules",config)

    def test_ignore_file_only_has_single_historical_checksum_fingerprint(self):
        entries=[line.strip() for line in (ROOT/".gitleaksignore").read_text(encoding="utf-8").splitlines()
                 if line.strip() and not line.strip().startswith("#")]
        self.assertEqual(entries,[EXACT])
