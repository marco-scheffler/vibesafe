"""Live detection proof — runs the REAL scanners against the vulnerable fixture.

Skipped unless VIBESAFE_LIVE=1 (so the default/hermetic suite stays offline and
fast). CI runs this in a dedicated job with gitleaks/semgrep/trivy/osv installed.
It asserts *categories* (not rule-ids, which drift across tool releases) so it
proves detection without being brittle.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import scan  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "vulnerable-app"


@unittest.skipUnless(os.environ.get("VIBESAFE_LIVE"), "set VIBESAFE_LIVE=1 to run")
class TestLiveDetection(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp())
        rc = scan.main(["--out-dir", str(self.out), str(FIXTURE)])
        self.assertEqual(rc, scan.EXIT_OK)  # no --fail-on → always 0
        self.rep = json.loads((self.out / "report.json").read_text())
        self.cats = {f["category"] for f in self.rep["findings"]}

    def test_secret_detected(self):
        self.assertIn("secrets", self.cats)

    def test_sast_detected(self):
        self.assertIn("sast", self.cats)

    def test_deps_detected(self):
        self.assertIn("deps", self.cats)

    def test_iac_detected(self):
        self.assertIn("iac", self.cats)

    def test_secret_value_never_leaks(self):
        # The exact secret value planted in fixtures/vulnerable-app/config.js.
        blob = (self.out / "report.json").read_text()
        self.assertNotIn("a3f5c9e1b7d2486094a1c8e5f2b6d0a3c7e9f1b4d6082a5c", blob)

    def test_coverage_line_lists_scanners(self):
        self.assertTrue(self.rep["summary"]["scanners_run"])


if __name__ == "__main__":
    unittest.main()
