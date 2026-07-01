"""Live detection proof — runs the REAL scanners against the vulnerable fixture.

Skipped unless VIBESAFE_LIVE=1 (so the default/hermetic suite stays offline and
fast). CI runs this in a dedicated job with gitleaks/semgrep/trivy/osv installed.
It asserts *categories* (not rule-ids, which drift across tool releases) so it
proves detection without being brittle.

The fixture is copied OUT of the repo's tests/ tree before scanning: semgrep
ignores tests/ paths by default, so an in-tree scan would never exercise SAST.
A lockfile is generated in the copy (best-effort) so dependency scanners can
resolve the planted vulnerable package.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import scan  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "vulnerable-app"
SECRET_VALUE = "a3f5c9e1b7d2486094a1c8e5f2b6d0a3c7e9f1b4d6082a5c"  # planted in config.js


@unittest.skipUnless(os.environ.get("VIBESAFE_LIVE"), "set VIBESAFE_LIVE=1 to run")
class TestLiveDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Copy the fixture out of tests/ — semgrep ignores tests/ by default.
        cls.work = Path(tempfile.mkdtemp()) / "vulnerable-app"
        shutil.copytree(FIXTURE, cls.work)
        # Best-effort lockfile so dependency scanners can resolve lodash.
        cls.have_lockfile = False
        try:
            subprocess.run(["npm", "install", "--package-lock-only"],
                           cwd=cls.work, capture_output=True, timeout=180, check=True)
            cls.have_lockfile = (cls.work / "package-lock.json").exists()
        except Exception:
            pass
        cls.out = Path(tempfile.mkdtemp())
        cls.rc = scan.main(["--out-dir", str(cls.out), str(cls.work)])
        cls.report_text = (cls.out / "report.json").read_text()
        cls.rep = json.loads(cls.report_text)
        cls.cats = {f["category"] for f in cls.rep["findings"]}

    def test_scan_exited_ok(self):
        self.assertEqual(self.rc, scan.EXIT_OK)  # no --fail-on → always 0

    def test_secret_detected(self):
        self.assertIn("secrets", self.cats)

    def test_sast_detected(self):
        self.assertIn("sast", self.cats)

    def test_iac_detected(self):
        self.assertIn("iac", self.cats)

    def test_deps_detected(self):
        if not self.have_lockfile:
            self.skipTest("no lockfile could be generated (npm unavailable)")
        self.assertIn("deps", self.cats)

    def test_secret_value_never_leaks(self):
        self.assertNotIn(SECRET_VALUE, self.report_text)

    def test_coverage_line_lists_scanners(self):
        self.assertTrue(self.rep["summary"]["scanners_run"])


FIXTURES = Path(__file__).resolve().parent / "fixtures"


@unittest.skipUnless(os.environ.get("VIBESAFE_LIVE"), "set VIBESAFE_LIVE=1 to run")
class TestLiveGoRust(unittest.TestCase):
    """Proves govulncheck (Go) and cargo-audit (Rust) run and flag the planted vulns.
    Assertions use scanners_run + a finding, so they're robust to which tool wins
    cross-tool dedup (cargo-audit and osv-scanner both flag the Rust crate)."""

    @classmethod
    def _scan(cls, name):
        work = Path(tempfile.mkdtemp()) / name
        shutil.copytree(FIXTURES / name, work)
        out = Path(tempfile.mkdtemp())
        scan.main(["--only", "deps", "--out-dir", str(out), str(work)])
        return json.loads((out / "report.json").read_text())

    @classmethod
    def setUpClass(cls):
        cls.go = cls._scan("go-app")
        cls.rust = cls._scan("rust-app")

    def test_go_govulncheck_ran_and_flagged(self):
        self.assertIn("govulncheck", self.go["summary"]["scanners_run"])
        self.assertTrue(any(str(f.get("rule_id", "")).startswith("GO-")
                            for f in self.go["findings"]))

    def test_rust_cargo_audit_ran_and_flagged(self):
        self.assertIn("cargo-audit", self.rust["summary"]["scanners_run"])
        self.assertTrue(any(f.get("package") == "time" for f in self.rust["findings"]))


@unittest.skipUnless(os.environ.get("VIBESAFE_LIVE"), "set VIBESAFE_LIVE=1 to run")
class TestLiveRubyPhpJava(unittest.TestCase):
    """Proves bundler-audit (Ruby), composer audit (PHP) and osv-scanner (Java) run and
    flag the planted vulns. Assertions use scanners_run + a finding, so they're robust to
    which tool wins cross-tool dedup."""

    php_have_lock = False

    @classmethod
    def _scan(cls, name, prepare=None):
        work = Path(tempfile.mkdtemp()) / name
        shutil.copytree(FIXTURES / name, work)
        if prepare:
            prepare(work)
        out = Path(tempfile.mkdtemp())
        scan.main(["--only", "deps", "--out-dir", str(out), str(work)])
        return json.loads((out / "report.json").read_text())

    @classmethod
    def _gen_composer_lock(cls, work):
        try:
            subprocess.run(["composer", "update", "--no-install", "--no-audit", "--quiet"],
                           cwd=work, capture_output=True, timeout=180, check=True)
            cls.php_have_lock = (work / "composer.lock").exists()
        except Exception:
            pass

    @classmethod
    def setUpClass(cls):
        cls.ruby = cls._scan("ruby-app")
        cls.php = cls._scan("php-app", prepare=cls._gen_composer_lock)
        cls.java = cls._scan("java-app")

    def test_ruby_bundler_audit_ran_and_flagged(self):
        self.assertIn("bundler-audit", self.ruby["summary"]["scanners_run"])
        self.assertTrue(any(f.get("package") == "rack" for f in self.ruby["findings"]))

    def test_php_composer_audit_ran_and_flagged(self):
        if not self.php_have_lock:
            self.skipTest("no composer.lock could be generated (composer unavailable)")
        self.assertIn("composer-audit", self.php["summary"]["scanners_run"])
        self.assertTrue(any(f.get("package") == "guzzlehttp/guzzle"
                            for f in self.php["findings"]))

    def test_java_osv_ran_and_flagged(self):
        self.assertIn("osv-scanner", self.java["summary"]["scanners_run"])
        self.assertTrue(any("log4j" in str(f.get("package") or f.get("title") or "").lower()
                            for f in self.java["findings"]))


if __name__ == "__main__":
    unittest.main()
