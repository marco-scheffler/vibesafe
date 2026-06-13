import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import scan  # noqa: E402

RAW = Path(__file__).resolve().parent / "fixtures" / "raw"


def raw(name):
    return json.loads((RAW / name).read_text())


class TestModel(unittest.TestCase):
    def test_finding_to_dict_keeps_none_keys(self):
        f = scan.Finding(tool="gitleaks", category="secrets", severity="critical", title="x")
        d = scan.finding_to_dict(f)
        self.assertEqual(d["tool"], "gitleaks")
        self.assertIn("file", d)
        self.assertIsNone(d["file"])

    def test_severity_sort(self):
        order = sorted(["low", "critical", "medium", "info", "high"], key=scan.severity_sort_key)
        self.assertEqual(order, ["critical", "high", "medium", "low", "info"])

    def test_normalize_severity_aliases(self):
        self.assertEqual(scan.normalize_severity("MODERATE"), "medium")
        self.assertEqual(scan.normalize_severity("ERROR"), "high")
        self.assertEqual(scan.normalize_severity("warning"), "medium")
        self.assertEqual(scan.normalize_severity("UNKNOWN"), "info")
        self.assertEqual(scan.normalize_severity("CRITICAL"), "critical")
        self.assertEqual(scan.normalize_severity(None), "info")


class TestDetect(unittest.TestCase):
    def _mk(self, *names):
        d = Path(tempfile.mkdtemp())
        for n in names:
            p = d / n
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("{}")
        return d

    def test_detect_multi(self):
        d = self._mk("package.json", "requirements.txt", "Dockerfile", "infra/main.tf")
        s = scan.detect_stack(d)
        self.assertTrue(s["node"])
        self.assertTrue(s["python"])
        self.assertTrue(s["docker"])
        self.assertTrue(s["terraform"])

    def test_detect_empty(self):
        d = Path(tempfile.mkdtemp())
        s = scan.detect_stack(d)
        self.assertFalse(s["node"])
        self.assertFalse(s["python"])
        self.assertFalse(s["docker"])
        self.assertFalse(s["terraform"])


class TestResolve(unittest.TestCase):
    def test_installed_binary_preferred(self):
        self.assertEqual(scan.resolve_runner("python3")[0], "python3")

    def test_python_tool_uses_uvx_or_pipx(self):
        cmd = scan.resolve_runner("semgrep", have=lambda t: t == "uvx", allow_ephemeral=True)
        self.assertEqual(cmd, ["uvx", "semgrep"])
        cmd = scan.resolve_runner("semgrep", have=lambda t: t == "pipx", allow_ephemeral=True)
        self.assertEqual(cmd, ["pipx", "run", "semgrep"])

    def test_native_missing_returns_none(self):
        self.assertIsNone(scan.resolve_runner("gitleaks", have=lambda t: False))

    def test_no_ephemeral_blocks_fallback(self):
        self.assertIsNone(
            scan.resolve_runner("semgrep", have=lambda t: t == "uvx", allow_ephemeral=False))

    def test_run_tool_timeout(self):
        rc, out, err, status = scan.run_tool(["sleep", "5"], cwd=".", timeout=1)
        self.assertEqual(status, "timeout")


class TestDepNormalizers(unittest.TestCase):
    def test_npm(self):
        fs = scan.normalize_npm_audit(raw("npm-audit.json"))
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].category, "deps")
        self.assertEqual(fs[0].package, "lodash")
        self.assertEqual(fs[0].severity, "high")
        self.assertIn("GHSA", (fs[0].cve or ""))

    def test_pip(self):
        fs = scan.normalize_pip_audit(raw("pip-audit.json"))
        self.assertEqual(fs[0].package, "jinja2")
        self.assertEqual(fs[0].cve, "CVE-2020-28493")
        self.assertIn("2.11.3", fs[0].remediation)

    def test_osv(self):
        fs = scan.normalize_osv(raw("osv-scanner.json"))
        self.assertEqual(fs[0].package, "golang.org/x/text")
        self.assertEqual(fs[0].severity, "high")


class TestSecretsSast(unittest.TestCase):
    def test_gitleaks_redacts(self):
        fs = scan.normalize_gitleaks(raw("gitleaks.json"))
        self.assertEqual(fs[0].category, "secrets")
        self.assertEqual(fs[0].severity, "critical")
        self.assertEqual(fs[0].file, "src/config.js")
        self.assertEqual(fs[0].line, 12)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", json.dumps(scan.finding_to_dict(fs[0])))

    def test_semgrep(self):
        fs = scan.normalize_semgrep(raw("semgrep.json"))
        self.assertEqual(fs[0].category, "sast")
        self.assertEqual(fs[0].severity, "high")
        self.assertEqual(fs[0].line, 42)
        self.assertEqual(fs[0].rule_id, "python.lang.security.audit.dangerous-eval")


class TestIacLicense(unittest.TestCase):
    def test_trivy(self):
        fs = scan.normalize_trivy(raw("trivy.json"))
        cats = sorted({f.category for f in fs})
        self.assertEqual(cats, ["deps", "iac", "license"])
        iac = [f for f in fs if f.category == "iac"][0]
        self.assertEqual(iac.line, 1)
        self.assertEqual(iac.severity, "high")

    def test_checkov(self):
        fs = scan.normalize_checkov(raw("checkov.json"))
        self.assertEqual(fs[0].category, "iac")
        self.assertEqual(fs[0].rule_id, "CKV_DOCKER_3")
        self.assertEqual(fs[0].line, 1)


class TestReport(unittest.TestCase):
    def test_build_and_sort(self):
        findings = [
            scan.Finding(tool="t", category="deps", severity="low", title="a"),
            scan.Finding(tool="t", category="sast", severity="critical", title="b"),
        ]
        rep = scan.build_report(
            findings, target="/x", run=["semgrep"],
            skipped=[{"tool": "trivy", "reason": "not installed", "install": "brew install trivy"}],
            errored=[], duration_s=1.2)
        self.assertEqual(rep["summary"]["critical"], 1)
        self.assertEqual(rep["summary"]["low"], 1)
        self.assertEqual(rep["findings"][0]["severity"], "critical")
        self.assertEqual(rep["summary"]["scanners_skipped"][0]["tool"], "trivy")

    def test_markdown(self):
        rep = scan.build_report(
            [scan.Finding(tool="t", category="sast", severity="high",
                          title="X", file="a.py", line=3)],
            target="/x", run=["semgrep"], skipped=[], errored=[], duration_s=0.1)
        md = scan.render_markdown(rep)
        self.assertIn("| Severity |", md)
        self.assertIn("a.py:3", md)
        self.assertIn("Coverage", md)


class TestCli(unittest.TestCase):
    def setUp(self):
        os.environ["VIBESAFE_NO_EPHEMERAL"] = "1"

    def tearDown(self):
        os.environ.pop("VIBESAFE_NO_EPHEMERAL", None)

    def test_main_empty_dir(self):
        d = Path(tempfile.mkdtemp())
        out = Path(tempfile.mkdtemp())
        rc = scan.main(["--out-dir", str(out), str(d)])
        self.assertEqual(rc, 0)
        rep = json.loads((out / "report.json").read_text())
        self.assertIn("summary", rep)
        self.assertIsInstance(rep["findings"], list)


class TestIntegration(unittest.TestCase):
    """End-to-end against the vulnerable fixture.

    Runs the secrets layer (gitleaks, a native binary that runs even under
    VIBESAFE_NO_EPHEMERAL). Asserts the redaction + no-silent-masking invariants;
    when gitleaks is installed it must actually detect the planted secret. On
    machines without gitleaks the scanner is skipped and the invariants still hold.
    """

    def setUp(self):
        os.environ["VIBESAFE_NO_EPHEMERAL"] = "1"

    def tearDown(self):
        os.environ.pop("VIBESAFE_NO_EPHEMERAL", None)

    def test_scan_fixture_secrets_layer(self):
        fixture = Path(__file__).resolve().parent / "fixtures" / "vulnerable-app"
        out = Path(tempfile.mkdtemp())
        rc = scan.main(["--only", "secrets", "--out-dir", str(out), str(fixture)])
        self.assertEqual(rc, 0)
        report_text = (out / "report.json").read_text()
        # The planted secret value must NEVER appear in the report (redaction).
        self.assertNotIn("a3f5c9e1b7d2486094a1c8e5f2b6d0a3c7e9f1b4d6082a5c", report_text)
        rep = json.loads(report_text)
        # A fatal tool failure must never be masked as "ran with 0 findings".
        self.assertEqual(rep["summary"]["scanners_errored"], [])
        # When gitleaks is installed it must actually catch the planted secret.
        if "gitleaks" in rep["summary"]["scanners_run"]:
            self.assertIn("secrets", {f["category"] for f in rep["findings"]})


if __name__ == "__main__":
    unittest.main()
