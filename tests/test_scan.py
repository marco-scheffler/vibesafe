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

    def test_markdown_marks_committed_secret(self):
        f = scan.Finding(tool="gitleaks", category="secrets", severity="critical",
                         title="leak", file="env/x.env", line=1)
        f.committed = True
        rep = scan.build_report([f], target="/x", run=["gitleaks"],
                                skipped=[], errored=[], duration_s=0.1)
        self.assertEqual(rep["summary"]["committed_secrets"], 1)
        self.assertIn("committed", scan.render_markdown(rep).lower())


class TestGitTracking(unittest.TestCase):
    def _repo(self):
        import subprocess as sp
        d = Path(tempfile.mkdtemp())
        sp.run(["git", "-C", str(d), "init", "-q"], check=True)
        sp.run(["git", "-C", str(d), "config", "user.email", "t@t"], check=True)
        sp.run(["git", "-C", str(d), "config", "user.name", "t"], check=True)
        return d

    def test_tracked_vs_untracked(self):
        import subprocess as sp
        d = self._repo()
        (d / "tracked.txt").write_text("x")
        sp.run(["git", "-C", str(d), "add", "tracked.txt"], check=True)
        sp.run(["git", "-C", str(d), "commit", "-qm", "x"], check=True)
        (d / "untracked.txt").write_text("y")
        tr = scan.tracked_abs_paths(d)
        self.assertIsNotNone(tr)
        self.assertIn(str((d / "tracked.txt").resolve()), tr)
        self.assertNotIn(str((d / "untracked.txt").resolve()), tr)

    def test_non_repo_returns_none(self):
        self.assertIsNone(scan.tracked_abs_paths(Path(tempfile.mkdtemp())))

    def test_annotate_sets_committed(self):
        import subprocess as sp
        d = self._repo()
        (d / "c.env").write_text("KEY=abc")
        sp.run(["git", "-C", str(d), "add", "c.env"], check=True)
        sp.run(["git", "-C", str(d), "commit", "-qm", "x"], check=True)
        (d / "local.env").write_text("KEY=def")
        findings = [
            scan.Finding(tool="gitleaks", category="secrets", severity="critical",
                         title="a", file="c.env", line=1),
            scan.Finding(tool="gitleaks", category="secrets", severity="critical",
                         title="b", file="local.env", line=1),
        ]
        scan.annotate_committed(findings, d, scan.tracked_abs_paths(d))
        self.assertIs(findings[0].committed, True)
        self.assertIs(findings[1].committed, False)


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
        # When gitleaks is installed it must actually catch the planted secret,
        # and flag it as committed (the fixture is tracked in this repo).
        if "gitleaks" in rep["summary"]["scanners_run"]:
            secs = [f for f in rep["findings"] if f["category"] == "secrets"]
            self.assertTrue(secs)
            self.assertTrue(all(f.get("committed") is True for f in secs))
            self.assertGreaterEqual(rep["summary"]["committed_secrets"], 1)


class TestFingerprint(unittest.TestCase):
    def test_line_independent_and_stable(self):
        a = scan.Finding(tool="semgrep", category="sast", severity="high",
                         title="Detected eval", file="app.py", line=42, rule_id="r1")
        b = scan.Finding(tool="semgrep", category="sast", severity="high",
                         title="Detected eval", file="app.py", line=99, rule_id="r1")
        self.assertEqual(scan.compute_fingerprint(a), scan.compute_fingerprint(b))

    def test_differs_by_rule_and_file(self):
        a = scan.Finding(tool="t", category="sast", severity="high", title="x",
                         file="app.py", rule_id="r1")
        b = scan.Finding(tool="t", category="sast", severity="high", title="x",
                         file="app.py", rule_id="r2")
        c = scan.Finding(tool="t", category="sast", severity="high", title="x",
                         file="other.py", rule_id="r1")
        self.assertNotEqual(scan.compute_fingerprint(a), scan.compute_fingerprint(b))
        self.assertNotEqual(scan.compute_fingerprint(a), scan.compute_fingerprint(c))

    def test_annotate_sets_field_and_in_report(self):
        fs = [scan.Finding(tool="t", category="sast", severity="high", title="x", file="a.py")]
        scan.annotate_fingerprints(fs)
        self.assertTrue(fs[0].fingerprint)
        self.assertIn("fingerprint", scan.finding_to_dict(fs[0]))


class TestBaseline(unittest.TestCase):
    def _fs(self):
        fs = [scan.Finding(tool="t", category="sast", severity="high", title="x", file="a.py"),
              scan.Finding(tool="t", category="deps", severity="low", title="y", package="lodash")]
        scan.annotate_fingerprints(fs)
        return fs

    def test_apply_baseline_filters_known(self):
        fs = self._fs()
        known = {fs[0].fingerprint}
        kept, n = scan.apply_baseline(fs, known)
        self.assertEqual(n, 1)
        self.assertEqual([f.title for f in kept], ["y"])

    def test_missing_file_is_empty_no_error(self):
        self.assertEqual(scan.load_baseline("/no/such/file.json"), set())

    def test_write_then_load_roundtrip(self):
        fs = self._fs()
        p = Path(tempfile.mkdtemp()) / "vibesafe-baseline.json"
        scan.write_baseline(p, fs, target="/x")
        loaded = scan.load_baseline(p)
        self.assertEqual(loaded, {f.fingerprint for f in fs})


class TestIgnore(unittest.TestCase):
    def _write(self, text):
        p = Path(tempfile.mkdtemp()) / ".vibesafeignore"
        p.write_text(text)
        return p

    def test_parse_prefixes_and_bare_glob(self):
        p = self._write("# c\n\npath:src/*.js\nrule:CKV_DOCKER_3\ncve:CVE-2021-23337\ntests/*\n")
        rules = scan.load_ignore_rules(p)
        self.assertIn(("path", "src/*.js"), rules)
        self.assertIn(("rule", "CKV_DOCKER_3"), rules)
        self.assertIn(("cve", "cve-2021-23337"), rules)
        self.assertIn(("path", "tests/*"), rules)

    def test_apply_suppresses(self):
        fs = [
            scan.Finding(tool="t", category="secrets", severity="critical", title="s", file="src/config.js"),
            scan.Finding(tool="t", category="iac", severity="high", title="i", file="Dockerfile", rule_id="CKV_DOCKER_3"),
            scan.Finding(tool="t", category="deps", severity="high", title="d", package="lodash", cve="CVE-2021-23337"),
            scan.Finding(tool="t", category="sast", severity="high", title="keep", file="app.py"),
        ]
        rules = [("path", "src/*.js"), ("rule", "CKV_DOCKER_3"), ("cve", "cve-2021-23337")]
        kept, n = scan.apply_ignore(fs, rules)
        self.assertEqual(n, 3)
        self.assertEqual([f.title for f in kept], ["keep"])


class TestDiffFilter(unittest.TestCase):
    def test_manifest_detection(self):
        self.assertTrue(scan._is_manifest("package-lock.json"))
        self.assertTrue(scan._is_manifest("sub/requirements-dev.txt"))
        self.assertTrue(scan._is_manifest("go.mod"))
        self.assertFalse(scan._is_manifest("src/app.py"))

    def test_keeps_only_changed_files(self):
        fs = [
            scan.Finding(tool="t", category="sast", severity="high", title="a", file="app.py"),
            scan.Finding(tool="t", category="sast", severity="high", title="b", file="./untouched.py"),
        ]
        kept = scan.apply_diff_filter(fs, {"app.py"})
        self.assertEqual([f.title for f in kept], ["a"])

    def test_fileless_dep_kept_only_if_manifest_changed(self):
        dep = scan.Finding(tool="npm-audit", category="deps", severity="high", title="d", package="lodash")
        self.assertEqual(scan.apply_diff_filter([dep], {"src/app.py"}), [])
        self.assertEqual(len(scan.apply_diff_filter([dep], {"package-lock.json"})), 1)


class TestGating(unittest.TestCase):
    def _rep(self, sevs, errored=None):
        fs = [scan.Finding(tool="t", category="sast", severity=s, title=s) for s in sevs]
        return scan.build_report(fs, target="/x", run=["semgrep"], skipped=[],
                                 errored=errored or [], duration_s=0.1)

    def test_no_flags_is_ok(self):
        self.assertEqual(scan.gating_exit(self._rep(["high"]), None, False), scan.EXIT_OK)

    def test_fail_on_high_triggers(self):
        self.assertEqual(scan.gating_exit(self._rep(["high"]), "high", False), scan.EXIT_FINDINGS)
        self.assertEqual(scan.gating_exit(self._rep(["medium"]), "high", False), scan.EXIT_OK)

    def test_tool_error_gating_and_precedence(self):
        errored = [{"tool": "trivy", "reason": "timeout"}]
        self.assertEqual(scan.gating_exit(self._rep(["low"], errored), None, True), scan.EXIT_TOOL_ERROR)
        # policy failure takes precedence over tool-error
        self.assertEqual(scan.gating_exit(self._rep(["high"], errored), "high", True), scan.EXIT_FINDINGS)

    def test_summary_carries_scope_fields(self):
        rep = scan.build_report([], target="/x", run=[], skipped=[], errored=[],
                                duration_s=0.1, scope="staged", changed_files=3, ignored=2, baselined=1)
        s = rep["summary"]
        self.assertEqual((s["scope"], s["changed_files"], s["ignored"], s["baselined"]), ("staged", 3, 2, 1))


class TestMainWiring(unittest.TestCase):
    def test_default_exit_zero_and_scope_full(self):
        d = Path(tempfile.mkdtemp()); out = Path(tempfile.mkdtemp())
        rc = scan.main(["--out-dir", str(out), str(d)])
        self.assertEqual(rc, scan.EXIT_OK)
        rep = json.loads((out / "report.json").read_text())
        self.assertEqual(rep["summary"]["scope"], "full")
        for k in ("ignored", "baselined", "changed_files"):
            self.assertIn(k, rep["summary"])

    def test_update_baseline_writes_and_exits_ok(self):
        d = Path(tempfile.mkdtemp()); out = Path(tempfile.mkdtemp())
        bl = Path(tempfile.mkdtemp()) / "vibesafe-baseline.json"
        rc = scan.main(["--out-dir", str(out), "--update-baseline", str(bl), str(d)])
        self.assertEqual(rc, scan.EXIT_OK)
        self.assertTrue(bl.exists())
        self.assertIn("fingerprints", json.loads(bl.read_text()))

    def test_baseline_and_update_are_mutually_exclusive(self):
        d = Path(tempfile.mkdtemp())
        with self.assertRaises(SystemExit):
            scan.main(["--baseline", "a.json", "--update-baseline", "b.json", str(d)])

    def test_staged_and_diff_are_mutually_exclusive(self):
        d = Path(tempfile.mkdtemp())
        with self.assertRaises(SystemExit):
            scan.main(["--staged", "--diff", "HEAD", str(d)])


class TestDedup(unittest.TestCase):
    def _dup(self, tool, sev, committed=None):
        return scan.Finding(tool=tool, category="deps", severity=sev, title="lodash CVE",
                            package="lodash", rule_id="CVE-2021-23337", committed=committed)

    def test_merges_same_fingerprint_keeps_most_severe(self):
        fs = [self._dup("npm-audit", "medium"), self._dup("trivy", "high"),
              self._dup("osv-scanner", "low")]
        scan.annotate_fingerprints(fs)
        out, removed = scan.dedupe_findings(fs)
        self.assertEqual(removed, 2)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "high")
        self.assertEqual(out[0].tool, "trivy")
        self.assertEqual(out[0].also_reported_by, ["npm-audit", "osv-scanner"])

    def test_distinct_fingerprints_untouched(self):
        fs = [scan.Finding(tool="t", category="sast", severity="high", title="a", file="a.py"),
              scan.Finding(tool="t", category="sast", severity="high", title="b", file="b.py")]
        scan.annotate_fingerprints(fs)
        out, removed = scan.dedupe_findings(fs)
        self.assertEqual((len(out), removed), (2, 0))
        self.assertIsNone(out[0].also_reported_by)

    def test_committed_flag_ors_across_group(self):
        fs = [self._dup("gitleaks", "critical", committed=False),
              self._dup("trivy", "critical", committed=True)]
        scan.annotate_fingerprints(fs)
        out, _ = scan.dedupe_findings(fs)
        self.assertTrue(out[0].committed)

    def test_markdown_shows_also_reported_by(self):
        f = scan.Finding(tool="trivy", category="deps", severity="high", title="lodash CVE",
                         package="lodash", also_reported_by=["npm-audit", "osv-scanner"])
        rep = scan.build_report([f], target="/x", run=["trivy"], skipped=[], errored=[], duration_s=0.1)
        md = scan.render_markdown(rep)
        self.assertIn("(also: npm-audit, osv-scanner)", md)

    def test_build_report_carries_deduped(self):
        rep = scan.build_report([], target="/x", run=[], skipped=[], errored=[],
                                duration_s=0.1, deduped=3)
        self.assertEqual(rep["summary"]["deduped"], 3)


class TestWorkerCount(unittest.TestCase):
    def test_values(self):
        self.assertEqual(scan.worker_count(3, 1), 1)   # sequential
        self.assertEqual(scan.worker_count(3, 0), 3)   # all at once
        self.assertEqual(scan.worker_count(3, 4), 3)   # capped by job count
        self.assertEqual(scan.worker_count(5, 4), 4)   # capped by flag
        self.assertEqual(scan.worker_count(0, 0), 1)   # no jobs → 1


class TestParallelEquivalence(unittest.TestCase):
    def _fps(self, jobs):
        out = Path(tempfile.mkdtemp())
        fixture = Path(__file__).resolve().parent / "fixtures" / "vulnerable-app"
        rc = scan.main(["--jobs", str(jobs), "--out-dir", str(out), str(fixture)])
        self.assertEqual(rc, scan.EXIT_OK)
        rep = json.loads((out / "report.json").read_text())
        fps = sorted(f["fingerprint"] for f in rep["findings"])
        run = sorted(rep["summary"]["scanners_run"])
        return fps, run

    def test_sequential_equals_parallel(self):
        seq_fps, seq_run = self._fps(1)     # sequential
        par_fps, par_run = self._fps(0)     # all at once
        self.assertEqual(seq_fps, par_fps)
        self.assertEqual(seq_run, par_run)


class TestNoDedupFlag(unittest.TestCase):
    def test_no_dedup_reports_zero_deduped(self):
        d = Path(tempfile.mkdtemp()); out = Path(tempfile.mkdtemp())
        rc = scan.main(["--no-dedup", "--out-dir", str(out), str(d)])
        self.assertEqual(rc, scan.EXIT_OK)
        rep = json.loads((out / "report.json").read_text())
        self.assertEqual(rep["summary"]["deduped"], 0)


class TestNormalizePaths(unittest.TestCase):
    def test_absolute_under_target_becomes_relative(self):
        target = Path(tempfile.mkdtemp())
        f = scan.Finding(tool="osv-scanner", category="deps", severity="high", title="x",
                         file=str(target / "sub" / "package-lock.json"))
        scan.normalize_finding_paths([f], target)
        self.assertEqual(f.file, "sub/package-lock.json")

    def test_dotslash_stripped_and_none_ok(self):
        f = scan.Finding(tool="t", category="sast", severity="high", title="x", file="./a.py")
        g = scan.Finding(tool="t", category="deps", severity="high", title="y", package="p")
        scan.normalize_finding_paths([f, g], "/whatever")
        self.assertEqual(f.file, "a.py")
        self.assertIsNone(g.file)


class TestDedupCrossTool(unittest.TestCase):
    def test_merges_title_independent_across_tools(self):
        a = scan.Finding(tool="osv-scanner", category="deps", severity="high",
                         title="lodash: prototype pollution", package="lodash",
                         cve="CVE-2021-23337", file="package-lock.json")
        b = scan.Finding(tool="trivy", category="deps", severity="critical",
                         title="Command injection in lodash", package="lodash",
                         cve="CVE-2021-23337", file="package-lock.json")
        out, removed = scan.dedupe_findings([a, b])
        self.assertEqual(removed, 1)
        self.assertEqual(out[0].severity, "critical")        # trivy (more severe) = primary
        self.assertEqual(out[0].also_reported_by, ["osv-scanner"])

    def test_different_lines_not_merged(self):
        a = scan.Finding(tool="semgrep", category="sast", severity="high", title="SQLi",
                         file="app.py", line=10, rule_id="sql")
        b = scan.Finding(tool="semgrep", category="sast", severity="high", title="SQLi",
                         file="app.py", line=20, rule_id="sql")
        out, removed = scan.dedupe_findings([a, b])
        self.assertEqual((len(out), removed), (2, 0))


class TestSarif(unittest.TestCase):
    def _rep(self, findings):
        return scan.build_report(findings, target="/x", run=[], skipped=[], errored=[], duration_s=0.1)

    def test_top_level_and_one_run_per_tool(self):
        fs = [
            scan.Finding(tool="gitleaks", category="secrets", severity="critical", title="secret", file="a.js", line=3, rule_id="aws"),
            scan.Finding(tool="semgrep", category="sast", severity="high", title="eval", file="b.py", line=5, rule_id="eval"),
            scan.Finding(tool="gitleaks", category="secrets", severity="critical", title="secret2", file="c.js", line=9, rule_id="gcp"),
        ]
        s = scan.build_sarif(self._rep(fs))
        self.assertEqual(s["version"], "2.1.0")
        self.assertIn("$schema", s)
        self.assertEqual(sorted(r["tool"]["driver"]["name"] for r in s["runs"]), ["gitleaks", "semgrep"])

    def test_level_mapping_and_location(self):
        f = scan.Finding(tool="semgrep", category="sast", severity="medium", title="x", file="b.py", line=7, rule_id="r")
        res = scan.build_sarif(self._rep([f]))["runs"][0]["results"][0]
        self.assertEqual(res["level"], "warning")
        loc = res["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "b.py")
        self.assertEqual(loc["region"]["startLine"], 7)

    def test_fileless_has_no_location(self):
        f = scan.Finding(tool="npm-audit", category="deps", severity="high", title="lodash", package="lodash")
        self.assertNotIn("locations", scan.build_sarif(self._rep([f]))["runs"][0]["results"][0])

    def test_rule_descriptor_fields(self):
        f = scan.Finding(tool="trivy", category="iac", severity="high", title="root user", file="Dockerfile", line=1, rule_id="DS002", remediation="Add USER")
        rule = scan.build_sarif(self._rep([f]))["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["id"], "DS002")
        for k in ("shortDescription", "fullDescription", "help"):
            self.assertIn("text", rule[k])
        self.assertEqual(rule["help"]["text"], "Add USER")

    def test_ruleid_fallback_and_properties(self):
        f = scan.Finding(tool="x", category="sast", severity="low", title="t")
        res = scan.build_sarif(self._rep([f]))["runs"][0]["results"][0]
        self.assertEqual(res["ruleId"], "sast/x")
        self.assertEqual(res["level"], "note")
        self.assertEqual(res["properties"]["category"], "sast")


class TestSarifMain(unittest.TestCase):
    def test_main_writes_sarif(self):
        d = Path(tempfile.mkdtemp()); out = Path(tempfile.mkdtemp())
        scan.main(["--out-dir", str(out), str(d)])
        s = json.loads((out / "report.sarif").read_text())
        self.assertEqual(s["version"], "2.1.0")
        self.assertIn("runs", s)


class TestDetectGoRust(unittest.TestCase):
    def _mk(self, *names):
        d = Path(tempfile.mkdtemp())
        for n in names:
            (d / n).write_text("x")
        return d

    def test_go_and_rust(self):
        self.assertTrue(scan.detect_stack(self._mk("go.mod"))["go"])
        self.assertTrue(scan.detect_stack(self._mk("Cargo.lock"))["rust"])

    def test_empty_neither(self):
        s = scan.detect_stack(Path(tempfile.mkdtemp()))
        self.assertFalse(s["go"]); self.assertFalse(s["rust"])


class TestCargoAudit(unittest.TestCase):
    def test_normalize(self):
        fs = scan.normalize_cargo_audit(raw("cargo-audit.json"))
        self.assertEqual(len(fs), 1)
        f = fs[0]
        self.assertEqual((f.category, f.tool), ("deps", "cargo-audit"))
        self.assertEqual(f.package, "time")
        self.assertEqual(f.cve, "CVE-2020-26235")
        self.assertEqual(f.file, "Cargo.lock")
        self.assertIn(">=0.2.23", f.remediation)


class TestGovulncheck(unittest.TestCase):
    def test_normalize(self):
        fs = scan.normalize_govulncheck(raw("govulncheck-sarif.json"))
        self.assertEqual(len(fs), 1)
        f = fs[0]
        self.assertEqual((f.category, f.tool, f.severity), ("deps", "govulncheck", "high"))
        self.assertEqual(f.rule_id, "GO-2021-0113")
        self.assertEqual(f.file, "go.mod")
        self.assertEqual(f.line, 1)


class TestPlanGoRust(unittest.TestCase):
    def _tools(self, **stack):
        base = {"node": False, "python": False, "docker": False, "terraform": False,
                "git": False, "go": False, "rust": False}
        base.update(stack)
        return [j[0] for j in scan._plan(base, only=set())]

    def test_go_rust_jobs_present(self):
        self.assertIn("govulncheck", self._tools(go=True))
        self.assertIn("cargo-audit", self._tools(rust=True))
        self.assertNotIn("govulncheck", self._tools())

    def test_only_deps_keeps_them(self):
        tools = self._tools(go=True, rust=True)
        # re-filter through --only deps
        base = {"node": False, "python": False, "docker": False, "terraform": False,
                "git": False, "go": True, "rust": True}
        only = [j[0] for j in scan._plan(base, only={"deps"})]
        self.assertIn("govulncheck", only)
        self.assertIn("cargo-audit", only)


if __name__ == "__main__":
    unittest.main()
