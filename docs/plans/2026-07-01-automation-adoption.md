# vibesafe Automation & Adoption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add CI with real detection proof, opt-in severity exit-codes + GitHub Action + pre-commit hook, and Bestandscode-fähige Baseline/Ignore + Diff-Scan to vibesafe.

**Architecture:** Extend the existing single-file stdlib orchestrator `scripts/scan.py` with pure, individually-testable post-processing functions (fingerprint → diff-filter → ignore → baseline → gating), wired into `main()` in a fixed order. Add repo-level automation artifacts (`.github/workflows/ci.yml`, `action.yml`, `.pre-commit-hooks.yaml`) and docs. No new runtime dependencies.

**Tech Stack:** Python 3 stdlib only (add `hashlib`, `fnmatch` to existing imports). Tests: stdlib `unittest`. GitHub Actions YAML. pre-commit hook manifest.

**Reference:** Spec at `docs/specs/2026-07-01-vibesafe-automation-design.md`.

## Global Constraints

- Python **stdlib only** — no third-party imports in `scripts/scan.py`.
- **Backwards compatible:** without any new flag, `scan.main()` returns exit code `0` exactly as before.
- Commit messages: **plain, no attribution** (no Co-Authored-By, no AI mention).
- Stage explicitly by path — never `git add -A` / `git add .`.
- Findings never store secret values (redaction is a hard requirement).
- Version target: **1.4.0**.
- Test bootstrap already in `tests/test_scan.py`: `sys.path.insert(0, .../scripts); import scan`.
- Run tests: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest discover -s tests -v`.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `scripts/scan.py` | + fingerprint, baseline, ignore, diff-filter, gating; `main()` wiring + new args | Modify |
| `tests/test_scan.py` | + unit tests for all new pure functions + main() wiring | Modify |
| `tests/test_live_detection.py` | Real-scanner detection proof (skipUnless `VIBESAFE_LIVE`) | Create |
| `.github/workflows/ci.yml` | `test` (hermetic matrix) + `live-detection` jobs | Create |
| `action.yml` | Composite GitHub Action wrapping `scan.py` | Create |
| `.pre-commit-hooks.yaml` | `vibesafe` staged-scan hook | Create |
| `references/automation.md` | CI / Action / pre-commit / exit-codes / baseline / ignore / diff docs | Create |
| `SKILL.md` | Mode-2 flags + pointer to automation.md | Modify |
| `references/tools.md` | Short exit-code/baseline note | Modify |
| `README.md` | CI badge + "Automate it" section + version 1.4.0 | Modify |
| `CHANGELOG.md` | 1.4.0 entry | Create |
| `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` | version → 1.4.0 | Modify |
| `tests/run-tests.sh` | note live-detection env | Modify |
| `docs/roadmap.md` | tick off delivered items | Modify |

---

## Task 1: Fingerprint

**Files:** Modify `scripts/scan.py`; Test `tests/test_scan.py`

**Interfaces:**
- Produces: `Finding.fingerprint: str | None`, `compute_fingerprint(f) -> str`, `annotate_fingerprints(findings) -> None`.

- [ ] **Step 1: Failing test** — append to `tests/test_scan.py`:

```python
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
```

- [ ] **Step 2: Run → FAIL** — `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest tests.test_scan -v` (AttributeError).

- [ ] **Step 3: Implement** — in `scripts/scan.py`: add `import hashlib` to the top import block; add `fingerprint: str | None = None` as the last field of `@dataclass class Finding`; add after `finding_to_dict`:

```python
def compute_fingerprint(f) -> str:
    """Stable, line-independent id for a finding (baseline/dedup basis)."""
    norm_title = (f.title or "").strip().lower()[:200]
    basis = "|".join([
        f.category or "",
        f.rule_id or f.cve or "",
        f.package or "",
        f.file or "",
        norm_title,
    ])
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]


def annotate_fingerprints(findings) -> None:
    for f in findings:
        f.fingerprint = compute_fingerprint(f)
```

- [ ] **Step 4: Run → PASS** (`tests.test_scan.TestFingerprint`).

- [ ] **Step 5: Commit**

```bash
git add scripts/scan.py tests/test_scan.py
git commit -m "Add stable per-finding fingerprint"
```

---

## Task 2: Baseline (load / apply / write)

**Files:** Modify `scripts/scan.py`; Test `tests/test_scan.py`

**Interfaces:**
- Consumes: `Finding.fingerprint`.
- Produces: `load_baseline(path) -> set`, `apply_baseline(findings, fps) -> (list, int)`, `write_baseline(path, findings, target) -> None`.

- [ ] **Step 1: Failing test**:

```python
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
```

- [ ] **Step 2: Run → FAIL**.

- [ ] **Step 3: Implement** — add to `scripts/scan.py`:

```python
def load_baseline(path) -> set:
    if not path:
        return set()
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return set()
    return set(data.get("fingerprints") or [])


def apply_baseline(findings, baseline_fps):
    if not baseline_fps:
        return findings, 0
    kept = [f for f in findings if f.fingerprint not in baseline_fps]
    return kept, len(findings) - len(kept)


def write_baseline(path, findings, target) -> None:
    fps = sorted({f.fingerprint for f in findings if f.fingerprint})
    Path(path).write_text(json.dumps(
        {"generated_from": str(target), "count": len(fps), "fingerprints": fps},
        indent=2))
```

- [ ] **Step 4: Run → PASS**.

- [ ] **Step 5: Commit** `git add scripts/scan.py tests/test_scan.py && git commit -m "Add fingerprint baseline load/apply/write"`

---

## Task 3: `.vibesafeignore`

**Files:** Modify `scripts/scan.py`; Test `tests/test_scan.py`

**Interfaces:**
- Produces: `load_ignore_rules(path) -> list[(kind, pattern)]`, `apply_ignore(findings, rules) -> (list, int)`.

- [ ] **Step 1: Failing test**:

```python
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
```

- [ ] **Step 2: Run → FAIL**.

- [ ] **Step 3: Implement** — add `import fnmatch` to the import block; add:

```python
def load_ignore_rules(path):
    """Parse .vibesafeignore → list of (kind, pattern), kind ∈ path|rule|cve."""
    rules = []
    try:
        lines = Path(path).read_text().splitlines()
    except OSError:
        return rules
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("path:"):
            rules.append(("path", line[5:].strip()))
        elif line.startswith("rule:"):
            rules.append(("rule", line[5:].strip()))
        elif line.startswith("cve:"):
            rules.append(("cve", line[4:].strip().lower()))
        else:
            rules.append(("path", line))
    return rules


def _rel_posix(file):
    fp = (file or "").replace("\\", "/")
    return fp[2:] if fp.startswith("./") else fp


def _matches_ignore(f, kind, pattern):
    if kind == "path":
        fp = _rel_posix(f.file)
        return bool(fp) and fnmatch.fnmatch(fp, pattern)
    if kind == "rule":
        return (f.rule_id or "") == pattern
    if kind == "cve":
        return (f.cve or "").lower() == pattern
    return False


def apply_ignore(findings, rules):
    if not rules:
        return findings, 0
    kept = [f for f in findings
            if not any(_matches_ignore(f, k, p) for k, p in rules)]
    return kept, len(findings) - len(kept)
```

- [ ] **Step 4: Run → PASS**.

- [ ] **Step 5: Commit** `git add scripts/scan.py tests/test_scan.py && git commit -m "Add .vibesafeignore suppression"`

---

## Task 4: Diff/staged post-filter

**Files:** Modify `scripts/scan.py`; Test `tests/test_scan.py`

**Interfaces:**
- Produces: `changed_files(target, staged=False, diff_ref=None) -> set|None`, `apply_diff_filter(findings, changed) -> list`, `_is_manifest(relpath) -> bool`.

- [ ] **Step 1: Failing test** (no real git needed — test the pure filter + manifest rule):

```python
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
```

- [ ] **Step 2: Run → FAIL**.

- [ ] **Step 3: Implement** — add:

```python
_MANIFESTS = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
              "pnpm-lock.yaml", "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock",
              "go.mod", "go.sum", "Cargo.lock", "composer.lock", "Gemfile.lock"}


def _is_manifest(relpath) -> bool:
    base = relpath.replace("\\", "/").rsplit("/", 1)[-1]
    if base in _MANIFESTS:
        return True
    return base.startswith("requirements") and base.endswith(".txt")


def _git_lines(args, cwd):
    try:
        r = subprocess.run(["git", "-C", str(cwd)] + args,
                           capture_output=True, text=True, timeout=30)
    except Exception:
        return None
    if r.returncode != 0:
        return None
    return [l.strip() for l in r.stdout.splitlines() if l.strip()]


def changed_files(target, staged=False, diff_ref=None):
    """Set of posix paths (relative to `target`) that changed, or None if git fails."""
    if staged:
        args = ["diff", "--cached", "--name-only"]
    elif diff_ref:
        args = ["diff", "--name-only", diff_ref]
    else:
        return None
    target = Path(target)
    root = _git_lines(["rev-parse", "--show-toplevel"], target)
    names = _git_lines(args, target)
    if not root or names is None:
        return None
    root = Path(root[0])
    out = set()
    for n in names:
        try:
            rel = os.path.relpath((root / n).resolve(), target.resolve()).replace("\\", "/")
        except Exception:
            continue
        if not rel.startswith("../"):
            out.add(rel)
    return out


def apply_diff_filter(findings, changed):
    """Keep findings in changed files; file-less findings only if a manifest changed."""
    manifest_changed = any(_is_manifest(c) for c in changed)
    kept = []
    for f in findings:
        if f.file:
            if _rel_posix(f.file) in changed:
                kept.append(f)
        elif manifest_changed:
            kept.append(f)
    return kept
```

- [ ] **Step 4: Run → PASS**.

- [ ] **Step 5: Commit** `git add scripts/scan.py tests/test_scan.py && git commit -m "Add diff/staged post-filter"`

---

## Task 5: Report summary fields + `--fail-on` gating

**Files:** Modify `scripts/scan.py`; Test `tests/test_scan.py`

**Interfaces:**
- Consumes: existing `build_report`, `severity_sort_key`.
- Produces: `EXIT_OK=0`, `EXIT_FINDINGS=1`, `EXIT_TOOL_ERROR=3`, `gating_exit(rep, fail_on, fail_on_error) -> int`; `build_report(..., scope="full", changed_files=None, ignored=0, baselined=0)`.

- [ ] **Step 1: Failing test**:

```python
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
```

- [ ] **Step 2: Run → FAIL**.

- [ ] **Step 3: Implement** — add exit constants near `SEVERITIES`:

```python
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_TOOL_ERROR = 3
```

Change `build_report` signature and summary dict to include the new fields:

```python
def build_report(findings, target, run, skipped, errored, duration_s,
                 scope="full", changed_files=None, ignored=0, baselined=0) -> dict:
    findings = sorted(findings, key=lambda f: severity_sort_key(f.severity))
    counts = {s: 0 for s in SEVERITIES}
    committed_secrets = 0
    for f in findings:
        counts[normalize_severity(f.severity)] += 1
        if f.category == "secrets" and getattr(f, "committed", None):
            committed_secrets += 1
    return {
        "summary": {
            **counts,
            "total": len(findings),
            "committed_secrets": committed_secrets,
            "scope": scope,
            "changed_files": changed_files,
            "ignored": ignored,
            "baselined": baselined,
            "scanners_run": run,
            "scanners_skipped": skipped,
            "scanners_errored": errored,
            "duration_s": round(duration_s, 2),
            "target": str(target),
        },
        "findings": [finding_to_dict(f) for f in findings],
    }
```

Add the gating helper:

```python
def gating_exit(rep, fail_on, fail_on_error) -> int:
    if fail_on:
        threshold = severity_sort_key(fail_on)
        for f in rep["findings"]:
            if severity_sort_key(f["severity"]) <= threshold:
                return EXIT_FINDINGS
    if fail_on_error and rep["summary"]["scanners_errored"]:
        return EXIT_TOOL_ERROR
    return EXIT_OK
```

- [ ] **Step 4: Run → PASS**. Also confirm existing `TestReport` still passes (extra summary keys don't break it).

- [ ] **Step 5: Commit** `git add scripts/scan.py tests/test_scan.py && git commit -m "Add scope summary fields and severity gating exit codes"`

---

## Task 6: Wire post-processing into `main()`

**Files:** Modify `scripts/scan.py`; Test `tests/test_scan.py`

**Interfaces:**
- Consumes: all of Tasks 1–5.
- Produces: `main()` accepting `--fail-on`, `--fail-on-error`, `--baseline`, `--update-baseline`, `--staged`, `--diff`, `--ignore-file`; returns `EXIT_*`.

- [ ] **Step 1: Failing tests** (end-to-end via `main()` on an empty dir + a temp findings-injected path is overkill; test the observable contract):

```python
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
```

- [ ] **Step 2: Run → FAIL**.

- [ ] **Step 3: Implement** — add the args in `main()`'s argparse block (after `--no-install-hints`):

```python
    ap.add_argument("--fail-on", default=None,
                    choices=["critical", "high", "medium", "low", "info"])
    ap.add_argument("--fail-on-error", action="store_true")
    ap.add_argument("--baseline", default=None)
    ap.add_argument("--update-baseline", nargs="?", const="vibesafe-baseline.json", default=None)
    ap.add_argument("--ignore-file", default=None)
    ap.add_argument("--staged", action="store_true")
    ap.add_argument("--diff", default=None, metavar="REF")
```

After `a = ap.parse_args(argv)`, add mutual-exclusion guards:

```python
    if a.baseline and a.update_baseline:
        ap.error("--baseline and --update-baseline are mutually exclusive")
    if a.staged and a.diff:
        ap.error("--staged and --diff are mutually exclusive")
```

Replace the tail of `main()` (from `annotate_committed(...)` through `return 0`) with the ordered pipeline:

```python
    # ---- post-processing pipeline (order matters; see spec §4.6) ----
    annotate_committed(findings, target, tracked_abs_paths(target))
    annotate_fingerprints(findings)

    scope, changed_n = "full", None
    if a.staged or a.diff:
        changed = changed_files(target, staged=a.staged, diff_ref=a.diff)
        if changed is None:
            print("[vibesafe] diff/staged requested but git is unavailable — nothing to diff.")
            changed = set()
        findings = apply_diff_filter(findings, changed)
        scope = "staged" if a.staged else f"diff:{a.diff}"
        changed_n = len(changed)

    ignore_path = a.ignore_file or (target / ".vibesafeignore")
    findings, ignored_n = apply_ignore(findings, load_ignore_rules(ignore_path))

    if a.update_baseline:
        write_baseline(a.update_baseline, findings, target)
        print(f"[vibesafe] baseline written: {a.update_baseline} ({len(findings)} fingerprints)")
        return EXIT_OK

    findings, baselined_n = apply_baseline(findings, load_baseline(a.baseline))

    rep = build_report(findings, target, run, skipped, errored, time.time() - t0,
                       scope=scope, changed_files=changed_n,
                       ignored=ignored_n, baselined=baselined_n)
    (out_dir / "report.json").write_text(json.dumps(rep, indent=2))
    md = render_markdown(rep)
    (out_dir / "report.md").write_text(md)
    print(md)
    print(f"\n[vibesafe] report: {out_dir}/report.json")
    return gating_exit(rep, a.fail_on, a.fail_on_error)
```

Note: `--update-baseline` writes the fingerprints of the findings **after** diff+ignore filtering but **before** baseline subtraction (there is no baseline in update mode). This is intentional: it snapshots the current, in-scope, non-ignored findings.

- [ ] **Step 4: Run → PASS**; then full suite: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest discover -s tests -v` → all green.

- [ ] **Step 5: Commit** `git add scripts/scan.py tests/test_scan.py && git commit -m "Wire fingerprint, diff, ignore, baseline and gating into main()"`

---

## Task 7: Live-detection test (real scanners)

**Files:** Create `tests/test_live_detection.py`

- [ ] **Step 1: Write the test** (skipped unless `VIBESAFE_LIVE=1`; proves detection per category, tolerant to rule-id drift):

```python
import os, sys, json, tempfile, unittest
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
        blob = (self.out / "report.json").read_text()
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", blob)

    def test_coverage_line_lists_scanners(self):
        self.assertTrue(self.rep["summary"]["scanners_run"])
```

> Note: the fixture's planted secret is a generic key; gitleaks reports it as "Generic API Key". `deps` requires npm to resolve lodash (the CI job runs `npm install --package-lock-only` first, see Task 8). `iac` requires trivy on the Dockerfile.

- [ ] **Step 2: Run locally to confirm skip** — `python3 -m unittest tests.test_live_detection -v` → `OK (skipped=6)`.

- [ ] **Step 3: Commit** `git add tests/test_live_detection.py && git commit -m "Add real-scanner live detection test (opt-in via VIBESAFE_LIVE)"`

---

## Task 8: GitHub Actions CI

**Files:** Create `.github/workflows/ci.yml`

- [ ] **Step 1: Write the workflow**:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    name: unit (hermetic)
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.8", "3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Run unit + integration tests (no network)
        env:
          VIBESAFE_NO_EPHEMERAL: "1"
        run: python -m unittest discover -s tests -v

  live-detection:
    name: live detection (real scanners)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install scanners
        run: |
          set -eux
          # gitleaks
          curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks
          # trivy
          curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
          # osv-scanner
          go install github.com/google/osv-scanner/cmd/osv-scanner@v1.8.5 || true
          echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"
          # semgrep (ephemeral runner)
          pipx install semgrep || pip install semgrep
      - name: Resolve lodash lockfile for the fixture (deps detection)
        working-directory: tests/fixtures/vulnerable-app
        run: npm install --package-lock-only
      - name: Prove detection
        env:
          VIBESAFE_LIVE: "1"
        run: python -m unittest tests.test_live_detection -v
```

> The `live-detection` job may occasionally be affected by upstream registry/DB availability; it asserts categories (not rule-ids) to stay robust. Keep `test` as the required status check; treat `live-detection` as informative.

- [ ] **Step 2: Validate YAML locally** — `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))" 2>/dev/null || echo "no pyyaml; skip"` (best-effort; GitHub validates on push).

- [ ] **Step 3: Commit** `git add .github/workflows/ci.yml && git commit -m "Add CI: hermetic unit matrix + live detection proof"`

---

## Task 9: GitHub Action

**Files:** Create `action.yml`

- [ ] **Step 1: Write the composite action**:

```yaml
name: vibesafe security scan
description: Run vibesafe's multi-scanner audit and optionally gate on severity.
branding:
  icon: shield
  color: purple
inputs:
  path:
    description: Path to scan.
    default: "."
  fail-on:
    description: Fail (non-zero) if a finding at or above this severity exists (critical|high|medium|low|info). Empty = never fail.
    default: ""
  only:
    description: Comma list of categories (secrets,deps,sast,iac,license).
    default: ""
  timeout:
    description: Per-tool timeout in seconds.
    default: "120"
runs:
  using: composite
  steps:
    - name: Run vibesafe scan
      shell: bash
      run: |
        set -eo pipefail
        args=("${{ inputs.path }}" --out-dir "$RUNNER_TEMP/vibesafe" --timeout "${{ inputs.timeout }}")
        [ -n "${{ inputs.fail-on }}" ] && args+=(--fail-on "${{ inputs.fail-on }}")
        [ -n "${{ inputs.only }}" ] && args+=(--only "${{ inputs.only }}")
        python3 "$GITHUB_ACTION_PATH/scripts/scan.py" "${args[@]}"
    - name: Upload report
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: vibesafe-report
        path: ${{ runner.temp }}/vibesafe/report.*
        if-no-files-found: ignore
```

> The action ships `scan.py` but not the scanners — the caller installs whichever engines they want (documented in `references/automation.md`); missing engines degrade gracefully.

- [ ] **Step 2: Commit** `git add action.yml && git commit -m "Add composite GitHub Action wrapping scan.py"`

---

## Task 10: pre-commit hook

**Files:** Create `.pre-commit-hooks.yaml`

- [ ] **Step 1: Write the hook manifest**:

```yaml
- id: vibesafe
  name: vibesafe security scan (staged)
  description: Scan staged changes for secrets, vulnerable deps, SAST, IaC and license issues.
  entry: python3 scripts/scan.py --staged --fail-on high
  language: system
  pass_filenames: false
  always_run: true
```

- [ ] **Step 2: Commit** `git add .pre-commit-hooks.yaml && git commit -m "Add pre-commit hook (staged scan, fail on high)"`

---

## Task 11: `references/automation.md`

**Files:** Create `references/automation.md`

- [ ] **Step 1: Write the doc** — cover: exit codes table (0/1/3), `--fail-on`/`--fail-on-error`; baseline workflow (`--update-baseline` then `--baseline`), fingerprint line-independence trade-off; `.vibesafeignore` format (path:/rule:/cve:/bare glob); diff/staged (`--staged`, `--diff REF`, file-less-dep manifest rule); GitHub Action usage snippet (`uses: marco-scheffler/vibesafe@v1.4.0` with `fail-on`); pre-commit usage snippet (`repo: https://github.com/marco-scheffler/vibesafe`, `rev: v1.4.0`, `hooks: - id: vibesafe`) + note that scanners must be on PATH; CI note that engines are installed by the caller.

- [ ] **Step 2: Commit** `git add references/automation.md && git commit -m "Document CI, Action, pre-commit, exit codes, baseline and diff"`

---

## Task 12: SKILL.md + tools.md pointers

**Files:** Modify `SKILL.md`, `references/tools.md`

- [ ] **Step 1: SKILL.md** — under Mode 2, add a short bullet after the `--only/--timeout/--out-dir` line: mention `--fail-on`, `--staged`/`--diff`, `--baseline`/`--update-baseline`, `.vibesafeignore`, and that automation details live in `references/automation.md`. Keep it ≤4 lines (progressive disclosure).

- [ ] **Step 2: references/tools.md** — add one line under "Scanning behavior": exit codes are opt-in via `--fail-on`; baseline/ignore/diff documented in `automation.md`.

- [ ] **Step 3: Commit** `git add SKILL.md references/tools.md && git commit -m "Point SKILL.md and tools.md at automation features"`

---

## Task 13: README + CHANGELOG + version bump

**Files:** Modify `README.md`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`; Create `CHANGELOG.md`

- [ ] **Step 1: README** — bump the version badge to `1.4.0`; add a CI badge line
  `![CI](https://github.com/marco-scheffler/vibesafe/actions/workflows/ci.yml/badge.svg)`;
  add an "## Automate it (CI / pre-commit)" section with the Action snippet + pre-commit snippet + a one-liner on `--fail-on`/baseline, linking `references/automation.md`.

- [ ] **Step 2: Version bump** — set `"version": "1.4.0"` in `.claude-plugin/plugin.json` and in the plugin entry of `.claude-plugin/marketplace.json`.

- [ ] **Step 3: CHANGELOG.md** — create with a `## 1.4.0 — 2026-07-01` entry listing: CI + live detection, `--fail-on`/exit codes, GitHub Action, pre-commit hook, fingerprint baseline + `.vibesafeignore`, diff/staged scan.

- [ ] **Step 4: Commit** `git add README.md CHANGELOG.md .claude-plugin/plugin.json .claude-plugin/marketplace.json && git commit -m "Bump to 1.4.0: CI badge, automate-it docs, changelog"`

---

## Task 14: Final verification + housekeeping

**Files:** Modify `tests/run-tests.sh`, `docs/roadmap.md`

- [ ] **Step 1: run-tests.sh** — add an echo noting live detection is opt-in: `echo "== (live detection: set VIBESAFE_LIVE=1 to run tests/test_live_detection.py) =="`.

- [ ] **Step 2: roadmap.md** — tick the delivered `Now — v1.4.0` checkboxes.

- [ ] **Step 3: Full hermetic suite green** — `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest discover -s tests -v` → all pass (skips for live).

- [ ] **Step 4: Local live smoke (best-effort, tools present on this machine)** — `VIBESAFE_LIVE=1 python3 -m unittest tests.test_live_detection -v` (semgrep/checkov may be absent → `deps`/`sast` from other engines still assert; if a category is genuinely uncovered locally, note it, don't fake it).

- [ ] **Step 5: Commit** `git add tests/run-tests.sh docs/roadmap.md && git commit -m "Note live-detection opt-in and tick delivered roadmap items"`

---

## Self-Review (against spec)

**Spec coverage:**
- §4.1 exit codes → Task 5 (constants + `gating_exit`), Task 6 (`return gating_exit`). ✓
- §4.2 fingerprint → Task 1. ✓
- §4.3 baseline → Task 2 + Task 6 wiring (`--baseline`/`--update-baseline`). ✓
- §4.4 `.vibesafeignore` → Task 3 + Task 6 (`--ignore-file` / default path). ✓
- §4.5 diff/staged post-filter + file-less-dep rule → Task 4 + Task 6. ✓
- §4.6 pipeline order → Task 6 (annotate → fingerprint → diff → ignore → update-baseline early-exit → baseline → report → gating). ✓
- §5 CI (test + live-detection) → Task 8; §5.1 live test → Task 7. ✓
- §6 Action → Task 9. §7 pre-commit → Task 10. ✓
- §8 docs/version → Tasks 11–13. §9 tests → Tasks 1–7. ✓

**Placeholder scan:** all code steps carry full code; doc tasks (11–13) are prose with explicit required content. No "TBD".

**Type consistency:** `Finding.fingerprint`, `compute_fingerprint`, `annotate_fingerprints`, `apply_baseline/load_baseline/write_baseline`, `load_ignore_rules/apply_ignore`, `_rel_posix`, `changed_files/apply_diff_filter/_is_manifest`, `gating_exit`, `EXIT_*`, and the extended `build_report(...)` signature are used identically across tasks. `_rel_posix` is defined in Task 3 and reused in Task 4 (Task 4 must run after Task 3 — order preserved).
```
