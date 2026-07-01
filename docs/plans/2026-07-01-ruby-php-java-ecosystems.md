# Ruby + PHP + Java Ecosystems Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect Ruby/PHP/Java projects and run `bundler-audit` (Ruby) and `composer audit` (PHP) as dedicated dependency scanners (Java via the already-generic `osv-scanner`), normalized into the existing Finding schema; plus a JS refinement so `npm audit` only runs with a lockfile.

**Architecture:** Extend `detect_stack` with `ruby`/`php`/`java`/`npm_lock`; add two defensive normalizers (`normalize_bundler_audit`, `normalize_composer_audit`); wire two conditional jobs into `_plan` and re-gate `npm`; surface detected ecosystems in `summary["stack"]`; prove end-to-end detection in CI with real tools (live fixtures) exactly as the Go/Rust feature did. Cross-tool dedup handles overlap with osv.

**Tech Stack:** Python 3 stdlib only. Tests: stdlib `unittest`.

**Reference:** Spec at `docs/specs/2026-07-01-vibesafe-ruby-php-java-design.md`.

## Global Constraints

- **Python stdlib only** in `scripts/scan.py`. No third-party imports.
- Normalizers must be **defensive** (`.get()` everywhere) — tool JSON is not locally verifiable.
- Commit messages **plain, no AI/tool attribution**. Stage by **explicit path** (never `git add -A`/`.`).
- Version target **1.8.0**.
- Run hermetic tests: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest discover -s tests -v`.
- Run one test: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest tests.test_scan.<Class>.<method> -v`.
- Live tests are `@skipUnless(VIBESAFE_LIVE)` and only run in CI with real tools installed.

---

## Task 1: Detect Ruby / PHP / Java / npm_lock

**Files:**
- Modify: `scripts/scan.py` (`detect_stack`, scan.py:292-308)
- Test: `tests/test_scan.py`

**Interfaces:**
- Produces: `detect_stack(path)` returns a dict that additionally contains the boolean keys
  `"ruby"`, `"php"`, `"java"`, `"npm_lock"`. `"node"` keeps its existing meaning.

- [ ] **Step 1: Write the failing test** (append to `tests/test_scan.py`, before `if __name__`):

```python
class TestDetectRubyPhpJava(unittest.TestCase):
    def _mk(self, *names):
        d = Path(tempfile.mkdtemp())
        for n in names:
            (d / n).write_text("x")
        return d

    def test_ruby_php_java_npm_lock(self):
        self.assertTrue(scan.detect_stack(self._mk("Gemfile.lock"))["ruby"])
        self.assertTrue(scan.detect_stack(self._mk("composer.json"))["php"])
        self.assertTrue(scan.detect_stack(self._mk("pom.xml"))["java"])
        self.assertTrue(scan.detect_stack(self._mk("package-lock.json"))["npm_lock"])

    def test_empty_all_false(self):
        s = scan.detect_stack(Path(tempfile.mkdtemp()))
        for k in ("ruby", "php", "java", "npm_lock"):
            self.assertFalse(s[k])

    def test_node_without_lock_has_no_npm_lock(self):
        s = scan.detect_stack(self._mk("package.json"))
        self.assertTrue(s["node"])
        self.assertFalse(s["npm_lock"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest tests.test_scan.TestDetectRubyPhpJava -v`
Expected: FAIL with `KeyError: 'ruby'`.

- [ ] **Step 3: Write minimal implementation**

In `detect_stack`, add these keys inside the returned dict (after the `"rust"` line, before `"git"`):

```python
        "ruby": (path / "Gemfile.lock").exists() or has("Gemfile.lock", "Gemfile"),
        "php": (path / "composer.json").exists() or has("composer.json", "composer.lock"),
        "java": has("pom.xml", "build.gradle", "build.gradle.kts"),
        "npm_lock": (any((path / f).exists()
                         for f in ("package-lock.json", "npm-shrinkwrap.json"))
                     or has("package-lock.json", "npm-shrinkwrap.json")),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest tests.test_scan.TestDetectRubyPhpJava -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add scripts/scan.py tests/test_scan.py
git commit -m "Detect Ruby/PHP/Java projects and npm lockfile presence"
```

---

## Task 2: `normalize_bundler_audit`

**Files:**
- Create: `tests/fixtures/raw/bundler-audit.json`
- Modify: `scripts/scan.py` (add normalizer + `_BUNDLER_SEV` near `normalize_cargo_audit`, scan.py:494)
- Test: `tests/test_scan.py`

**Interfaces:**
- Consumes: `Finding`, `_first_cve` (existing).
- Produces: `normalize_bundler_audit(raw) -> list[Finding]` with `tool="bundler-audit"`,
  `category="deps"`, `file="Gemfile.lock"`.

- [ ] **Step 1: Create the raw fixture** `tests/fixtures/raw/bundler-audit.json` (real `report.to_h` shape; includes a second `insecure_source` result that must be ignored):

```json
{
  "version": "0.9.2",
  "created_at": "2026-01-01 00:00:00 +0000",
  "results": [
    {
      "type": "unpatched_gem",
      "gem": {"name": "rack", "version": "2.0.0"},
      "advisory": {
        "path": "/db/gems/rack/CVE-2022-30122.yml",
        "id": "CVE-2022-30122",
        "url": "https://github.com/advisories/GHSA-wq4h-9vvf-58wf",
        "title": "Denial of Service Vulnerability in Rack Multipart Parsing",
        "date": "2022-05-31",
        "description": "A DoS in rack multipart parsing.",
        "cvss_v2": null,
        "cvss_v3": 7.5,
        "cve": "2022-30122",
        "osvdb": null,
        "ghsa": "wq4h-9vvf-58wf",
        "unaffected_versions": [],
        "patched_versions": ["~> 2.0.9.1", ">= 2.1.4.1"],
        "criticality": "high"
      }
    },
    {
      "type": "insecure_source",
      "source": "http://rubygems.org/"
    }
  ]
}
```

- [ ] **Step 2: Write the failing test** (append to `tests/test_scan.py`):

```python
class TestBundlerAudit(unittest.TestCase):
    def test_normalize(self):
        fs = scan.normalize_bundler_audit(raw("bundler-audit.json"))
        self.assertEqual(len(fs), 1)          # insecure_source result ignored
        f = fs[0]
        self.assertEqual((f.category, f.tool), ("deps", "bundler-audit"))
        self.assertEqual(f.package, "rack")
        self.assertEqual(f.severity, "high")  # from criticality
        self.assertEqual(f.cve, "CVE-2022-30122")
        self.assertEqual(f.rule_id, "CVE-2022-30122")
        self.assertEqual(f.file, "Gemfile.lock")
        self.assertIn("2.0.9.1", f.remediation)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest tests.test_scan.TestBundlerAudit -v`
Expected: FAIL with `AttributeError: module 'scan' has no attribute 'normalize_bundler_audit'`.

- [ ] **Step 4: Write minimal implementation** (in `scripts/scan.py`, immediately after `normalize_cargo_audit`):

```python
_BUNDLER_SEV = {"critical": "critical", "high": "high", "medium": "medium",
                "low": "low", "none": "info"}


def normalize_bundler_audit(raw) -> list:
    out = []
    for r in raw.get("results") or []:
        if r.get("type") != "unpatched_gem":
            continue
        gem = r.get("gem") or {}
        adv = r.get("advisory") or {}
        patched = ", ".join(str(x) for x in (adv.get("patched_versions") or [])) \
            or "a patched version"
        cve_num = adv.get("cve")
        aliases = [adv.get("id"), (f"CVE-{cve_num}" if cve_num else None)]
        out.append(Finding(
            tool="bundler-audit", category="deps",
            severity=_BUNDLER_SEV.get(str(adv.get("criticality") or "").lower(), "high"),
            title=adv.get("title") or f"Vulnerable dependency: {gem.get('name')}",
            package=gem.get("name"), cve=_first_cve(aliases, adv.get("id")),
            rule_id=adv.get("id"), file="Gemfile.lock",
            remediation=f"Upgrade {gem.get('name')} to {patched}."))
    return out
```

- [ ] **Step 5: Run test to verify it passes**

Run: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest tests.test_scan.TestBundlerAudit -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/scan.py tests/test_scan.py tests/fixtures/raw/bundler-audit.json
git commit -m "Normalize bundler-audit JSON into Finding schema"
```

---

## Task 3: `normalize_composer_audit`

**Files:**
- Create: `tests/fixtures/raw/composer-audit.json`
- Modify: `scripts/scan.py` (add normalizer after `normalize_bundler_audit`)
- Test: `tests/test_scan.py`

**Interfaces:**
- Consumes: `Finding`, `_first_cve` (existing).
- Produces: `normalize_composer_audit(raw) -> list[Finding]` with `tool="composer-audit"`,
  `category="deps"`, `file="composer.lock"`.

- [ ] **Step 1: Create the raw fixture** `tests/fixtures/raw/composer-audit.json` (real `composer audit --format=json` shape):

```json
{
  "advisories": {
    "guzzlehttp/guzzle": [
      {
        "advisoryId": "PKSA-1234-5678-9012",
        "packageName": "guzzlehttp/guzzle",
        "affectedVersions": ">=6.0.0,<6.5.8|>=7.0.0,<7.4.5",
        "title": "CVE-2022-31090: Cross-domain cookie leakage",
        "cve": "CVE-2022-31090",
        "link": "https://github.com/guzzle/guzzle/security/advisories/GHSA-25mq-v84f-6vm5",
        "reportedAt": "2022-06-20T22:24:00+00:00",
        "sources": [{"name": "GitHub", "remoteId": "GHSA-25mq-v84f-6vm5"}]
      }
    ]
  },
  "abandoned": {}
}
```

- [ ] **Step 2: Write the failing test** (append to `tests/test_scan.py`):

```python
class TestComposerAudit(unittest.TestCase):
    def test_normalize(self):
        fs = scan.normalize_composer_audit(raw("composer-audit.json"))
        self.assertEqual(len(fs), 1)
        f = fs[0]
        self.assertEqual((f.category, f.tool), ("deps", "composer-audit"))
        self.assertEqual(f.package, "guzzlehttp/guzzle")
        self.assertEqual(f.severity, "high")   # composer omits severity → default high
        self.assertEqual(f.cve, "CVE-2022-31090")
        self.assertEqual(f.rule_id, "PKSA-1234-5678-9012")
        self.assertEqual(f.file, "composer.lock")
        self.assertIn("6.5.8", f.remediation)   # affectedVersions in remediation
```

- [ ] **Step 3: Run test to verify it fails**

Run: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest tests.test_scan.TestComposerAudit -v`
Expected: FAIL with `AttributeError: ... has no attribute 'normalize_composer_audit'`.

- [ ] **Step 4: Write minimal implementation** (after `normalize_bundler_audit`):

```python
def normalize_composer_audit(raw) -> list:
    out = []
    for pkg_name, advisories in (raw.get("advisories") or {}).items():
        for adv in advisories or []:
            name = adv.get("packageName") or pkg_name
            affected = adv.get("affectedVersions")
            rem = (f"Upgrade {name} beyond the affected range ({affected})."
                   if affected else f"Upgrade {name} to a patched version.")
            out.append(Finding(
                tool="composer-audit", category="deps", severity="high",  # composer omits severity
                title=adv.get("title") or f"Vulnerable dependency: {name}",
                package=name,
                cve=_first_cve([adv.get("cve"), adv.get("advisoryId")], adv.get("advisoryId")),
                rule_id=adv.get("advisoryId"), file="composer.lock",
                remediation=rem))
    return out
```

- [ ] **Step 5: Run test to verify it passes**

Run: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest tests.test_scan.TestComposerAudit -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/scan.py tests/test_scan.py tests/fixtures/raw/composer-audit.json
git commit -m "Normalize composer audit JSON into Finding schema"
```

---

## Task 4: Wire scanners into `_plan` (+ registries, npm re-gate, manifests)

**Files:**
- Modify: `scripts/scan.py` — `_MANIFESTS` (228-230), `_NATIVE_ONLY` (372), `INSTALL_HINTS` (374-384),
  `CATEGORY_OF` (752-756), `_plan` (766-798), `_execute_job` name line (819)
- Test: `tests/test_scan.py` (add tests; update `TestPlanGoRust` base dicts)

**Interfaces:**
- Consumes: `normalize_bundler_audit`, `normalize_composer_audit` (Tasks 2-3); stack keys (Task 1).
- Produces: `_plan` yields a `("bundler-audit", ["check","--format","json"], ...)` job when
  `stack["ruby"]`, a `("composer", ["audit","--format=json"], ...)` job when `stack["php"]`, and
  the `npm` job only when `stack["npm_lock"]`. `_execute_job` maps job name `composer` →
  display name `composer-audit`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_scan.py`):

```python
class TestPlanRubyPhpJava(unittest.TestCase):
    def _base(self, **stack):
        base = {"node": False, "python": False, "docker": False, "terraform": False,
                "git": False, "go": False, "rust": False,
                "ruby": False, "php": False, "java": False, "npm_lock": False}
        base.update(stack)
        return base

    def _tools(self, **stack):
        return [j[0] for j in scan._plan(self._base(**stack), only=set())]

    def test_ruby_php_jobs_present(self):
        self.assertIn("bundler-audit", self._tools(ruby=True))
        self.assertIn("composer", self._tools(php=True))

    def test_java_adds_no_job(self):
        # Java is covered by the always-on osv-scanner; no dedicated job.
        self.assertEqual(self._tools(java=True), self._tools())

    def test_npm_gated_on_lockfile(self):
        self.assertNotIn("npm", self._tools(node=True))                 # node but no lock
        self.assertIn("npm", self._tools(node=True, npm_lock=True))     # lock present

    def test_only_deps_keeps_ruby_php(self):
        only = [j[0] for j in scan._plan(self._base(ruby=True, php=True), only={"deps"})]
        self.assertIn("bundler-audit", only)
        self.assertIn("composer", only)

    def test_pom_is_manifest(self):
        self.assertTrue(scan._is_manifest("pom.xml"))
        self.assertTrue(scan._is_manifest("sub/build.gradle"))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest tests.test_scan.TestPlanRubyPhpJava -v`
Expected: FAIL (`KeyError`/assertion — jobs not wired, `pom.xml` not a manifest).

- [ ] **Step 3: Implement — (a) `_MANIFESTS`** add the Java manifests:

```python
_MANIFESTS = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
              "pnpm-lock.yaml", "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock",
              "go.mod", "go.sum", "Cargo.lock", "composer.lock", "Gemfile.lock",
              "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"}
```

- [ ] **Step 4: Implement — (b) `_NATIVE_ONLY`**:

```python
_NATIVE_ONLY = {"gitleaks", "trivy", "osv-scanner", "govulncheck", "cargo-audit",
                "bundler-audit", "composer"}  # need a real install
```

- [ ] **Step 5: Implement — (c) `INSTALL_HINTS`** add two entries (inside the dict):

```python
    "bundler-audit": "gem install bundler-audit",
    "composer": "install Composer — https://getcomposer.org",
```

- [ ] **Step 6: Implement — (d) `CATEGORY_OF`** add two entries:

```python
    "bundler-audit": "deps", "composer": "deps",
```

- [ ] **Step 7: Implement — (e) `_plan`** — re-gate npm and add the two jobs. Change the npm block:

```python
    if stack["npm_lock"]:
        jobs.append(("npm", ["audit", "--json"], normalize_npm_audit))
```

and add, right after the `cargo-audit` job append:

```python
    if stack["ruby"]:
        jobs.append(("bundler-audit", ["check", "--format", "json"], normalize_bundler_audit))
    if stack["php"]:
        jobs.append(("composer", ["audit", "--format=json"], normalize_composer_audit))
```

- [ ] **Step 8: Implement — (f) `_execute_job` display name** — change the `name =` line so `composer` reports as `composer-audit`:

```python
    name = {"npm": "npm-audit", "composer": "composer-audit"}.get(tool, tool)
```

- [ ] **Step 9: Update the existing `TestPlanGoRust` base dicts** — they index new keys via `_plan`. In `tests/test_scan.py`, in `TestPlanGoRust._tools` and in `test_only_deps_keeps_them`, extend both `base` dicts with the new keys:

```python
        base = {"node": False, "python": False, "docker": False, "terraform": False,
                "git": False, "go": False, "rust": False,
                "ruby": False, "php": False, "java": False, "npm_lock": False}
```
(Keep the `go=True`/`rust=True` overrides those tests already apply.)

- [ ] **Step 10: Run the full suite to verify green**

Run: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest discover -s tests -v`
Expected: PASS (new `TestPlanRubyPhpJava`; `TestPlanGoRust` still green; nothing else broken).

- [ ] **Step 11: Commit**

```bash
git add scripts/scan.py tests/test_scan.py
git commit -m "Run bundler-audit/composer audit and gate npm audit on a lockfile"
```

---

## Task 5: Surface detected ecosystems in `summary["stack"]`

**Files:**
- Modify: `scripts/scan.py` — `build_report` (606-632), `render_markdown` (647-683), `main` (955-957)
- Test: `tests/test_scan.py`

**Interfaces:**
- Produces: `build_report(..., stack=None)` adds `summary["stack"]` (list; `[]` when omitted).
  `main` passes `stack = sorted(k for k,v in stack.items() if v and k not in ("git","npm_lock"))`.
  `render_markdown` emits a `**Detected:** ...` line when `summary["stack"]` is non-empty.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_scan.py`):

```python
class TestStackSummary(unittest.TestCase):
    def test_build_report_defaults_empty(self):
        rep = scan.build_report([], target="/x", run=[], skipped=[], errored=[], duration_s=0.1)
        self.assertEqual(rep["summary"]["stack"], [])

    def test_build_report_carries_stack(self):
        rep = scan.build_report([], target="/x", run=[], skipped=[], errored=[],
                                duration_s=0.1, stack=["java", "node"])
        self.assertEqual(rep["summary"]["stack"], ["java", "node"])

    def test_markdown_shows_detected(self):
        rep = scan.build_report([], target="/x", run=[], skipped=[], errored=[],
                                duration_s=0.1, stack=["java", "node"])
        self.assertIn("**Detected:** java, node", scan.render_markdown(rep))

    def test_main_reports_java_stack(self):
        os.environ["VIBESAFE_NO_EPHEMERAL"] = "1"
        try:
            d = Path(tempfile.mkdtemp()); (d / "pom.xml").write_text("<project/>")
            out = Path(tempfile.mkdtemp())
            scan.main(["--out-dir", str(out), str(d)])
            st = json.loads((out / "report.json").read_text())["summary"]["stack"]
            self.assertIn("java", st)
            self.assertNotIn("npm_lock", st)
            self.assertNotIn("git", st)
        finally:
            os.environ.pop("VIBESAFE_NO_EPHEMERAL", None)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest tests.test_scan.TestStackSummary -v`
Expected: FAIL (`KeyError: 'stack'` / missing `**Detected:**`).

- [ ] **Step 3: Implement — `build_report`** — add the `stack` parameter and summary field.

Change the signature (add `stack=None` at the end):

```python
def build_report(findings, target, run, skipped, errored, duration_s,
                 scope="full", changed_files=None, ignored=0, baselined=0, deduped=0,
                 stack=None) -> dict:
```

Add to the `"summary"` dict (e.g. right after `"scope": scope,`):

```python
            "stack": stack or [],
```

- [ ] **Step 4: Implement — `render_markdown`** — after the `if rep["findings"]:` block (right before `run = ", ".join(...)`), insert:

```python
    if s.get("stack"):
        L.append(f"**Detected:** {', '.join(s['stack'])}")
        L.append("")
```

- [ ] **Step 5: Implement — `main`** — compute and pass the detected list. Replace the `build_report(...)` call so it includes `stack`:

```python
    detected = sorted(k for k, v in stack.items() if v and k not in ("git", "npm_lock"))
    rep = build_report(findings, target, run, skipped, errored, time.time() - t0,
                       scope=scope, changed_files=changed_n,
                       ignored=ignored_n, baselined=baselined_n, deduped=deduped_n,
                       stack=detected)
```

- [ ] **Step 6: Run the full suite to verify green**

Run: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest discover -s tests -v`
Expected: PASS (new `TestStackSummary`; existing report tests unaffected — `stack` defaults to `[]`).

- [ ] **Step 7: Commit**

```bash
git add scripts/scan.py tests/test_scan.py
git commit -m "Report detected ecosystems in summary.stack and markdown"
```

---

## Task 6: Live-detection fixtures + tests + CI (Ruby/PHP/Java)

**Files:**
- Create: `tests/fixtures/ruby-app/Gemfile`, `tests/fixtures/ruby-app/Gemfile.lock`
- Create: `tests/fixtures/php-app/composer.json`
- Create: `tests/fixtures/java-app/pom.xml`
- Modify: `tests/test_live_detection.py` (add `TestLiveRubyPhpJava`)
- Modify: `.github/workflows/ci.yml` (install bundler-audit + PHP/Composer in the `live-detection` job)

**Interfaces:**
- Consumes: `scan.main`, `scan.EXIT_OK`, the `FIXTURES` path constant (already defined in
  `tests/test_live_detection.py`).
- Produces: three committed vulnerable fixtures + a `@skipUnless(VIBESAFE_LIVE)` test class.
  These do **not** run in the hermetic suite (they're skipped without `VIBESAFE_LIVE`).

- [ ] **Step 1: Create `tests/fixtures/ruby-app/Gemfile`**:

```ruby
source "https://rubygems.org"
gem "rack", "2.0.0"
```

- [ ] **Step 2: Create `tests/fixtures/ruby-app/Gemfile.lock`** (bundler-audit parses this directly, offline):

```
GEM
  remote: https://rubygems.org/
  specs:
    rack (2.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  rack (= 2.0.0)

BUNDLED WITH
   2.3.0
```

- [ ] **Step 3: Create `tests/fixtures/php-app/composer.json`** (lock is generated in-test):

```json
{
  "name": "vibesafe/php-fixture",
  "description": "Intentionally vulnerable fixture for vibesafe live-detection.",
  "require": {
    "guzzlehttp/guzzle": "6.5.0"
  }
}
```

- [ ] **Step 4: Create `tests/fixtures/java-app/pom.xml`** (Log4Shell; osv-scanner reads pom.xml):

```xml
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.vibesafe</groupId>
  <artifactId>java-fixture</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
```

- [ ] **Step 5: Add `TestLiveRubyPhpJava`** to `tests/test_live_detection.py` (after `TestLiveGoRust`; it reuses the existing `FIXTURES` constant, `json`, `os`, `shutil`, `subprocess`, `tempfile`, `unittest`, `Path`, `scan` imports already at the top of the file):

```python
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
```

- [ ] **Step 6: Verify the hermetic suite still skips these** (no real tools needed):

Run: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest discover -s tests -v`
Expected: PASS; `TestLiveRubyPhpJava` tests report as **skipped** (`VIBESAFE_LIVE` unset).

- [ ] **Step 7: Extend the CI `live-detection` job.** In `.github/workflows/ci.yml`, in the
`Install scanners` step, append after the `cargo-audit` block (before the closing of the `run: |`):

```yaml
          # bundler-audit (Ruby deps) — Ruby is preinstalled on ubuntu-latest
          sudo gem install --no-document bundler-audit
          bundler-audit update
          # composer audit (PHP deps) — PHP + latest Composer (>=2.4 for `audit`)
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends php-cli
          curl -sS https://getcomposer.org/installer | php -- --install-dir="$HOME/bin" --filename=composer
          # Java deps are covered by osv-scanner (installed above) — no extra tool
```

Then update the final step's `name:` to reflect the added ecosystems:

```yaml
      - name: Prove detection (secrets / sast / deps / iac + Go, Rust, Ruby, PHP, Java)
```

(The run command `python -m unittest tests.test_live_detection -v` already discovers the new class — no change needed.)

- [ ] **Step 8: Commit**

```bash
git add tests/fixtures/ruby-app tests/fixtures/php-app tests/fixtures/java-app \
        tests/test_live_detection.py .github/workflows/ci.yml
git commit -m "Prove Ruby/PHP/Java detection end-to-end in CI (live fixtures)"
```

---

## Task 7: Docs + version bump 1.8.0

**Files:**
- Modify: `references/tools.md`, `CHANGELOG.md`, `.claude-plugin/plugin.json`,
  `.claude-plugin/marketplace.json`, `README.md`, `docs/roadmap.md`

- [ ] **Step 1: `references/tools.md`** — add three rows to the scanner matrix (after the Rust row, line 14):

```markdown
| Deps (Ruby) | bundler-audit | `bundler-audit check --format json` | `gem install bundler-audit` |
| Deps (PHP) | composer audit | `composer audit --format=json` | https://getcomposer.org |
| Deps (Java) | osv-scanner | (covered by osv-scanner; parses `pom.xml`/`gradle.lockfile`) | `brew install osv-scanner` |
```

Then extend the privacy bullet (line 26) so the dependency-scanner list and its data sources include the new tools:

```markdown
- **Dependency scanners** (`npm audit`, `pip-audit`, `osv-scanner`, `cargo-audit`, `govulncheck`,
  `bundler-audit`, `composer audit`) send only **package metadata** to advisory APIs (npm registry,
  PyPI, `api.osv.dev`, RustSec DB, Go vulnerability DB, RubySec advisory DB, Packagist security
  advisories) — never your code.
```

- [ ] **Step 2: Version bump 1.8.0** — set `"version": "1.8.0"` in `.claude-plugin/plugin.json:3`
and the plugin entry of `.claude-plugin/marketplace.json:13`; change the README badge
`README.md:10` from `version-1.7.0-blue` to `version-1.8.0-blue`.

- [ ] **Step 3: `CHANGELOG.md`** — insert above `## 1.7.0 — 2026-07-01`:

```markdown
## 1.8.0 — 2026-07-01

### Added
- **Ruby, PHP & Java ecosystems**: `detect_stack` recognizes Ruby (`Gemfile.lock`), PHP
  (`composer.json`/`composer.lock`) and Java (`pom.xml`/Gradle). Runs `bundler-audit` (Ruby) and
  `composer audit` (PHP) as dedicated dependency scanners (deduped against `osv-scanner`); Java
  dependencies are covered by the always-on `osv-scanner`. All degrade gracefully when the tool
  isn't installed. End-to-end detection is proven in CI with real tools.
- **Detected ecosystems** are listed in `report.json` (`summary.stack`) and the markdown report
  (`Detected:` line).

### Changed
- `npm audit` now runs only when an npm lockfile (`package-lock.json`/`npm-shrinkwrap.json`) is
  present; pure yarn/pnpm projects are covered by `osv-scanner` instead of erroring on a missing
  npm lockfile.
```

- [ ] **Step 4: `docs/roadmap.md`** — update the Tier 3 "Mehr Ökosysteme" bullet to mark Ruby/PHP/Java
done and code-gap #3 fully closed. Replace the existing bullet (lines 43-45) with:

```markdown
- **Mehr Ökosysteme** — ✅ **Go + Rust in v1.7.0**, **Ruby + PHP + Java in v1.8.0** (`bundler-audit`,
  `composer audit`, Java via `osv-scanner`). **Code-Lücke #3 vollständig behoben.**
```

Also update code-gap #3 (lines 29-30) to strike it through as resolved, matching #1/#2:

```markdown
3. ~~**Stack-Detection ist Node/Python/Docker/TF-zentriert**~~ — ✅ **behoben (Go/Rust v1.7.0,
   Ruby/PHP/Java v1.8.0)**: alle gängigen Ökosysteme werden erkannt und adressiert.
```

- [ ] **Step 5: Sanity-check the JSON files parse**

Run:
```bash
python3 -c "import json; json.load(open('.claude-plugin/plugin.json')); json.load(open('.claude-plugin/marketplace.json')); print('json ok')"
```
Expected: `json ok`.

- [ ] **Step 6: Run the full hermetic suite one last time**

Run: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest discover -s tests -v`
Expected: PASS (all tests; live tests skipped).

- [ ] **Step 7: Commit**

```bash
git add references/tools.md CHANGELOG.md .claude-plugin/plugin.json \
        .claude-plugin/marketplace.json README.md docs/roadmap.md
git commit -m "Docs + version bump 1.8.0 (Ruby/PHP/Java ecosystems)"
```

---

## Task 8: Graceful-skip smoke test (manual verification)

**Files:** none (verification only)

- [ ] **Step 1: Scan a throwaway Ruby/PHP/Java dir; confirm tools skip cleanly (not installed) without crashing:**

```bash
D=$(mktemp -d)
printf 'source "https://rubygems.org"\n' > "$D/Gemfile"; : > "$D/Gemfile.lock"
printf '{"require":{"guzzlehttp/guzzle":"6.5.0"}}\n' > "$D/composer.json"
printf '<project/>\n' > "$D/pom.xml"
OUT=$(mktemp -d)
VIBESAFE_NO_EPHEMERAL=1 python3 scripts/scan.py --out-dir "$OUT" "$D" >/dev/null
python3 -c "import json; s=json.load(open('$OUT/report.json'))['summary']; \
print('stack:', s['stack']); \
print('skipped:', [x['tool'] for x in s['scanners_skipped']])"
```

Expected: `stack:` includes `java`, `php`, `ruby`; `bundler-audit` and `composer-audit` appear in
`scanners_skipped` with install hints (when the tools aren't installed); **no crash**.

---

## Self-Review (against spec)

- **§4 detection** → Task 1. **§5.1 plan / CATEGORY_OF / INSTALL_HINTS / _NATIVE_ONLY / display-name**
  → Task 4. **§5.2 bundler-audit** → Task 2. **§5.3 composer-audit** → Task 3.
  **§6 summary.stack** → Task 5. **§7 dedup** → covered by existing engine (no code change).
  **§8 diff/manifests** → Task 4 (Step 3). **§9 hermetic tests** → Tasks 1-5.
  **§9.1 live-detection + CI** → Task 6. **§10 docs/version** → Task 7. Graceful skip → Task 8. ✓
- **Placeholders:** none — fixtures and code are complete; doc-task content is explicit.
- **Type consistency:** `normalize_bundler_audit`/`normalize_composer_audit` return
  `list[Finding]` like their peers; `_BUNDLER_SEV` mirrors the existing severity maps; `_plan`
  job tuples keep the `(tool, argv, normalizer)` shape; `build_report`'s new `stack` param is
  keyword-only-by-default (`None`) so existing callers are unaffected; job name `composer` →
  display `composer-audit` is applied consistently in `_execute_job` and the normalizer's `tool=`.
