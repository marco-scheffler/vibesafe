# Go + Rust Ecosystems Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect Go and Rust projects and run `govulncheck` (via SARIF) and `cargo-audit` as additional dependency scanners, normalized into the existing Finding schema.

**Architecture:** Extend `detect_stack`, add two normalizers (`normalize_cargo_audit`, `normalize_govulncheck`) + `_SARIF_TO_SEV`, and wire two conditional jobs into `_plan`. Native tools, graceful skip when absent. Existing cross-tool dedup handles overlap with osv.

**Tech Stack:** Python 3 stdlib only. Tests: stdlib `unittest`.

**Reference:** Spec at `docs/specs/2026-07-01-vibesafe-go-rust-design.md`.

## Global Constraints

- Python **stdlib only** in `scripts/scan.py`. Commit messages plain, no attribution. Stage by explicit path.
- Version target **1.7.0**. Run tests: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest discover -s tests -v`.
- Normalizers must be defensive (`.get()` everywhere) — tool JSON isn't locally verifiable.

---

## Task 1: Detect Go & Rust

**Files:** Modify `scripts/scan.py`; Test `tests/test_scan.py`

- [ ] **Step 1: Failing test** (append to `tests/test_scan.py`):
```python
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
```

- [ ] **Step 2: Run → FAIL** — `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest tests.test_scan.TestDetectGoRust -v` (KeyError).

- [ ] **Step 3: Implement** — in `detect_stack`'s returned dict, add before `"git":`:
```python
        "go": (path / "go.mod").exists() or has("go.mod", "go.sum"),
        "rust": (path / "Cargo.toml").exists() or has("Cargo.toml", "Cargo.lock"),
```

- [ ] **Step 4: Run → PASS**.

- [ ] **Step 5: Commit** `git add scripts/scan.py tests/test_scan.py && git commit -m "Detect Go and Rust projects"`

---

## Task 2: `normalize_cargo_audit`

**Files:** Modify `scripts/scan.py`; Create `tests/fixtures/raw/cargo-audit.json`; Test `tests/test_scan.py`

- [ ] **Step 1: Fixture** — `tests/fixtures/raw/cargo-audit.json`:
```json
{
  "database": {"advisory-count": 500},
  "vulnerabilities": {
    "found": true,
    "count": 1,
    "list": [
      {
        "advisory": {
          "id": "RUSTSEC-2020-0071",
          "package": "time",
          "title": "Potential segfault in the time crate",
          "url": "https://rustsec.org/advisories/RUSTSEC-2020-0071",
          "aliases": ["CVE-2020-26235"]
        },
        "versions": {"patched": [">=0.2.23"], "unaffected": []},
        "package": {"name": "time", "version": "0.2.10"}
      }
    ]
  },
  "warnings": {}
}
```

- [ ] **Step 2: Failing test**:
```python
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
```

- [ ] **Step 3: Run → FAIL**.

- [ ] **Step 4: Implement** (add near `normalize_osv`):
```python
def normalize_cargo_audit(raw) -> list:
    out = []
    for v in ((raw.get("vulnerabilities") or {}).get("list")) or []:
        adv = v.get("advisory") or {}
        pkg = v.get("package") or {}
        patched = ", ".join((v.get("versions") or {}).get("patched") or []) or "a patched version"
        out.append(Finding(
            tool="cargo-audit", category="deps", severity="high",
            title=adv.get("title") or f"Vulnerable dependency: {pkg.get('name')}",
            package=pkg.get("name"), cve=_first_cve(adv.get("aliases"), adv.get("id")),
            file="Cargo.lock",
            remediation=f"Upgrade {pkg.get('name')} to {patched}."))
    return out
```

- [ ] **Step 5: Run → PASS; Commit** `git add scripts/scan.py tests/test_scan.py tests/fixtures/raw/cargo-audit.json && git commit -m "Add cargo-audit normalizer"`

---

## Task 3: `normalize_govulncheck` (SARIF)

**Files:** Modify `scripts/scan.py`; Create `tests/fixtures/raw/govulncheck-sarif.json`; Test `tests/test_scan.py`

- [ ] **Step 1: Fixture** — `tests/fixtures/raw/govulncheck-sarif.json`:
```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name": "govulncheck", "rules": [
        {"id": "GO-2021-0113", "shortDescription": {"text": "Out-of-range read in golang.org/x/text"}}
      ]}},
      "results": [
        {
          "ruleId": "GO-2021-0113",
          "level": "error",
          "message": {"text": "golang.org/x/text/language: out-of-range read via ParseAcceptLanguage"},
          "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "main.go"}, "region": {"startLine": 12}}}
          ]
        }
      ]
    }
  ]
}
```

- [ ] **Step 2: Failing test**:
```python
class TestGovulncheck(unittest.TestCase):
    def test_normalize(self):
        fs = scan.normalize_govulncheck(raw("govulncheck-sarif.json"))
        self.assertEqual(len(fs), 1)
        f = fs[0]
        self.assertEqual((f.category, f.tool, f.severity), ("deps", "govulncheck", "high"))
        self.assertEqual(f.rule_id, "GO-2021-0113")
        self.assertEqual(f.file, "main.go")
        self.assertEqual(f.line, 12)
```

- [ ] **Step 3: Run → FAIL**.

- [ ] **Step 4: Implement** — add `_SARIF_TO_SEV` next to `_SARIF_LEVEL`, and the normalizer near `normalize_cargo_audit`:
```python
_SARIF_TO_SEV = {"error": "high", "warning": "medium", "note": "low"}


def normalize_govulncheck(raw) -> list:
    out = []
    for run in raw.get("runs") or []:
        for res in run.get("results") or []:
            rid = res.get("ruleId")
            locs = res.get("locations") or []
            pl = (locs[0].get("physicalLocation") or {}) if locs else {}
            out.append(Finding(
                tool="govulncheck", category="deps",
                severity=_SARIF_TO_SEV.get(res.get("level"), "high"),
                title=((res.get("message") or {}).get("text") or rid or "Go vulnerability")[:200],
                file=(pl.get("artifactLocation") or {}).get("uri"),
                line=(pl.get("region") or {}).get("startLine"),
                rule_id=rid, cve=_first_cve([rid], rid),
                remediation="Update the module to a fixed version."))
    return out
```

- [ ] **Step 5: Run → PASS; Commit** `git add scripts/scan.py tests/test_scan.py tests/fixtures/raw/govulncheck-sarif.json && git commit -m "Add govulncheck SARIF normalizer"`

---

## Task 4: Wire jobs into `_plan` (+ CATEGORY_OF, INSTALL_HINTS)

**Files:** Modify `scripts/scan.py`; Test `tests/test_scan.py`

- [ ] **Step 1: Failing test**:
```python
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
        tools = [j[0] for j in scan._plan(
            {"node": False, "python": False, "docker": False, "terraform": False,
             "git": False, "go": True, "rust": True}, only={"deps"})]
        self.assertIn("govulncheck", tools); self.assertIn("cargo-audit", tools)
```

- [ ] **Step 2: Run → FAIL**.

- [ ] **Step 3: Implement**:

(a) In `CATEGORY_OF` dict, add entries:
```python
    "govulncheck": "deps", "cargo-audit": "deps",
```

(b) In `INSTALL_HINTS`, add:
```python
    "govulncheck": "go install golang.org/x/vuln/cmd/govulncheck@latest",
    "cargo-audit": "cargo install cargo-audit",
```

(c) In `_plan`, after the `osv-scanner` job append and before the `semgrep` block:
```python
    if stack["go"]:
        jobs.append(("govulncheck", ["-format", "sarif", "./..."], normalize_govulncheck))
    if stack["rust"]:
        jobs.append(("cargo-audit", ["audit", "--json"], normalize_cargo_audit))
```

- [ ] **Step 4: Run → PASS**, then full suite green.

- [ ] **Step 5: Commit** `git add scripts/scan.py tests/test_scan.py && git commit -m "Run govulncheck and cargo-audit for Go/Rust projects"`

---

## Task 5: Docs + version bump 1.7.0

**Files:** Modify `references/tools.md`, `README.md`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `docs/roadmap.md`; Modify `CHANGELOG.md`

- [ ] **Step 1: `references/tools.md`** — add Go (`govulncheck`) and Rust (`cargo-audit`) rows to the scanner matrix, and note RustSec DB / Go vuln DB as (free, public) online sources in the privacy section.

- [ ] **Step 2: Version bump 1.7.0** — `"version": "1.7.0"` in `.claude-plugin/plugin.json` and the plugin entry of `.claude-plugin/marketplace.json`; README badge `version-1.6.0-blue` → `version-1.7.0-blue`.

- [ ] **Step 3: `CHANGELOG.md`** — add above `## 1.6.0 — 2026-07-01`:
```markdown
## 1.7.0 — 2026-07-01

### Added
- **Go & Rust ecosystems**: `detect_stack` recognizes Go (`go.mod`) and Rust (`Cargo.toml`/`Cargo.lock`),
  and runs `govulncheck` (via SARIF) and `cargo-audit` as additional dependency scanners (deduped
  against osv-scanner). Both degrade gracefully when the tool isn't installed.

```

- [ ] **Step 4: `docs/roadmap.md`** — under Tier 3 "Mehr Ökosysteme", mark Go + Rust delivered (v1.7.0);
Ruby/PHP/Java remain. Note code-gap #3 partially fixed.

- [ ] **Step 5: Validate + commit**
```bash
python3 -c "import json; json.load(open('.claude-plugin/plugin.json')); json.load(open('.claude-plugin/marketplace.json'))"
git add references/tools.md README.md CHANGELOG.md .claude-plugin/plugin.json .claude-plugin/marketplace.json docs/roadmap.md
git commit -m "Document Go/Rust scanners and bump to 1.7.0"
```

---

## Task 6: Final verification

**Files:** none

- [ ] **Step 1: Full hermetic suite green**
`VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest discover -s tests -v` → all pass (live skipped).

- [ ] **Step 2: Graceful-skip smoke** — scan a throwaway Go/Rust dir; confirm the tools skip cleanly (not installed) without crashing:
```bash
D=$(mktemp -d); printf 'module x\n' > "$D/go.mod"; printf '[package]\nname="x"\n' > "$D/Cargo.toml"; : > "$D/Cargo.lock"
OUT=$(mktemp -d); VIBESAFE_NO_EPHEMERAL=1 python3 scripts/scan.py --out-dir "$OUT" "$D" >/dev/null
python3 -c "import json; s=json.load(open('$OUT/report.json'))['summary']; print('skipped:', [x['tool'] for x in s['scanners_skipped']])"
```
Expected: `govulncheck` and `cargo-audit` appear in `scanners_skipped` with install hints; no crash.

---

## Self-Review (against spec)

- §4 detection → Task 1. §5.1 plan/CATEGORY_OF/INSTALL_HINTS → Task 4. §5.2 cargo-audit → Task 2.
  §5.3 govulncheck + `_SARIF_TO_SEV` → Task 3. §7 tests → Tasks 1–4. §8 docs/version → Task 5. ✓
- Placeholders: none (fixtures + code complete). Doc task is prose with explicit content.
- Type consistency: `normalize_cargo_audit`/`normalize_govulncheck` return `list[Finding]` like peers;
  `_SARIF_TO_SEV` mirrors `_SARIF_LEVEL`; `_plan` job tuples match `(tool, argv, normalizer)`.
