# SARIF Output Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit a SARIF 2.1.0 `report.sarif` (one run per tool) alongside the existing outputs, and let the GitHub Action optionally upload it to code scanning.

**Architecture:** A pure `build_sarif(rep)` renderer in `scripts/scan.py` (peer of `render_markdown`), wired into `main()` so `report.sarif` is always written. `action.yml` gains an opt-in `upload-sarif` input that runs `github/codeql-action/upload-sarif@v4`.

**Tech Stack:** Python 3 stdlib only. Tests: stdlib `unittest`. GitHub Actions YAML.

**Reference:** Spec at `docs/specs/2026-07-01-vibesafe-sarif-design.md`.

## Global Constraints

- Python **stdlib only** in `scripts/scan.py`.
- SARIF facts (verified against GitHub docs): top-level `$schema` + `version:"2.1.0"` + `runs[]`;
  driver needs `name` + `rules[]`; each rule needs `id`/`shortDescription.text`/`fullDescription.text`/`help.text`;
  result `level` ∈ `note|warning|error`; a result needs ≥1 `locations` to display; **omit
  `partialFingerprints`** (upload-sarif computes them). Upload action is **`@v4`**, input `sarif_file`,
  permission `security-events: write`.
- Backwards compatible: only adds a file; a plain run still exits `0`.
- Commit messages plain, no attribution. Stage by explicit path.
- Version target: **1.6.0**.
- Run tests: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest discover -s tests -v`.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `scripts/scan.py` | + `_SARIF_LEVEL`, `build_sarif(rep)`; write `report.sarif` in `main()` | Modify |
| `tests/test_scan.py` | + `TestSarif` | Modify |
| `action.yml` | + `upload-sarif` input + conditional upload step | Modify |
| `references/automation.md`, `SKILL.md` | SARIF docs | Modify |
| `README.md`, `CHANGELOG.md`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `docs/roadmap.md` | version 1.6.0 + roadmap | Modify |

---

## Task 1: `build_sarif` renderer

**Files:** Modify `scripts/scan.py`; Test `tests/test_scan.py`

**Interfaces:**
- Consumes: `rep` dict from `build_report` (its `findings` are dicts via `finding_to_dict`), `normalize_severity`.
- Produces: `build_sarif(rep) -> dict`, `_SARIF_LEVEL`.

- [ ] **Step 1: Failing test** — append to `tests/test_scan.py`:

```python
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
```

- [ ] **Step 2: Run → FAIL** — `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest tests.test_scan.TestSarif -v`.

- [ ] **Step 3: Implement** in `scripts/scan.py` (add near `render_markdown`):

```python
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def build_sarif(rep) -> dict:
    """SARIF 2.1.0 log, one run per tool. partialFingerprints are omitted — GitHub's
    upload-sarif computes them from the source."""
    by_tool, order = {}, []
    for f in rep["findings"]:
        t = f.get("tool") or "vibesafe"
        if t not in by_tool:
            by_tool[t] = []
            order.append(t)
        by_tool[t].append(f)
    runs = []
    for t in order:
        rules, rule_index, results = [], {}, []
        for f in by_tool[t]:
            rid = f.get("rule_id") or f.get("cve") or f"{f.get('category')}/{t}"
            title = str(f.get("title") or rid)
            if rid not in rule_index:
                rule_index[rid] = len(rules)
                rules.append({
                    "id": rid,
                    "shortDescription": {"text": title[:120]},
                    "fullDescription": {"text": title},
                    "help": {"text": f.get("remediation") or "See references/remediation.md."},
                })
            msg = title + (f" (also: {', '.join(f['also_reported_by'])})"
                           if f.get("also_reported_by") else "")
            result = {
                "ruleId": rid,
                "ruleIndex": rule_index[rid],
                "level": _SARIF_LEVEL.get(normalize_severity(f.get("severity")), "note"),
                "message": {"text": msg},
                "properties": {k: f.get(k) for k in
                               ("category", "severity", "tool", "cve", "package",
                                "committed", "also_reported_by") if f.get(k) is not None},
            }
            if f.get("file"):
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file"]},
                        "region": {"startLine": f.get("line") or 1, "startColumn": 1},
                    }
                }]
            results.append(result)
        runs.append({
            "tool": {"driver": {
                "name": t,
                "informationUri": "https://github.com/marco-scheffler/vibesafe",
                "rules": rules,
            }},
            "results": results,
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }
```

- [ ] **Step 4: Run → PASS**.

- [ ] **Step 5: Commit**
```bash
git add scripts/scan.py tests/test_scan.py
git commit -m "Add SARIF 2.1.0 renderer (one run per tool)"
```

---

## Task 2: Write `report.sarif` in `main()`

**Files:** Modify `scripts/scan.py`; Test `tests/test_scan.py`

**Interfaces:**
- Consumes: `build_sarif`.
- Produces: `main()` writes `report.sarif` into the out-dir.

- [ ] **Step 1: Failing test**:

```python
class TestSarifMain(unittest.TestCase):
    def test_main_writes_sarif(self):
        d = Path(tempfile.mkdtemp()); out = Path(tempfile.mkdtemp())
        scan.main(["--out-dir", str(out), str(d)])
        s = json.loads((out / "report.sarif").read_text())
        self.assertEqual(s["version"], "2.1.0")
        self.assertIn("runs", s)
```

- [ ] **Step 2: Run → FAIL**.

- [ ] **Step 3: Implement** — in `main()`, replace:

```python
    (out_dir / "report.json").write_text(json.dumps(rep, indent=2))
    md = render_markdown(rep)
    (out_dir / "report.md").write_text(md)
    print(md)
    print(f"\n[vibesafe] report: {out_dir}/report.json")
    return gating_exit(rep, a.fail_on, a.fail_on_error)
```

with:

```python
    (out_dir / "report.json").write_text(json.dumps(rep, indent=2))
    (out_dir / "report.sarif").write_text(json.dumps(build_sarif(rep), indent=2))
    md = render_markdown(rep)
    (out_dir / "report.md").write_text(md)
    print(md)
    print(f"\n[vibesafe] report: {out_dir}/report.json  ·  sarif: {out_dir}/report.sarif")
    return gating_exit(rep, a.fail_on, a.fail_on_error)
```

- [ ] **Step 4: Run → PASS**, then full suite green.

- [ ] **Step 5: Commit**
```bash
git add scripts/scan.py tests/test_scan.py
git commit -m "Always write report.sarif alongside json/md"
```

---

## Task 3: Action `upload-sarif` input

**Files:** Modify `action.yml`

- [ ] **Step 1: Add the input** — under `inputs:` (after `timeout`):
```yaml
  upload-sarif:
    description: If "true", upload report.sarif to GitHub code scanning (needs security-events: write).
    default: "false"
```

- [ ] **Step 2: Add the upload step** — as the last step under `runs.steps:` (after "Upload report"):
```yaml
    - name: Upload SARIF to code scanning
      if: ${{ always() && inputs.upload-sarif == 'true' }}
      uses: github/codeql-action/upload-sarif@v4
      with:
        sarif_file: ${{ runner.temp }}/vibesafe/report.sarif
```
> `always()` so the SARIF still uploads when the scan step exits non-zero from `fail-on` gating
> (the SARIF is written before `scan.py` returns the gating code).

- [ ] **Step 3: Validate YAML**
```bash
python3 -c "import yaml; yaml.safe_load(open('action.yml')); print('ok')"
```

- [ ] **Step 4: Commit**
```bash
git add action.yml
git commit -m "Add opt-in upload-sarif input to the Action"
```

---

## Task 4: Docs + version bump 1.6.0

**Files:** Modify `references/automation.md`, `SKILL.md`, `README.md`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `docs/roadmap.md`; Modify `CHANGELOG.md`

- [ ] **Step 1: `references/automation.md`** — add after the "Dedup & parallelism" section:
```markdown
## SARIF & code scanning

Every scan also writes **`report.sarif`** (SARIF 2.1.0, one run per tool) next to
`report.json`/`report.md`. Point GitHub code scanning at it so findings show up inline in the PR
Security tab. The Action can upload it for you with `upload-sarif: true`:

```yaml
jobs:
  vibesafe:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # required to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - run: pipx install semgrep
      - uses: marco-scheffler/vibesafe@v1.6.0
        with:
          path: .
          upload-sarif: true
```

`partialFingerprints` are omitted on purpose — `upload-sarif@v4` computes them from the source.
```

- [ ] **Step 2: `SKILL.md`** — append to the automation flags bullet:
`Every run also writes report.sarif (SARIF 2.1.0) for GitHub code scanning.`

- [ ] **Step 3: Version bump 1.6.0** — `"version": "1.6.0"` in `.claude-plugin/plugin.json` and the plugin entry of `.claude-plugin/marketplace.json`; README badge `version-1.5.0-blue` → `version-1.6.0-blue`.

- [ ] **Step 4: `CHANGELOG.md`** — add above `## 1.5.0 — 2026-07-01`:
```markdown
## 1.6.0 — 2026-07-01

### Added
- **SARIF output**: every scan writes `report.sarif` (SARIF 2.1.0, one run per tool) alongside
  `report.json`/`report.md`.
- **Action `upload-sarif` input**: opt-in upload to GitHub code scanning via
  `github/codeql-action/upload-sarif@v4` (needs `security-events: write`).

```

- [ ] **Step 5: `docs/roadmap.md`** — remove the `**SARIF-Output**` bullet from Tier 2 (delivered);
optionally note it under a "Done" mention.

- [ ] **Step 6: Validate + commit**
```bash
python3 -c "import json; json.load(open('.claude-plugin/plugin.json')); json.load(open('.claude-plugin/marketplace.json'))"
git add references/automation.md SKILL.md README.md CHANGELOG.md .claude-plugin/plugin.json .claude-plugin/marketplace.json docs/roadmap.md
git commit -m "Document SARIF output and bump to 1.6.0"
```

---

## Task 5: Final verification

**Files:** none

- [ ] **Step 1: Full hermetic suite green**
`VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest discover -s tests -v` → all pass (live skipped).

- [ ] **Step 2: Real SARIF smoke** — scan the fixture and sanity-check the SARIF:
```bash
OUT=$(mktemp -d); VIBESAFE_NO_EPHEMERAL=1 python3 scripts/scan.py --out-dir "$OUT" tests/fixtures/vulnerable-app >/dev/null
python3 -c "import json; s=json.load(open('$OUT/report.sarif')); print('version', s['version'], '| runs', [r['tool']['driver']['name'] for r in s['runs']])"
```
Expected: `version 2.1.0` and one run per tool that produced findings.

---

## Self-Review (against spec)

**Spec coverage:**
- §4.1 `build_sarif`, one run per tool → Task 1. ✓
- §4.2 result mapping (ruleId fallback, level, message+also, locations when file, properties) → Task 1 + tests. ✓
- §4.3 rule descriptors (id/short/full/help) → Task 1 + `test_rule_descriptor_fields`. ✓
- §4.4 always write `report.sarif` in `main()` → Task 2. ✓
- §5 Action `upload-sarif` @v4 + `always()` → Task 3. ✓
- §6 docs/version/roadmap/tests → Task 4 + Tasks 1–2 tests. ✓

**Placeholder scan:** all code steps carry full code; doc steps have explicit content. None.

**Type consistency:** `build_sarif(rep)->dict`, `_SARIF_LEVEL`, and the `report.sarif` write use the
same `rep` shape produced by `build_report`. Rule/result `ruleIndex` links results to `driver.rules`.
