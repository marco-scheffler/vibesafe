# Cross-Tool-Dedup + Parallelism Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge cross-tool duplicate findings by fingerprint (default on) and run the scanners concurrently, in the existing stdlib orchestrator `scripts/scan.py`.

**Architecture:** Two pure, testable additions to `scan.py` — `dedupe_findings()` (groups by the v1.4.0 `fingerprint`, keeps the most-severe as primary, records other tools) and `worker_count()` (jobs-math) — plus a `ThreadPoolExecutor` execution path in `main()`. Post-processing order becomes: scanners → committed → fingerprint → dedup → diff → ignore → baseline → report → gating.

**Tech Stack:** Python 3 stdlib only (add `concurrent.futures`). Tests: stdlib `unittest`.

**Reference:** Spec at `docs/specs/2026-07-01-vibesafe-dedup-parallel-design.md`.

## Global Constraints

- Python **stdlib only** in `scripts/scan.py`.
- **Backwards compatible** except the intended default change (dedup on): a plain run still exits `0`.
- Dedup default **on**; `--no-dedup` disables. Parallelism `--jobs` default **4** (`1`=sequential, `0`=all).
- Deterministic output regardless of concurrency (collect results in plan order).
- Commit messages plain, no attribution. Stage by explicit path (no `git add -A`).
- Version target: **1.5.0**.
- Run tests: `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest discover -s tests -v`.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `scripts/scan.py` | + `Finding.also_reported_by`, `dedupe_findings`, `worker_count`, ThreadPool exec, `--jobs`/`--no-dedup`, `build_report` `deduped` | Modify |
| `tests/test_scan.py` | + `TestDedup`, `TestWorkerCount`, `TestParallelEquivalence` | Modify |
| `references/automation.md` | document `--no-dedup` / `--jobs` | Modify |
| `SKILL.md` | mention the two flags | Modify |
| `README.md`, `CHANGELOG.md`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` | version 1.5.0 | Modify/Create |
| `docs/roadmap.md` | move dedup+parallel to Done; mark code-gaps #1/#2 fixed | Modify |

---

## Task 1: Cross-tool dedup (pure function + schema)

**Files:** Modify `scripts/scan.py`; Test `tests/test_scan.py`

**Interfaces:**
- Consumes: `Finding.fingerprint`, `severity_sort_key`, `annotate_fingerprints`.
- Produces: `Finding.also_reported_by: list | None`, `dedupe_findings(findings) -> (list, int)`, `build_report(..., deduped=0)`, markdown `(also: …)` suffix.

- [ ] **Step 1: Failing test** — append to `tests/test_scan.py`:

```python
class TestDedup(unittest.TestCase):
    def _dup(self, tool, sev, committed=None):
        # same category/file/title/rule → same fingerprint regardless of tool/severity
        f = scan.Finding(tool=tool, category="deps", severity=sev, title="lodash CVE",
                         package="lodash", rule_id="CVE-2021-23337", committed=committed)
        return f

    def test_merges_same_fingerprint_keeps_most_severe(self):
        fs = [self._dup("npm-audit", "medium"), self._dup("trivy", "high"),
              self._dup("osv-scanner", "low")]
        scan.annotate_fingerprints(fs)
        out, removed = scan.dedupe_findings(fs)
        self.assertEqual(removed, 2)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "high")               # most severe kept
        self.assertEqual(out[0].tool, "trivy")                  # primary = most severe
        self.assertEqual(out[0].also_reported_by, ["npm-audit", "osv-scanner"])  # sorted others

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
```

- [ ] **Step 2: Run → FAIL** — `VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest tests.test_scan.TestDedup -v`.

- [ ] **Step 3: Implement** in `scripts/scan.py`:

(a) Add field to `Finding` (after `fingerprint`):
```python
    also_reported_by: list | None = None  # other tools that flagged the same fingerprint
```

(b) Add the function after `annotate_fingerprints`:
```python
def dedupe_findings(findings):
    """Merge findings sharing a fingerprint. Primary = most-severe (ties: first seen);
    other source tools go into also_reported_by; committed is OR-ed across the group."""
    groups, order = {}, []
    for f in findings:
        if f.fingerprint not in groups:
            groups[f.fingerprint] = []
            order.append(f.fingerprint)
        groups[f.fingerprint].append(f)
    out = []
    for fp in order:
        grp = groups[fp]
        if len(grp) == 1:
            out.append(grp[0])
            continue
        primary = min(grp, key=lambda g: severity_sort_key(g.severity))  # ties → first seen
        others = sorted({g.tool for g in grp if g is not primary and g.tool != primary.tool})
        primary.also_reported_by = others or None
        if any(getattr(g, "committed", None) is True for g in grp):
            primary.committed = True
        out.append(primary)
    return out, len(findings) - len(out)
```

(c) In `build_report`, add `deduped=0` to the signature and `"deduped": deduped,` to the summary dict (place it next to `"baselined"`):
```python
def build_report(findings, target, run, skipped, errored, duration_s,
                 scope="full", changed_files=None, ignored=0, baselined=0, deduped=0) -> dict:
```
```python
            "ignored": ignored,
            "baselined": baselined,
            "deduped": deduped,
```

(d) In `render_markdown`, after the `committed` prefix line, append the also-suffix. Replace:
```python
            if f.get("committed"):
                title = "🔓 committed — " + title
            L.append(f"| {f['severity']} | {f['category']} | {title} | {loc} |")
```
with:
```python
            if f.get("committed"):
                title = "🔓 committed — " + title
            if f.get("also_reported_by"):
                title += f" (also: {', '.join(f['also_reported_by'])})"
            L.append(f"| {f['severity']} | {f['category']} | {title} | {loc} |")
```

- [ ] **Step 4: Run → PASS** (`TestDedup`), then the existing `TestReport` still passes.

- [ ] **Step 5: Commit**
```bash
git add scripts/scan.py tests/test_scan.py
git commit -m "Add cross-tool dedup by fingerprint"
```

---

## Task 2: Parallel execution + wire dedup/jobs into main()

**Files:** Modify `scripts/scan.py`; Test `tests/test_scan.py`

**Interfaces:**
- Consumes: `dedupe_findings`, `_plan`, `_execute_job`.
- Produces: `worker_count(n_jobs, flag) -> int`; `main()` accepting `--jobs` (int, default 4) and `--no-dedup`.

- [ ] **Step 1: Failing tests**:

```python
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
```

- [ ] **Step 2: Run → FAIL**.

- [ ] **Step 3: Implement**:

(a) Add to the import block (alphabetical, after `import concurrent`... actually put it with the others):
```python
import concurrent.futures
```
Place it right after `import argparse` line group — insert after `import argparse`:
```python
import argparse
import concurrent.futures
import fnmatch
```

(b) Add the pure helper (near `dedupe_findings`):
```python
def worker_count(n_jobs, flag):
    if n_jobs <= 0:
        return 1
    if flag == 1:
        return 1
    if flag <= 0:
        return n_jobs
    return min(flag, n_jobs)
```

(c) In `main()` argparse block, add (after `--diff`):
```python
    ap.add_argument("--jobs", type=int, default=4,
                    help="scanners to run concurrently (1=sequential, 0=all at once)")
    ap.add_argument("--no-dedup", action="store_true",
                    help="do not merge findings reported by multiple tools")
```

(d) Replace the sequential run loop:
```python
    t0 = time.time()
    findings, run, skipped, errored = [], [], [], []
    for tool, argv_, norm in _plan(stack, only):
        fs, (state, info) = _execute_job(tool, argv_, norm, target, a.timeout)
        findings += fs
        if state == "run":
            run.append(info)
        elif state == "skipped":
            if a.no_install_hints:
                info.pop("install", None)
            skipped.append(info)
        else:
            errored.append(info)
```
with the concurrent version (results collected in plan order for determinism):
```python
    t0 = time.time()
    jobs = _plan(stack, only)
    workers = worker_count(len(jobs), a.jobs)
    if workers == 1:
        results = [_execute_job(t, av, nz, target, a.timeout) for t, av, nz in jobs]
    else:
        results = [None] * len(jobs)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_execute_job, t, av, nz, target, a.timeout): i
                    for i, (t, av, nz) in enumerate(jobs)}
            for fut in concurrent.futures.as_completed(futs):
                results[futs[fut]] = fut.result()

    findings, run, skipped, errored = [], [], [], []
    for fs, (state, info) in results:
        findings += fs
        if state == "run":
            run.append(info)
        elif state == "skipped":
            if a.no_install_hints:
                info.pop("install", None)
            skipped.append(info)
        else:
            errored.append(info)
```

(e) In the post-processing pipeline, add dedup right after `annotate_fingerprints(findings)`:
```python
    annotate_fingerprints(findings)
    deduped_n = 0
    if not a.no_dedup:
        findings, deduped_n = dedupe_findings(findings)
```

(f) Pass it to `build_report` (extend the existing call):
```python
    rep = build_report(findings, target, run, skipped, errored, time.time() - t0,
                       scope=scope, changed_files=changed_n,
                       ignored=ignored_n, baselined=baselined_n, deduped=deduped_n)
```

- [ ] **Step 4: Run → PASS** (`TestWorkerCount`, `TestParallelEquivalence`, `TestNoDedupFlag`), then full suite:
`VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest discover -s tests -v` → all green.

- [ ] **Step 5: Commit**
```bash
git add scripts/scan.py tests/test_scan.py
git commit -m "Run scanners concurrently and wire dedup/--jobs into main()"
```

---

## Task 3: Docs + version bump 1.5.0

**Files:** Modify `references/automation.md`, `SKILL.md`, `README.md`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `docs/roadmap.md`; Modify `CHANGELOG.md`

- [ ] **Step 1: `references/automation.md`** — add a short section after the "Diff / staged scoping" section:
```markdown
## Dedup & parallelism

Findings reported by multiple tools (e.g. one CVE from `npm audit`, `trivy` and `osv-scanner`) are
**merged by fingerprint** into one entry — the most-severe wins and the others appear as
`also_reported_by` (and `(also: …)` in `report.md`). The summary reports `deduped`. Disable with
`--no-dedup`.

Scanners run **concurrently** by default. `--jobs N` sets how many run at once (`1` = sequential
for debugging, `0` = all at once). Output is deterministic regardless of `--jobs`.
```

- [ ] **Step 2: `SKILL.md`** — extend the automation flags line (the one added in v1.4.0) to also mention `--jobs`/`--no-dedup`. Append to that bullet:
`Scanners run concurrently (--jobs N); cross-tool duplicates are merged (disable with --no-dedup).`

- [ ] **Step 3: Version bump 1.5.0** — set `"version": "1.5.0"` in `.claude-plugin/plugin.json` and the plugin entry of `.claude-plugin/marketplace.json`; in `README.md` change the version badge `version-1.4.0-blue` → `version-1.5.0-blue`.

- [ ] **Step 4: `CHANGELOG.md`** — add above the `## 1.4.0` entry:
```markdown
## 1.5.0 — 2026-07-01

Engine quality.

### Added
- **Cross-tool dedup** (default on): findings sharing a fingerprint are merged — most-severe wins,
  other tools listed in `also_reported_by`. Summary reports `deduped`; disable with `--no-dedup`.
- **Parallel scanners**: `--jobs N` runs scanners concurrently (default 4; `1`=sequential, `0`=all).
  Output stays deterministic.

### Changed
- `report.json` summary gains `deduped`; merged findings gain `also_reported_by`.
```

- [ ] **Step 5: `docs/roadmap.md`** — under "Konkrete Code-Lücken", mark #1 (dedup) and #2 (sequential)
as fixed (append `— behoben in v1.5.0`); under "Tier 2", remove the "Cross-Tool-Dedup" and
"Parallele Scanner-Ausführung" bullets (delivered).

- [ ] **Step 6: Validate + commit**
```bash
python3 -c "import json; json.load(open('.claude-plugin/plugin.json')); json.load(open('.claude-plugin/marketplace.json'))"
git add references/automation.md SKILL.md README.md CHANGELOG.md .claude-plugin/plugin.json .claude-plugin/marketplace.json docs/roadmap.md
git commit -m "Document dedup/--jobs and bump to 1.5.0"
```

---

## Task 4: Final verification

**Files:** none

- [ ] **Step 1: Full hermetic suite green**
`VIBESAFE_NO_EPHEMERAL=1 python3 -m unittest discover -s tests -v` → all pass (7 live skipped).

- [ ] **Step 2: Real dedup smoke** (tools present locally) — scan the fixture with a lockfile copy and confirm the lodash CVE is merged (one `deps` entry with `also_reported_by`) and `--no-dedup` shows the duplicates:
```bash
W=$(mktemp -d)/app; cp -R tests/fixtures/vulnerable-app "$W"; (cd "$W" && npm install --package-lock-only >/dev/null 2>&1)
python3 scripts/scan.py --only deps --out-dir "$(mktemp -d)" "$W" | grep -i "also:" && echo "dedup OK"
```
(If npm/scanners are absent, note it — don't fake it.)

- [ ] **Step 3: Confirm determinism** — already covered by `TestParallelEquivalence`; no extra action.

---

## Self-Review (against spec)

**Spec coverage:**
- §4.1 `also_reported_by` field → Task 1(a). ✓
- §4.2 `dedupe_findings` (primary=most severe, ties first-seen, others sorted, committed OR) → Task 1(b) + tests. ✓
- §4.3 pipeline order + `deduped` summary + markdown suffix + `--no-dedup` → Task 1(c/d) + Task 2(e/f) + Task 2 arg. ✓
- §5.1 `worker_count` → Task 2(b) + `TestWorkerCount`. ✓
- §5.2 ThreadPool, plan-order collection, `--jobs` → Task 2(d) + arg. ✓
- §6 tests (dedup, markdown, worker_count, equivalence, no-dedup) → Tasks 1–2. ✓
- §7 docs/version/roadmap → Task 3. ✓

**Placeholder scan:** all code steps carry full code; doc steps have explicit content. None.

**Type consistency:** `dedupe_findings(findings)->(list,int)`, `worker_count(n_jobs,flag)->int`,
`Finding.also_reported_by`, `build_report(..., deduped=0)` used identically across tasks. The
concurrent block reuses `_execute_job`'s existing `(fs, (state, info))` return shape unchanged.
