#!/usr/bin/env python3
"""vibesafe — multi-scanner orchestrator (stdlib only).

Detects the project stack, runs each available security scanner (installed binary
or ephemeral runner), normalizes heterogeneous JSON output into a single Finding
schema, and writes report.json + report.md. Missing/failed tools degrade
gracefully — they are recorded as skipped/errored and never abort the run.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path

# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #
SEVERITIES = ["critical", "high", "medium", "low", "info"]
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
_SEV_ALIASES = {
    "moderate": "medium",
    "error": "high",
    "warning": "medium",
    "warn": "medium",
    "unknown": "info",
    "none": "info",
    "": "info",
}


def normalize_severity(value) -> str:
    if value is None:
        return "info"
    v = str(value).strip().lower()
    v = _SEV_ALIASES.get(v, v)
    return v if v in _SEV_RANK else "info"


def severity_sort_key(sev) -> int:
    return _SEV_RANK.get(normalize_severity(sev), len(SEVERITIES))


@dataclass
class Finding:
    tool: str
    category: str            # secrets | deps | sast | iac | license
    severity: str            # critical | high | medium | low | info
    title: str
    file: str | None = None
    line: int | None = None
    package: str | None = None
    cve: str | None = None
    rule_id: str | None = None
    remediation: str | None = None
    committed: bool | None = None   # secrets: True if the file is git-tracked (in history)
    fingerprint: str | None = None  # stable, line-independent id (baseline/dedup basis)


def finding_to_dict(f: "Finding") -> dict:
    d = asdict(f)
    d["severity"] = normalize_severity(d["severity"])
    return d


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


# --------------------------------------------------------------------------- #
# Baseline (freeze existing findings; re-scan shows only new ones)
# --------------------------------------------------------------------------- #
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


# --------------------------------------------------------------------------- #
# .vibesafeignore (pattern-based suppression of accepted findings)
# --------------------------------------------------------------------------- #
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


# --------------------------------------------------------------------------- #
# Diff / staged scoping (post-filter findings to changed files)
# --------------------------------------------------------------------------- #
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


# --------------------------------------------------------------------------- #
# Stack detection
# --------------------------------------------------------------------------- #
def detect_stack(path) -> dict:
    path = Path(path)

    def has(*globs):
        return any(next(path.rglob(g), None) is not None for g in globs)

    return {
        "node": (path / "package.json").exists() or has("package.json"),
        "python": any((path / f).exists() for f in
                      ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py"))
        or has("requirements.txt", "pyproject.toml"),
        "docker": has("Dockerfile", "*.dockerfile", "docker-compose.yml", "docker-compose.yaml"),
        "terraform": has("*.tf"),
        "git": (path / ".git").exists(),
    }


def tracked_abs_paths(target):
    """Absolute paths of all git-tracked files for the repo containing `target`.

    Returns a set of absolute path strings, or None if `target` is not inside a
    git work tree (so callers can distinguish "not tracked" from "unknown")."""
    target = Path(target)
    try:
        top = subprocess.run(["git", "-C", str(target), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=10)
        if top.returncode != 0 or not top.stdout.strip():
            return None
        root = Path(top.stdout.strip())
        r = subprocess.run(["git", "-C", str(target), "ls-files", "--full-name"],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return None
        return {str((root / line.strip()).resolve())
                for line in r.stdout.splitlines() if line.strip()}
    except Exception:
        return None


def annotate_committed(findings, target, tracked):
    """Set finding.committed for secrets findings based on git-tracked status.

    `tracked` is the set from tracked_abs_paths (None → not a git repo → leave unknown)."""
    if tracked is None:
        return
    target = Path(target)
    for f in findings:
        if f.category == "secrets" and f.file:
            try:
                ap = str((target / f.file).resolve())
            except Exception:
                continue
            f.committed = ap in tracked


# --------------------------------------------------------------------------- #
# Tool resolution / safe runner
# --------------------------------------------------------------------------- #
_PY_TOOLS = {"semgrep", "checkov"}          # runnable via uvx / pipx run
_NATIVE_ONLY = {"gitleaks", "trivy", "osv-scanner"}  # need a real install

INSTALL_HINTS = {
    "gitleaks": "brew install gitleaks",
    "trivy": "brew install trivy",
    "osv-scanner": "brew install osv-scanner",
    "semgrep": "brew install semgrep  # or: uvx semgrep / pipx run semgrep",
    "checkov": "pipx install checkov  # or: pipx run checkov",
    "npm": "install Node.js (npm ships with it)",
    "pip-audit": "pip install pip-audit",
}


def resolve_runner(tool, have=None, allow_ephemeral=None):
    """Return a command-prefix list to run `tool`, or None if unavailable.

    `have` lets tests inject availability. `allow_ephemeral` toggles npx/uvx/pipx
    fallbacks; it defaults to off when VIBESAFE_NO_EPHEMERAL is set (used by the
    test suite to stay hermetic/offline).
    """
    have = have or (lambda t: shutil.which(t) is not None)
    if allow_ephemeral is None:
        allow_ephemeral = not os.environ.get("VIBESAFE_NO_EPHEMERAL")
    if have(tool):
        return [tool]
    if allow_ephemeral and tool in _PY_TOOLS:
        if have("uvx"):
            return ["uvx", tool]
        if have("pipx"):
            return ["pipx", "run", tool]
    return None


def run_tool(cmd, cwd, timeout=120):
    """Run a command capturing output. Returns (returncode, stdout, stderr, status).

    status ∈ {ok, timeout, missing, errored}. A non-zero exit code is still "ok"
    (many scanners exit non-zero when they find issues)."""
    try:
        p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr, "ok"
    except subprocess.TimeoutExpired:
        return None, "", f"timeout after {timeout}s", "timeout"
    except FileNotFoundError as e:
        return None, "", str(e), "missing"
    except Exception as e:  # never let one tool crash the whole run
        return None, "", repr(e), "errored"


# --------------------------------------------------------------------------- #
# Normalizers — each maps one tool's parsed JSON to a list[Finding]
# --------------------------------------------------------------------------- #
def _first_cve(aliases, fallback=None):
    for a in aliases or []:
        if str(a).upper().startswith("CVE-"):
            return a
    return fallback


def normalize_npm_audit(raw) -> list:
    out = []
    for name, v in (raw.get("vulnerabilities") or {}).items():
        sev = normalize_severity(v.get("severity"))
        cve = None
        title = f"Vulnerable dependency: {name}"
        for via in v.get("via") or []:
            if isinstance(via, dict):
                title = via.get("title", title)
                url = str(via.get("url", ""))
                if "advisories" in url or "GHSA" in url.upper():
                    cve = cve or url
        out.append(Finding(
            tool="npm-audit", category="deps", severity=sev, title=title,
            package=name, cve=cve,
            remediation=f"Upgrade {name} (npm audit fix) to a non-vulnerable range."))
    return out


def normalize_pip_audit(raw) -> list:
    deps = raw.get("dependencies") if isinstance(raw, dict) else raw
    out = []
    for dep in deps or []:
        name, ver = dep.get("name"), dep.get("version")
        for vu in dep.get("vulns") or []:
            fixes = ", ".join(vu.get("fix_versions") or []) or "a patched version"
            out.append(Finding(
                tool="pip-audit", category="deps", severity="high",  # pip-audit omits CVSS
                title=f"Vulnerable dependency: {name} {ver} ({vu.get('id')})",
                package=name, cve=_first_cve(vu.get("aliases"), vu.get("id")),
                remediation=f"Upgrade {name} to {fixes}."))
    return out


def _cvss_to_sev(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "high"
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"


def normalize_osv(raw) -> list:
    out = []
    for res in raw.get("results") or []:
        src = (res.get("source") or {}).get("path")
        for pkg in res.get("packages") or []:
            p = pkg.get("package") or {}
            max_sev = None
            for g in pkg.get("groups") or []:
                max_sev = g.get("max_severity") or max_sev
            for vu in pkg.get("vulnerabilities") or []:
                out.append(Finding(
                    tool="osv-scanner", category="deps", severity=_cvss_to_sev(max_sev),
                    title=f"Vulnerable dependency: {p.get('name')}@{p.get('version')} ({vu.get('id')})",
                    file=src, package=p.get("name"),
                    cve=_first_cve(vu.get("aliases"), vu.get("id")),
                    remediation=f"Upgrade {p.get('name')} to a fixed version."))
    return out


def normalize_gitleaks(raw) -> list:
    items = raw if isinstance(raw, list) else raw.get("findings", [])
    out = []
    for r in items or []:
        out.append(Finding(
            tool="gitleaks", category="secrets", severity="critical",
            title=f"Potential secret: {r.get('Description', 'secret detected')}",
            file=r.get("File"), line=r.get("StartLine"), rule_id=r.get("RuleID"),
            remediation="Rotate the secret, remove it from code/history, load from env/secret manager."))
        # NOTE: deliberately do NOT copy r['Secret'] into the finding (no secret leakage).
    return out


_SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def normalize_semgrep(raw) -> list:
    out = []
    for r in raw.get("results") or []:
        extra = r.get("extra") or {}
        sev = _SEMGREP_SEV.get(str(extra.get("severity", "")).upper(),
                               normalize_severity(extra.get("severity")))
        out.append(Finding(
            tool="semgrep", category="sast", severity=sev,
            title=(extra.get("message") or r.get("check_id") or "SAST finding")[:200],
            file=r.get("path"), line=(r.get("start") or {}).get("line"),
            rule_id=r.get("check_id"),
            remediation="Review the flagged code path and apply the secure pattern (see references/remediation.md)."))
    return out


def normalize_trivy(raw) -> list:
    out = []
    for res in raw.get("Results") or []:
        target = res.get("Target")
        for v in res.get("Vulnerabilities") or []:
            out.append(Finding(
                tool="trivy", category="deps", severity=normalize_severity(v.get("Severity")),
                title=v.get("Title") or f"Vulnerable dependency: {v.get('PkgName')}",
                file=target, package=v.get("PkgName"), cve=v.get("VulnerabilityID"),
                remediation=(f"Upgrade {v.get('PkgName')} to {v.get('FixedVersion')}."
                             if v.get("FixedVersion") else "Upgrade to a patched version.")))
        for m in res.get("Misconfigurations") or []:
            out.append(Finding(
                tool="trivy", category="iac", severity=normalize_severity(m.get("Severity")),
                title=m.get("Title") or m.get("ID"), file=target,
                line=(m.get("CauseMetadata") or {}).get("StartLine"),
                rule_id=m.get("ID"), remediation=m.get("Resolution")))
        for s in res.get("Secrets") or []:
            out.append(Finding(
                tool="trivy", category="secrets",
                severity=normalize_severity(s.get("Severity", "critical")),
                title=f"Potential secret: {s.get('Title') or s.get('RuleID')}",
                file=target, line=s.get("StartLine"), rule_id=s.get("RuleID"),
                remediation="Rotate the secret and remove it from the repo."))
        for lic in res.get("Licenses") or []:
            out.append(Finding(
                tool="trivy", category="license", severity=normalize_severity(lic.get("Severity")),
                title=f"License risk: {lic.get('Name')} ({lic.get('PkgName')})",
                file=target, package=lic.get("PkgName"),
                remediation="Review license compatibility with your distribution terms."))
    return out


def normalize_checkov(raw) -> list:
    out = []
    for c in ((raw.get("results") or {}).get("failed_checks")) or []:
        rng = c.get("file_line_range") or [None]
        out.append(Finding(
            tool="checkov", category="iac", severity=normalize_severity(c.get("severity")),
            title=c.get("check_name") or c.get("check_id"),
            file=c.get("file_path"), line=rng[0], rule_id=c.get("check_id"),
            remediation=c.get("guideline") or "Apply the recommended secure configuration."))
    return out


# --------------------------------------------------------------------------- #
# Report build + markdown render
# --------------------------------------------------------------------------- #
def build_report(findings, target, run, skipped, errored, duration_s) -> dict:
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
            "scanners_run": run,
            "scanners_skipped": skipped,
            "scanners_errored": errored,
            "duration_s": round(duration_s, 2),
            "target": str(target),
        },
        "findings": [finding_to_dict(f) for f in findings],
    }


def render_markdown(rep: dict) -> str:
    s = rep["summary"]
    L = [f"# vibesafe report — `{s['target']}`", ""]
    L.append("| Severity | Count |")
    L.append("|---|---|")
    for sev in SEVERITIES:
        L.append(f"| {sev} | {s.get(sev, 0)} |")
    L.append("")
    if s.get("committed_secrets"):
        L.append(f"> ⚠️ **{s['committed_secrets']} secret(s) in git-tracked files "
                 f"(committed — in history; rotate + purge).**")
        L.append("")
    if rep["findings"]:
        L.append("| Sev | Category | Finding | Location |")
        L.append("|---|---|---|---|")
        for f in rep["findings"]:
            loc = f.get("file") or ""
            if f.get("line"):
                loc += f":{f['line']}"
            title = str(f["title"]).replace("|", "/")
            if f.get("committed"):
                title = "🔓 committed — " + title
            L.append(f"| {f['severity']} | {f['category']} | {title} | {loc} |")
        L.append("")
    run = ", ".join(s["scanners_run"]) or "none"
    cov = f"**Coverage:** ran: {run}"
    if s["scanners_skipped"]:
        sk = "; ".join(f"{x['tool']} ({x['reason']} → `{x.get('install', '')}`)"
                       for x in s["scanners_skipped"])
        cov += f" · skipped: {sk}"
    if s["scanners_errored"]:
        cov += " · errored: " + ", ".join(x["tool"] for x in s["scanners_errored"])
    cov += f" · {s['duration_s']}s"
    L.append(cov)
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
CATEGORY_OF = {
    "gitleaks": "secrets", "npm": "deps", "pip-audit": "deps",
    "osv-scanner": "deps", "semgrep": "sast", "trivy": "iac", "checkov": "iac",
}

# Vendored / build / data directories that should never be scanned as source.
# semgrep and trivy honor these via flags; gitleaks via scripts/gitleaks.toml.
EXCLUDE_DIRS = ["node_modules", ".git", "dist", "build", ".next", ".nuxt",
                ".dart_tool", ".gradle", "vendor", "postgres_data",
                "__pycache__", ".venv", "coverage"]
GITLEAKS_CONFIG = str(Path(__file__).resolve().parent / "gitleaks.toml")


def _plan(stack, only):
    """Yield (tool, argv, normalizer) for the applicable scanners."""
    gl = ["dir", ".", "--no-banner", "-f", "json", "-r", "{REPORT}"]
    if Path(GITLEAKS_CONFIG).exists():
        gl += ["--config", GITLEAKS_CONFIG]
    jobs = [("gitleaks", gl, normalize_gitleaks)]

    if stack["node"]:
        jobs.append(("npm", ["audit", "--json"], normalize_npm_audit))
    if stack["python"]:
        jobs.append(("pip-audit", ["-f", "json"], normalize_pip_audit))
    jobs.append(("osv-scanner", ["--format", "json", "-r", "."], normalize_osv))

    sg = ["--config", "p/security-audit", "--config", "p/secrets",
          "--config", "p/owasp-top-ten", "--json", "--quiet"]
    for d in EXCLUDE_DIRS:
        sg += ["--exclude", d]
    sg.append(".")
    jobs.append(("semgrep", sg, normalize_semgrep))

    if stack["docker"] or stack["terraform"]:
        skip = ",".join(f"**/{d}" for d in EXCLUDE_DIRS)
        jobs.append(("trivy",
                     ["fs", "--format", "json", "--scanners",
                      "vuln,misconfig,secret,license", "--skip-dirs", skip, "."],
                     normalize_trivy))
    if only:
        jobs = [j for j in jobs if CATEGORY_OF.get(j[0]) in only]
    return jobs


def _rm(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _execute_job(tool, argv, normalizer, cwd, timeout):
    """Returns (findings, (state, info)) where state ∈ {run, skipped, errored}.

    Supports a "{REPORT}" placeholder in argv: it is replaced with a temp file the
    tool writes its JSON report to (some tools, e.g. gitleaks, refuse to write to
    stdout), which is then read back as the raw output.

    Crucially: an empty result with a non-zero exit code is treated as an *error*,
    not as "ran with 0 findings" — so a tool that fatally fails is never silently
    masked in the coverage line.
    """
    name = "npm-audit" if tool == "npm" else tool
    runner = resolve_runner(tool)
    if runner is None:
        return [], ("skipped", {"tool": name, "reason": "not installed",
                                "install": INSTALL_HINTS.get(tool, "")})

    report_file = None
    if "{REPORT}" in argv:
        fd, report_file = tempfile.mkstemp(prefix="vibesafe-", suffix=".json")
        os.close(fd)
        argv = [report_file if a == "{REPORT}" else a for a in argv]

    rc, out, err, status = run_tool(runner + argv, cwd=cwd, timeout=timeout)

    if status != "ok":
        if report_file:
            _rm(report_file)
        return [], ("errored", {"tool": name, "reason": status})

    if report_file is not None:
        try:
            raw = Path(report_file).read_text()
        except OSError:
            raw = ""
        _rm(report_file)
    else:
        raw = out
    raw = raw.strip()

    if not raw:
        # No output: distinguish a clean run (exit 0) from a failed tool (exit != 0)
        # so a fatal failure is surfaced, never masked as "ran with 0 findings".
        if rc not in (0, None):
            tail = ((err or "").strip().splitlines() or [""])[-1]
            return [], ("errored", {"tool": name, "reason": f"exit {rc}: {tail[:120]}"})
        return [], ("run", name)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return [], ("errored", {"tool": name, "reason": "bad json"})
    return normalizer(data), ("run", name)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="scan.py", description="vibesafe multi-scanner")
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--only", default="", help="comma list: secrets,deps,sast,iac,license")
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--no-install-hints", action="store_true")
    a = ap.parse_args(argv)

    target = Path(a.path).resolve()
    out_dir = Path(a.out_dir) if a.out_dir else Path(tempfile.mkdtemp(prefix="vibesafe-"))
    out_dir.mkdir(parents=True, exist_ok=True)
    only = {x.strip() for x in a.only.split(",") if x.strip()}
    stack = detect_stack(target)

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

    annotate_committed(findings, target, tracked_abs_paths(target))
    rep = build_report(findings, target, run, skipped, errored, time.time() - t0)
    (out_dir / "report.json").write_text(json.dumps(rep, indent=2))
    md = render_markdown(rep)
    (out_dir / "report.md").write_text(md)
    print(md)
    print(f"\n[vibesafe] report: {out_dir}/report.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
