# Automation: CI, pre-commit, exit codes, baseline & diff

`scan.py` is CI-friendly: it degrades gracefully, writes a machine-readable
`report.json`, and (opt-in) returns a severity-based exit code. This page covers the
flags and artifacts that make vibesafe usable in pipelines and on existing codebases.

## Exit codes (opt-in gating)

By default `scan.py` always exits `0` — findings are reported, never fatal (the
interactive co-pilot flow must never break). Turn on gating explicitly:

| Code | Meaning |
|---|---|
| `0` | Success; no gating triggered. |
| `1` | `--fail-on <sev>` set and ≥1 **shown** finding is at/above that severity. |
| `3` | `--fail-on-error` set and ≥1 scanner errored/timed out (only if no policy failure). |
| `2` | Argument/usage error (argparse). |

```bash
# fail the build if anything high or critical is present
python3 scripts/scan.py . --fail-on high

# additionally fail if a scanner crashed/timed out (don't silently under-cover)
python3 scripts/scan.py . --fail-on high --fail-on-error
```

Gating is evaluated on the **final shown** findings — i.e. *after* diff/staged scoping,
`.vibesafeignore`, and baseline subtraction. So CI fails only on **new, non-ignored** issues.

## Baseline — freeze existing debt, surface only new findings

For a codebase that already has findings, snapshot them once and then only see what's new:

```bash
# 1. create the baseline (writes vibesafe-baseline.json; never fails)
python3 scripts/scan.py . --update-baseline

# 2. from now on, hide the known set
python3 scripts/scan.py . --baseline vibesafe-baseline.json --fail-on high
```

`--baseline` and `--update-baseline` are mutually exclusive. The summary reports
`baselined` (how many known findings were hidden).

**Fingerprint** — each finding carries a stable `fingerprint` (sha1 over
`category | rule_id/cve | package | file | normalized-title`). It deliberately **excludes the
line number**, so edits *above* a finding don't invalidate the baseline. Trade-off: two
otherwise-identical findings in the same file share one fingerprint.

## `.vibesafeignore` — permanently suppress accepted findings / false positives

Place `.vibesafeignore` at the scan target root (or point to it with `--ignore-file`). One rule
per line; blank lines and `#` comments are ignored:

```gitignore
# by path glob (bare line == path:)
path:src/generated/*
vendor/**

# by scanner rule id
rule:CKV_DOCKER_3

# by CVE
cve:CVE-2021-23337
```

The summary reports `ignored` (how many findings were suppressed). Use the baseline to *freeze a
moment in time*; use `.vibesafeignore` for *permanent* suppressions (a rule you never want, a
known-false path).

## Diff / staged scoping — fast pre-commit & PR scans

Run the full scanners, then keep only findings in changed files:

```bash
python3 scripts/scan.py . --staged            # git-staged files (pre-commit)
python3 scripts/scan.py . --diff origin/main  # files changed since a ref (PRs)
```

`--staged` and `--diff` are mutually exclusive. **File-less** dependency findings (e.g. from
`npm audit`) are kept only when a dependency manifest/lockfile is among the changed files
(`package.json`, `package-lock.json`, `requirements*.txt`, `go.mod`, `Cargo.lock`, …). The summary
reports `scope` (`full` | `staged` | `diff:<ref>`) and `changed_files`. If git is unavailable the
scan reports the situation and yields nothing (rather than crashing).

## Dedup & parallelism

Findings for the same issue reported by multiple tools (e.g. one CVE from `trivy` and
`osv-scanner`) are **merged** into one entry — matched on category, CVE/rule, package, file and line
(title-independent), the most-severe wins and the others appear as `also_reported_by` (and
`(also: …)` in `report.md`). The summary reports `deduped`. Disable with `--no-dedup`. Scanner file
paths are normalized to target-relative first, so tools that emit absolute paths (e.g.
`osv-scanner`) dedupe, diff and baseline correctly.

Scanners run **concurrently** by default. `--jobs N` sets how many run at once (`1` = sequential for
debugging, `0` = all at once). Output is deterministic regardless of `--jobs`.

## GitHub Action

The repo ships a composite action (`action.yml`). It runs `scan.py` and uploads the report as an
artifact; pass `fail-on` to gate the job. The **caller installs** whichever scan engines they want
(missing engines degrade gracefully — see the report's coverage line).

```yaml
# .github/workflows/security.yml
name: security
on: [pull_request]
jobs:
  vibesafe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # install the engines you care about, e.g.:
      - run: pipx install semgrep
      - uses: marco-scheffler/vibesafe@v1.4.0
        with:
          path: .
          fail-on: high
```

## pre-commit

The repo ships `.pre-commit-hooks.yaml` (hook id `vibesafe`). It scans **staged** changes and
fails the commit on `high`+ findings. The external scanners must be on `PATH` on the developer's
machine (`brew install gitleaks trivy osv-scanner`; semgrep via `uvx`).

```yaml
# .pre-commit-config.yaml in a consuming repo
repos:
  - repo: https://github.com/marco-scheffler/vibesafe
    rev: v1.4.0
    hooks:
      - id: vibesafe
```

## Hermetic test mode

`VIBESAFE_NO_EPHEMERAL=1` disables `uvx`/`pipx`/`npx` fallbacks (only installed binaries run) — the
unit suite uses it to stay offline. The real-scanner detection proof lives in
`tests/test_live_detection.py` and runs only when `VIBESAFE_LIVE=1` is set (CI does this in a
dedicated job).
