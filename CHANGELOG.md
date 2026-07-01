# Changelog

All notable changes to vibesafe are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions use semantic versioning.

## 1.4.0 — 2026-07-01

Automation & adoption: make vibesafe usable in pipelines and on existing codebases.

### Added
- **CI** (`.github/workflows/ci.yml`): a hermetic unit-test matrix (Python 3.8/3.11/3.12)
  plus a `live-detection` job that installs the real scanners and **proves** the vulnerable
  fixture is detected per category — guarding against normalizer drift.
- **Opt-in exit codes**: `--fail-on <severity>` (exit `1` on findings at/above the threshold)
  and `--fail-on-error` (exit `3` when a scanner errors). Default runs still exit `0`.
- **GitHub Action** (`action.yml`): composite action wrapping `scan.py`, uploads the report
  and gates on `fail-on`.
- **pre-commit hook** (`.pre-commit-hooks.yaml`): scans staged changes, fails on `high`+.
- **Fingerprint baseline**: `--update-baseline` / `--baseline` to freeze existing findings and
  surface only new ones. Each finding now carries a stable, line-independent `fingerprint`.
- **`.vibesafeignore`**: pattern-based suppression by `path:` / `rule:` / `cve:` (or bare glob).
- **Diff/staged scoping**: `--staged` and `--diff <ref>` restrict findings to changed files
  (file-less dependency findings kept only when a manifest changed).
- **`references/automation.md`**: CI, Action, pre-commit, exit codes, baseline, ignore and diff docs.

### Changed
- `report.json` summary now includes `scope`, `changed_files`, `ignored`, `baselined`, and each
  finding includes `fingerprint`.

## 1.3.0

- Packaged as a Claude Code plugin + marketplace; README polish; repository URL updates;
  flag git-tracked (committed) secrets; exclude vendored/build/data dirs from scanning.
