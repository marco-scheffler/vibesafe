# Changelog

All notable changes to vibesafe are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions use semantic versioning.

## 1.8.0 — 2026-07-01

### Added
- **Ruby, PHP & Java ecosystems**: `detect_stack` recognizes Ruby (`Gemfile.lock`), PHP
  (`composer.json`/`composer.lock`), and Java (`pom.xml`/Gradle). Runs `bundler-audit` (Ruby) and
  `composer audit` (PHP) as dedicated dependency scanners (deduped against `osv-scanner`); Java
  dependencies covered by the always-on `osv-scanner`. All degrade gracefully when the tool
  isn't installed. End-to-end detection proven in CI with real tools.
- **Detected ecosystems** listed in `report.json` (`summary.stack`) and the markdown report
  (`Detected:` line).

### Changed
- `npm audit` now runs only when an npm lockfile (`package-lock.json`/`npm-shrinkwrap.json`) is
  present; pure yarn/pnpm projects are covered by `osv-scanner` instead of erroring on a missing
  npm lockfile.

## 1.7.0 — 2026-07-01

### Added
- **Go & Rust ecosystems**: `detect_stack` recognizes Go (`go.mod`) and Rust
  (`Cargo.toml`/`Cargo.lock`), and runs `govulncheck` (via SARIF) and `cargo-audit` as additional
  dependency scanners (deduped against `osv-scanner`). Both degrade gracefully when the tool isn't
  installed.

## 1.6.0 — 2026-07-01

### Added
- **SARIF output**: every scan writes `report.sarif` (SARIF 2.1.0, one run per tool) alongside
  `report.json`/`report.md`.
- **Action `upload-sarif` input**: opt-in upload to GitHub code scanning via
  `github/codeql-action/upload-sarif@v4` (needs `security-events: write`).

## 1.5.0 — 2026-07-01

Engine quality.

### Added
- **Cross-tool dedup** (default on): findings for the same issue reported by multiple tools
  (matched on category / CVE-or-rule / package / file / line — title-independent) are merged;
  most-severe wins, other tools listed in `also_reported_by`. Summary reports `deduped`; disable
  with `--no-dedup`.
- **Parallel scanners**: `--jobs N` runs scanners concurrently (default 4; `1`=sequential, `0`=all).
  Output stays deterministic regardless of `--jobs`.

### Changed
- `report.json` summary gains `deduped`; merged findings gain `also_reported_by`.

### Fixed
- Scanner file paths are normalized to target-relative, so findings from tools that emit absolute
  paths (e.g. `osv-scanner`) now work correctly with `--diff`/`--staged` and portable baselines.

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
