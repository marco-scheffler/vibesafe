# Scanner matrix & data sources

`scan.py` runs each scanner if it is installed, or via an ephemeral runner where possible
(`uvx` / `pipx run` for Python tools). Native binaries (gitleaks, trivy, osv-scanner) must
be installed to run; otherwise they are reported as **skipped** with the install hint below.

| Category | Tool | Run command (simplified) | Install |
|---|---|---|---|
| Secrets | gitleaks | `gitleaks detect --no-banner --no-git -f json -r /dev/stdout` | `brew install gitleaks` |
| Deps (Node) | npm audit | `npm audit --json` | ships with Node.js |
| Deps (Python) | pip-audit | `pip-audit -f json` | `pip install pip-audit` |
| Deps (multi) | osv-scanner | `osv-scanner --format json -r .` | `brew install osv-scanner` |
| SAST (code) | semgrep | `semgrep --config p/security-audit --config p/secrets --config p/owasp-top-ten --json --quiet .` | `uvx semgrep` / `brew install semgrep` |
| IaC / Container / License | trivy | `trivy fs --format json --scanners vuln,misconfig,secret,license .` | `brew install trivy` |
| IaC (fallback) | checkov | `checkov -d . -o json` | `pipx run checkov` |

One-time full setup: `brew install gitleaks trivy osv-scanner` (semgrep runs via `uvx`).

## Where the data comes from (privacy)

The **scan engines run locally**; your **source code is not uploaded**. What may touch the
network:

- **Dependency scanners** (`npm audit`, `pip-audit`, `osv-scanner`) send only **package
  name + version** to advisory APIs (npm registry, PyPI, `api.osv.dev`) — never your code.
- **semgrep** downloads only the **rulesets** (semgrep.dev), then scans locally.
- **trivy** downloads a **vulnerability DB** (ghcr.io, cached locally, refreshed ~6h), then
  scans locally.
- **gitleaks** and **checkov** are fully local (no network).

Upstream vulnerability data (all free/public): OSV.dev, GitHub Advisory Database, NVD/CVE,
distro security trackers (Debian/Alpine/RHEL), and the semgrep registry. No paid feed, no AI
service. The report's coverage line shows exactly which scanners ran.

## Hermetic mode for tests

Set `VIBESAFE_NO_EPHEMERAL=1` to disable `uvx`/`pipx`/`npx` fallbacks (only installed
binaries run). The test suite uses this to stay offline and fast. Normal usage leaves it unset.
