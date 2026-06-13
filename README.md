# vibesafe

A Claude Code **security co-pilot** skill. It has two halves:

- **Proactive guidance** — while you write web-app code, Claude applies secure patterns
  (input validation, parameterized queries, authorization checks, no hardcoded secrets, …).
- **On-demand scanning** — runs *real* scanners and reports prioritized findings with fixes:
  secrets, vulnerable dependencies, code SAST, IaC/container misconfig, and license risks.

Unlike a pure-prose guide, vibesafe actually executes tooling and normalizes every scanner's
output into a single report. Missing tools degrade gracefully (reported as skipped with an
install hint) — they never abort the run.

## Install

```bash
git clone <this-repo> ~/coding/vibesafe
ln -s ~/coding/vibesafe ~/.claude/skills/vibesafe
```
Restart Claude Code so the skill is picked up.

## Use

- Just write code — the guidance half triggers automatically on web-app work.
- To audit: ask Claude *"scan &lt;project&gt; for security issues"*, or run directly:

```bash
python3 ~/.claude/skills/vibesafe/scripts/scan.py <path>
```

The scanner writes `report.json` + `report.md` to a temp dir and prints the path.

## Scanners

| Category | Tool | Install |
|---|---|---|
| Secrets | gitleaks | `brew install gitleaks` |
| Dependencies | npm audit / pip-audit / osv-scanner | built-in / `pip install pip-audit` / `brew install osv-scanner` |
| Code (SAST) | semgrep | `uvx semgrep` / `brew install semgrep` |
| IaC / Container / License | trivy (fallback: checkov) | `brew install trivy` |

## Docs

- Design spec: [`docs/specs/2026-06-13-vibesafe-skill-design.md`](docs/specs/2026-06-13-vibesafe-skill-design.md)
- Implementation plan: [`docs/plans/2026-06-13-vibesafe.md`](docs/plans/2026-06-13-vibesafe.md)

## Tests

```bash
bash tests/run-tests.sh
```

## License

MIT — see [`LICENSE`](LICENSE). Inspired by the open-source VibeSec-Skill (Apache-2.0); all
content here is original.
