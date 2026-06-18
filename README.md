# vibesafe

> A security co-pilot **skill** for AI coding agents — proactive secure-coding guidance **plus**
> real, multi-scanner security audits with a single normalized report.

vibesafe makes your AI coding agent approach code like a bug-hunter. Two halves:

- **Proactive guidance** — while you write web-app code, the agent applies secure patterns
  (server-side validation, parameterized queries, authorization/ownership checks, secure headers,
  no hardcoded secrets).
- **On-demand scanning** — runs *real* tools and reports prioritized findings with fixes:
  **secrets, vulnerable dependencies, code (SAST), IaC/container misconfig, and license risks.**

Unlike a pure-prose guide, vibesafe actually executes the scanners (gitleaks, semgrep, trivy,
npm/pip/osv audit), **normalizes every tool's output into one report**, **redacts secret values**,
and flags **committed** secrets (those in git history) as top priority. Missing tools degrade
gracefully — they are reported as skipped with an install hint, never aborting the run.

## Requirements

- **Python 3.8+** — the orchestrator (`scripts/scan.py`) is **stdlib-only**, no `pip install` needed.
- **Optional scanners** for full coverage (see [Scanners](#scanners)). Without them vibesafe still
  runs whatever is available and shows the coverage gaps in the report.

## Install

### Claude Code — as a plugin (recommended)

```text
/plugin marketplace add marco-scheffler/vibesafe
/plugin install vibesafe@vibesafe-marketplace
```

### Claude Code — as a cloned skill

```bash
git clone https://github.com/marco-scheffler/vibesafe.git ~/.claude/skills/vibesafe
```

Either way, restart Claude Code, then just ask: *“scan &lt;project&gt; for security issues.”*

### Other agents

Same idea — clone into the agent's skills directory (global), or the project-local
`.<agent>/skills/` for a single project:

| Agent | Global skills directory |
|---|---|
| Claude Code | `~/.claude/skills/vibesafe` |
| Cursor | `~/.cursor/skills/vibesafe` |
| Codex | `~/.agents/skills/vibesafe` |
| GitHub Copilot | `~/.copilot/skills/vibesafe` |
| Antigravity (Gemini) | `~/.gemini/antigravity/skills/vibesafe` |

### Developing on the skill

Clone anywhere and symlink, so repo edits go live immediately:

```bash
git clone https://github.com/marco-scheffler/vibesafe.git ~/code/vibesafe
ln -s ~/code/vibesafe ~/.claude/skills/vibesafe
```

## Scanners

The orchestrator runs each tool if available (installed binary, or ephemeral `uvx`/`pipx run`
for Python tools), otherwise it skips it with an install hint. One-time full setup:

```bash
brew install gitleaks trivy osv-scanner   # native binaries
pip install pip-audit                      # usually already present
# semgrep needs no install — vibesafe runs it via `uvx`
```

| Category | Tool | Install |
|---|---|---|
| Secrets | gitleaks | `brew install gitleaks` |
| Dependencies | npm audit / pip-audit / osv-scanner | built-in / `pip install pip-audit` / `brew install osv-scanner` |
| Code (SAST) | semgrep | `uvx semgrep` (auto) / `brew install semgrep` |
| IaC / Container / License | trivy (fallback: checkov) | `brew install trivy` |

## Usage

- **Guidance** triggers automatically when you write or modify web-app code.
- **Audit on demand** — ask the agent (*“scan this project”*), or run the scanner directly:

```bash
python3 ~/.claude/skills/vibesafe/scripts/scan.py <path>
```

It writes `report.json` + `report.md` to a temp dir and prints the path. Useful flags:
`--only secrets,deps,sast,iac,license` · `--timeout <seconds>` · `--out-dir <dir>`.

## How it works & privacy

The scan engines run **locally** — your **source code is not uploaded**. Dependency scanners send
only **package names + versions** to advisory APIs (npm registry, PyPI, OSV); semgrep downloads
rulesets and trivy downloads a vulnerability DB (cached locally). No paid feed, no AI service.
Full details and the data-source matrix: [`references/tools.md`](references/tools.md).

Secret findings never contain the raw secret value (redacted by design), and carry a `committed`
flag — `true` means the secret is in a git-tracked file (in history → rotate **and** purge).

## Docs

- Secure-coding guidance: [`references/secure-coding.md`](references/secure-coding.md)
- Design spec: [`docs/specs/2026-06-13-vibesafe-skill-design.md`](docs/specs/2026-06-13-vibesafe-skill-design.md)
- Implementation plan: [`docs/plans/2026-06-13-vibesafe.md`](docs/plans/2026-06-13-vibesafe.md)

## Tests

```bash
bash tests/run-tests.sh
```

## License

MIT — see [`LICENSE`](LICENSE). Inspired by the open-source
[VibeSec-Skill](https://github.com/BehiSecc/VibeSec-Skill) (Apache-2.0); all content here is original.
