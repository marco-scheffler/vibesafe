---
name: vibesafe
description: Security co-pilot for web apps. Use when writing, reviewing, or auditing
  web application code, or when the user asks to scan/audit a project for vulnerabilities
  (secrets, vulnerable dependencies, injection/XSS/IDOR, insecure Docker/Terraform, license risks).
---

# vibesafe — secure-coding co-pilot

Two modes. Pick based on what the user is doing.

## Mode 1 — Proactive guidance (while writing code)

When writing or modifying web-app code, apply secure defaults and consult
`references/secure-coding.md` for the relevant category. Non-negotiables:

- Validate **all** input server-side (never trust the client).
- Parameterized queries / prepared statements — never string-build SQL.
- Authorization + ownership check on **every** data access (not just the route).
- Context-correct output encoding; rely on framework escaping.
- No hardcoded secrets — load from env / secret manager.
- Secure HTTP headers and cookies (`HttpOnly`, `Secure`, `SameSite`).

## Mode 2 — On-demand scan (audit / pre-commit)

When the user asks to scan/audit a project (or before a commit/release):

1. **Run the orchestrator** (bundled with this skill; the path resolves whether it is
   installed as a plugin or cloned into a skills directory):
   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT:-$HOME/.claude/skills/vibesafe}/scripts/scan.py" <path>
   ```
   Defaults to the current directory. It detects the stack, runs every available
   scanner, and writes `report.json` + `report.md` to a temp dir (path printed at the end).
   Useful flags: `--only secrets,deps,sast,iac,license`, `--timeout <s>`, `--out-dir <dir>`.
   For CI / pre-commit / existing codebases: `--fail-on <sev>` (severity-gated exit code),
   `--staged` / `--diff <ref>` (scan only changed files), `--baseline` / `--update-baseline` and
   `.vibesafeignore` (show only new / suppress accepted findings). Scanners run concurrently
   (`--jobs N`); cross-tool duplicates are merged (`--no-dedup` to disable). Details: `references/automation.md`.

2. **Read `report.json`** (not the raw tool output). Present a prioritized summary —
   critical/high first, each with `file:line`.

3. **Surface coverage gaps.** If the report lists skipped scanners, tell the user the
   exact `brew install …` / `uvx …` command from the coverage line. Offer to install the
   missing tools **once, only with their consent** — never auto-install.

4. **Propose fixes.** For each finding, give a concrete fix using
   `references/remediation.md` (framework-aware).

5. **Apply only after approval.** Never auto-edit code. After fixes, offer a re-scan to
   confirm the findings are resolved.

## Notes

- The scanner **degrades gracefully**: a missing/failed/timed-out tool is recorded as
  skipped/errored and never aborts the run. Always show the coverage line so gaps are visible.
- Report findings to the user **in their language**.
- Findings never contain raw secret values (they are redacted by design).
- **Secrets carry a `committed` flag.** `committed: true` means the secret lives in a
  **git-tracked** file (so it is in history — treat as compromised: rotate **and** purge from
  history). `committed: false` means local-only (gitignored) — real, but not leaked. The
  report's summary also has `committed_secrets`; lead with those.
- Scanner list, run commands, and what data goes online: `references/tools.md`.
