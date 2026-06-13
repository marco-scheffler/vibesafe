# Remediation patterns

Keyed by finding `category`. Each finding in `report.json` carries `tool`, `severity`,
`file`/`line` (or `package`), `rule_id`/`cve`, and a short `remediation`. Use this file to
turn that into a concrete, framework-aware fix. Always confirm with the user before editing.

## category: secrets

**Read it:** a credential/token was found in the code or history (`file:line`, `rule_id`).
The raw value is intentionally redacted from the report — open the file to see it.

**Canonical fix:**
1. **Rotate the secret immediately** (assume it is compromised — it may be in git history).
2. Remove it from code; load from environment or a secret manager.
3. Purge it from history if it was committed (`git filter-repo` / BFG), then force-push.
4. Add the pattern to `.gitignore` / pre-commit secret scanning.

```js
// before
const AWS_KEY = "AKIA...";
// after
const AWS_KEY = process.env.AWS_KEY;   // provided via env / secret manager
```

## category: deps

**Read it:** a dependency has a known vulnerability (`package`, `cve`, severity).

**Canonical fix:** upgrade to the fixed version; if none exists, pin a safe version, apply a
vendor patch, or remove the dependency.

```bash
# Node
npm audit fix            # or: npm install <pkg>@<fixed>
# Python
pip install -U <pkg>     # pin <pkg>>=<fixed> in requirements/pyproject
```
Re-run the scan to confirm the advisory is gone. Watch transitive deps (the fix may be in a
nested package — use `npm ls <pkg>` / `pip show`).

## category: sast

**Read it:** a code pattern matched a security rule (`rule_id`, `file:line`). Map the rule to
the right pattern in `secure-coding.md`. Common ones:

- **SQL injection** → parameterized queries / ORM bound params (never string interpolation).
- **Command injection** → avoid shell; pass argv arrays; allow-list inputs.
- **`eval` / dynamic code** → remove; use a safe parser or explicit dispatch.
- **XSS sink** → context-correct encoding; avoid `dangerouslySetInnerHTML` / `v-html`.
- **Weak crypto / hardcoded IV** → use vetted libraries and secure defaults.

```python
# before — SQL injection
db.execute("SELECT * FROM users WHERE name = '%s'" % name)
# after — parameterized
db.execute("SELECT * FROM users WHERE name = ?", (name,))
```

## category: iac

**Read it:** an infrastructure/container misconfiguration (`rule_id`, `file:line`).

**Canonical fixes (common):**
- Dockerfile: pin a digest/tag (not `latest`); add a non-root `USER`; minimal base image.
- Terraform/cloud: no `0.0.0.0/0` ingress on sensitive ports; encrypt at rest; least-privilege IAM; no public buckets.

```dockerfile
# before
FROM node:latest
# after
FROM node:22.11.0-slim
RUN useradd -m app
USER app
```

## category: license

**Read it:** a dependency uses a license that may be incompatible with how you distribute
(`package`, license name).

**Canonical fix:** confirm whether your distribution model is compatible (e.g. copyleft like
GPL in proprietary distribution). If not: replace the dependency, isolate it behind a service
boundary, or obtain a commercial license. This is a legal/judgment call — flag it, don't
auto-"fix".
