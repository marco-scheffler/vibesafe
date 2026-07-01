# vibesafe — Design-Spec: Go + Rust Ökosysteme (v1.7.0)

- **Datum:** 2026-07-01
- **Status:** Genehmigt (Brainstorming abgeschlossen), bereit für Implementierungs-Planung
- **Basis:** `main` (v1.6.0). Branch `feat/go-rust-ecosystems`.

## 1. Zweck

Erweitert vibesafe um **Go** und **Rust**: Stack-Detection + je ein ökosystem-spezifisches
SCA-Tool (`govulncheck`, `cargo-audit`) zusätzlich zur bestehenden osv-Abdeckung. Roadmap Tier 3
(Code-Lücke #3, erster Teil). Ruby/PHP/Java folgen später.

## 2. Entscheidungen

| Thema | Entscheidung |
|---|---|
| Tiefe | Detection **+** eigene SCA-Tools (nicht nur Detection) |
| Umfang | **Go + Rust** zuerst; Ruby/PHP/Java später |
| Go-Tool | `govulncheck` über **`-format sarif`** (ein Doc, passt in die Single-JSON-Pipeline) |
| Rust-Tool | `cargo-audit` (`cargo audit --json`) |
| Version | **1.7.0** |

## 3. Verifizierte Fakten

- **govulncheck** (offizielle Doku): `-format json` ist ein **Stream** von Objekten (ungeeignet
  für unser `json.loads`); `-format sarif` liefert **ein** SARIF-2.1.0-Doc. Source-Mode braucht
  Go-Toolchain + baubaren Modul (Reachability). `-mode binary` ohne Call-Stacks (nicht genutzt).
- **cargo-audit**: `cargo audit` am Projekt-Root; CI-Beispiel macht vorher `cargo generate-lockfile`
  → **`Cargo.lock` erwartet**; braucht Netz (RustSec-DB). JSON-Flag `--json` (Struktur unten defensiv
  behandelt; exakte Felder beim Impl gegen `--help` erfasst).

## 4. Detection

`detect_stack` (scan.py:292) ergänzt zwei Schlüssel:
```python
"go": (path / "go.mod").exists() or has("go.mod", "go.sum"),
"rust": (path / "Cargo.toml").exists() or has("Cargo.toml", "Cargo.lock"),
```

## 5. Scanner-Integration

### 5.1 `_plan` (scan.py:727) — neue Jobs
```python
if stack["go"]:
    jobs.append(("govulncheck", ["-format", "sarif", "./..."], normalize_govulncheck))
if stack["rust"]:
    jobs.append(("cargo-audit", ["audit", "--json"], normalize_cargo_audit))
```
- `govulncheck` binär, cwd = target. `cargo-audit` binär (direkt aufgerufen `cargo-audit audit …`).
- Beide sind **native** Tools (kein uvx/pipx). `resolve_runner` liefert `[tool]` wenn installiert,
  sonst `None` → `skipped` (graceful) mit Install-Hint.
- `CATEGORY_OF` += `"govulncheck": "deps", "cargo-audit": "deps"` (für `--only deps`).
- `INSTALL_HINTS` += `govulncheck: "go install golang.org/x/vuln/cmd/govulncheck@latest"`,
  `cargo-audit: "cargo install cargo-audit"`.

### 5.2 `normalize_cargo_audit(raw)`
Aus `raw["vulnerabilities"]["list"]`:
```python
for v in list:
    adv = v.get("advisory") or {}; pkg = v.get("package") or {}
    patched = ", ".join((v.get("versions") or {}).get("patched") or []) or "a patched version"
    Finding(tool="cargo-audit", category="deps", severity="high",   # RustSec liefert kein CVSS-Feld einheitlich
            title=adv.get("title") or f"Vulnerable dependency: {pkg.get('name')}",
            package=pkg.get("name"), cve=_first_cve(adv.get("aliases"), adv.get("id")),
            file="Cargo.lock",
            remediation=f"Upgrade {pkg.get('name')} to {patched}.")
```

### 5.3 `normalize_govulncheck(raw)` — SARIF parsen
```python
for run in raw.get("runs") or []:
    for res in run.get("results") or []:
        rid = res.get("ruleId")
        loc = res.get("locations") or []
        pl = (loc[0].get("physicalLocation") or {}) if loc else {}
        Finding(tool="govulncheck", category="deps",
                severity=_SARIF_TO_SEV.get(res.get("level"), "high"),
                title=((res.get("message") or {}).get("text") or rid or "Go vulnerability")[:200],
                file=(pl.get("artifactLocation") or {}).get("uri"),
                line=(pl.get("region") or {}).get("startLine"),
                rule_id=rid, cve=_first_cve([rid], rid),
                remediation="Update the module to a fixed version.")
```
Neue Map `_SARIF_TO_SEV = {"error": "high", "warning": "medium", "note": "low"}` (Umkehrung von
`_SARIF_LEVEL`).

## 6. Dedup-Interaktion
Beide liefern `category=deps`. Der bestehende `dedupe_key` (`category|cve/rule_id|package|file|line`)
merged Überlappungen mit osv, wenn dieselbe Advisory-ID + Package + Datei matchen. GO-IDs (govulncheck)
vs. CVE/GHSA (osv) differieren oft → teils kein Merge; `also_reported_by` macht Mehrfachquellen sichtbar.
Akzeptiert (keine ID-Alias-Auflösung in dieser Iteration).

## 7. Tests (hermetisch)
- `detect_stack`: `go.mod` → `go` True; `Cargo.lock` → `rust` True; leeres Verzeichnis → beide False.
- `normalize_cargo_audit`: Fixture `tests/fixtures/raw/cargo-audit.json` (dokumentiertes Format) →
  Finding(deps, package, cve=RUSTSEC/CVE, file=Cargo.lock, remediation enthält patched-Version).
- `normalize_govulncheck`: Fixture `tests/fixtures/raw/govulncheck-sarif.json` → Finding(deps,
  govulncheck, severity aus level, rule_id=GO-id, file/line aus location).
- `_plan`: bei `stack["go"]`/`stack["rust"]` erscheinen die Jobs; `--only deps` behält sie.
- Graceful: fehlendes Tool → `skipped` mit Install-Hint (deckt der bestehende `_execute_job`-Pfad ab).

## 8. Docs / Version
- `references/tools.md`: Scanner-Matrix += Go (govulncheck) / Rust (cargo-audit); Datenquellen
  (RustSec-DB, Go-Vuln-DB) im Privacy-Teil.
- `CHANGELOG.md`: `1.7.0`. Version-Bump 1.7.0 (`plugin.json`, `marketplace.json`, README-Badge).
- `docs/roadmap.md`: Tier 3 „Mehr Ökosysteme" — Go + Rust erledigt, Ruby/PHP/Java bleiben offen;
  Code-Lücke #3 teil-behoben.

## 9. Risiken
- **cargo-audit JSON-Feldnamen** nicht 1:1 aus der README bestätigt → defensiv (`.get()`), Fixture nach
  dokumentiertem Format; bei Drift kein Crash (leere Liste), spätere Live-Detection fängt es.
- **govulncheck Build-Abhängigkeit**: nicht-baubarer Modul → `errored` (graceful); osv deckt `go.mod`
  weiter ab. Kein Merge-Gate für den (informativen) Live-Job.
- **Keine lokalen Live-Fixtures** (Tools nicht installiert) → Unit-Tests über erfasste Roh-Fixtures,
  wie die bestehenden Normalizer.
