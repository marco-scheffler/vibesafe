# vibesafe — Design-Spec

- **Datum:** 2026-06-13
- **Status:** Genehmigt (Brainstorming abgeschlossen), bereit für Implementierungs-Planung
- **Autor:** Marco Scheffler

## 1. Zweck

`vibesafe` ist ein **globaler Claude-Code-Skill**, der Claude beim Schreiben von Web-App-Code zu einem
Security-Co-Piloten macht. Er ist als eigenständige, leistungsfähigere Alternative zum quelloffenen
`VibeSec-Skill` (Apache-2.0) konzipiert: VibeSec ist eine reine Markdown-Anleitung (passiv, kein
echtes Tooling). `vibesafe` kombiniert dieselbe Art von Secure-Coding-Guidance **mit echten,
ausgeführten Security-Scannern** und einem normalisierten Report.

## 2. Ziele / Nicht-Ziele

**Ziele**
- Proaktive Secure-Coding-Guidance beim Programmieren (passiv).
- Echte Schwachstellen-Scans auf Zuruf (aktiv): Secrets, Dependencies, SAST, IaC/Container, Lizenzen.
- Robuster Betrieb in einer Umgebung, in der die meisten Scanner **nicht** vorinstalliert sind.
- Priorisierter Report + Fixes erst nach Freigabe.
- Testgetrieben (echte Fixtures), versioniert.

**Nicht-Ziele (v1)**
- Kein MCP-Server / kein Plugin-Packaging.
- Keine fertige CI-Action (das Skript ist aber CI-tauglich).
- Keine eigenen semgrep-Regeln (öffentliche Rulesets nutzen).
- Kein Auto-Install ohne Consent.
- Kein dedizierter Offline-/Air-Gap-Modus (als spätere Erweiterung vorgesehen, siehe §13).

## 3. Getroffene Entscheidungen

| Thema | Entscheidung |
|---|---|
| Name | `vibesafe` |
| Grundmodus | **Hybrid** — passive Guidance + aktive On-Demand-Scans |
| Scan-Tiefe | **Comprehensive** — Secrets + Dependencies + SAST + IaC/Container + Lizenzen |
| Fix-Verhalten | **Report (nach Severity priorisiert) + Fix erst nach Freigabe** |
| Architektur | **B** — SKILL.md (Orchestrierungs-„Gehirn") + gebündeltes `scan.py` |
| Orchestrator-Sprache | **Python 3, nur stdlib** (`subprocess`, `json`, `argparse`) |
| Betrieb | **Online** (Offline-Modus = spätere Erweiterung) |
| Ort | Git-Repo `~/coding/vibesafe/`, Symlink → `~/.claude/skills/vibesafe` |
| Sprache der Inhalte | SKILL.md + references in **Englisch** (Trigger-Qualität, Portabilität); Claude reportet dem Nutzer in dessen Sprache (Deutsch) |

## 4. Architektur

Ansatz **B**: Die `SKILL.md` ist das knappe „Gehirn" (Trigger, Modi, Wie-scannen, Wie-reporten) und
nutzt *progressive disclosure* — Detailinhalte liegen in `references/` und werden nur bei Bedarf
geladen. Ein gebündeltes `scripts/scan.py` führt die externen Scanner deterministisch aus,
**normalisiert deren heterogenen Output in ein einheitliches Findings-Format** und schreibt
`report.json` + `report.md`. Claude liest `report.json` (nicht den rohen Tool-Output) und schlägt
Fixes vor.

Begründung gegen die Alternativen: Eine reine Markdown-SKILL.md (Ansatz A) müsste Claude bei jedem
Lauf 5+ Tools mit je eigenem JSON-Format korrekt zusammenstecken und parsen lassen — fehleranfällig,
langsam, inkonsistent. Ein MCP-Server (Ansatz C) wäre Overkill (eigene Infra, kein klassischer Skill).

## 5. Verzeichnisstruktur

```
vibesafe/                              # Git-Repo unter ~/coding/, Symlink nach ~/.claude/skills/vibesafe
├── SKILL.md                          # Orchestrierungs-Gehirn (knapp; YAML-Frontmatter: name, description)
├── scripts/
│   └── scan.py                       # Orchestrator: Stack-Erkennung, Scanner-Aufruf, Normalisierung → report.json + report.md
├── references/
│   ├── secure-coding.md              # Guidance (Access Control, XSS, CSRF, SSRF, Secrets, …) — on demand
│   ├── remediation.md                # Fix-Patterns pro Fund-Kategorie & Framework (React/Vue/Node/Python/.NET)
│   └── tools.md                      # Scanner-Matrix: Abdeckung, Lauf-Befehl, Install-Befehl, Output-Format
├── tests/
│   ├── fixtures/vulnerable-app/      # absichtlich verwundbares Mini-Projekt (gepflanzte Funde)
│   └── run-tests.sh                  # läuft scan.py gegen fixtures, prüft erwartete Funde + Graceful-Skip
├── docs/
│   └── specs/2026-06-13-vibesafe-skill-design.md
├── README.md
└── LICENSE
```

## 6. Die zwei Modi

**Modus 1 — Proaktive Guidance (passiv).**
Triggert über die `description`, wenn Web-App-Code geschrieben/geändert wird. Claude konsultiert
`references/secure-coding.md` und wendet sichere Patterns direkt an: serverseitige Input-Validierung,
parametrisierte Queries, Authz-/Ownership-Checks, Security-Header, keine hartkodierten Secrets,
sichere Defaults. Inhaltlich VibeSec-artig, aber als on-demand geladene Referenz (hält die SKILL.md schlank).

**Modus 2 — On-Demand-Scan (aktiv).**
Triggert auf Zuruf („scanne/audite dieses Projekt/diese Datei") oder vor Commit/Release. Ablauf:
`scan.py <pfad>` ausführen → `report.json` lesen → priorisierten Report zeigen → Fixes vorschlagen →
nach Freigabe anwenden (siehe §10).

## 7. Scanner-Matrix (Comprehensive)

| Kategorie | Primärtool | Lauf-Befehl (vereinfacht) | Beschaffung / Fallback |
|---|---|---|---|
| Secrets | **gitleaks** | `gitleaks detect --no-banner -f json` | brew/Binary · Fallback: trufflehog |
| Deps (Node) | **npm audit** | `npm audit --json` | eingebaut ✓ |
| Deps (Python) | **pip-audit** | `pip-audit -f json` | installiert ✓ · Fallback: osv-scanner |
| Deps (multi) | **osv-scanner** | `osv-scanner --format json -r .` | brew/Binary |
| SAST (Code) | **semgrep** | `semgrep --config p/security-audit --config p/secrets --config p/owasp-top-ten --json` | `uvx`/`pipx run` (ephemer) |
| IaC/Container | **trivy** | `trivy fs --format json .` | brew · Fallback: `pipx run checkov` |
| Lizenzen | **trivy** `--scanners license` | (in trivy enthalten) | brew |

Hinweis: `trivy` ist mehrzweckfähig (Vulns + Misconfig + Secrets + Lizenz). Wir behalten dennoch
spezialisierte Tools (gitleaks für Secrets, semgrep für Code-SAST) für mehr Tiefe und nutzen trivy
primär für IaC/Container/Lizenz.

## 8. Install- & Degradations-Strategie

Zentral, weil in der Zielumgebung nur `npm`, `pip-audit`, `node`, `python3` vorhanden sind.

- **Tier 1 — Null-Install:** `npm audit`, `pip-audit` (vorhanden). Node-Tools via `npx -y`,
  Python-Tools (semgrep) via `uvx` bzw. `pipx run` — **ephemer, ohne globale Installation**.
- **Tier 2 — native Binaries** (gitleaks, trivy, osv-scanner): nicht via npx/uvx lauffähig.
  `scan.py` prüft `command -v`. Fehlt das Tool → **kein Auto-Install**, sondern Eintrag
  `status: skipped (not installed)` + exakter `brew install …`-Hinweis im Report.
- **Einmal-Consent:** Beim ersten Scan mit fehlenden Tier-2-Tools bietet der Skill **einen**
  Sammelbefehl `brew install gitleaks trivy osv-scanner` an — nur mit Nutzer-OK.
- **Graceful Degradation:** Ein fehlendes/abstürzendes/timeoutendes Tool bricht **nie** den Rest ab.
  Der Report weist die Abdeckung aus (z. B. „5/6 Scanner liefen; trivy übersprungen").

## 9. `scan.py` — Vertrag

**CLI**
```
scan.py [PATH]                       # Default: aktuelles Verzeichnis
        [--only secrets,deps,sast,iac,license]   # Teilmenge der Kategorien
        [--out-dir DIR]              # Default: temporäres Verzeichnis ($TMPDIR/vibesafe-<ts>/), Pfad wird auf stdout gemeldet
        [--timeout 120]              # pro Tool, Sekunden
        [--no-install-hints]
```

**Ablauf**
1. **Stack-Erkennung:** `package.json`/`package-lock.json` → Node; `requirements.txt`/`pyproject.toml`
   → Python; `Dockerfile` → Container; `*.tf` → Terraform; Git-Repo → Secrets über History optional.
2. Pro aktivierter Kategorie: Tool lokalisieren (installiert? ephemerer Runner? sonst skip).
3. Tool mit Per-Tool-Timeout ausführen, stdout/stderr/Exit-Code erfassen.
4. Output in einheitliches Findings-Format parsen (§10).
5. `report.json` + `report.md` ins Ausgabeverzeichnis schreiben; `report.md` zusätzlich auf stdout ausgeben; Pfad melden.
6. Respektiert `.gitignore`; Default-Pfad = cwd; Ziel kann Unterordner/Datei sein.

**Isolation:** Jedes Tool läuft gekapselt; eine unbehandelte Ausnahme eines Tools darf den
Gesamtlauf nicht abbrechen.

## 10. Einheitliches Findings-Format & Report

`report.json`:
```json
{
  "summary": {
    "critical": 2, "high": 5, "medium": 3, "low": 1, "info": 0,
    "scanners_run": ["npm-audit", "pip-audit", "semgrep"],
    "scanners_skipped": [{"tool": "trivy", "reason": "not installed", "install": "brew install trivy"}],
    "scanners_errored": [],
    "duration_s": 8.1,
    "target": "/abs/pfad"
  },
  "findings": [
    {
      "tool": "semgrep",
      "category": "sast",
      "severity": "critical",
      "title": "SQL injection via string formatting",
      "file": "app/db.py",
      "line": 42,
      "package": null,
      "cve": null,
      "rule_id": "python.lang.security.sql-injection",
      "remediation": "Parametrisierte Queries / Bound Params verwenden."
    }
  ]
}
```
- `category`: `secrets | deps | sast | iac | license`
- `severity`: `critical | high | medium | low | info` (Mapping pro Tool normalisiert)
- `report.md`: nach Severity sortierte Tabelle + Abdeckungs-Footer (run/skipped/errored).

Claude liest **`report.json`** und kommuniziert die Funde dem Nutzer in dessen Sprache.

## 11. Report- & Fix-Flow

1. `scan.py <pfad>` ausführen, `report.json` lesen.
2. Priorisierte Zusammenfassung zeigen (Critical/High zuerst, mit `datei:zeile`).
3. Pro Fund konkreten Fix vorschlagen — aus `references/remediation.md`, framework-bewusst.
4. **Fix erst nach Freigabe** anwenden (gesammelt oder einzeln). Nie automatisch editieren.
5. Optional Re-Scan zur Bestätigung, dass der Fund verschwunden ist.

## 12. Datenquellen & Privacy

- **Scan-Engines laufen lokal**; der **Quellcode wird nicht hochgeladen** (Ausnahme: keine — die
  Dependency-Scanner senden nur Paketmetadaten, kein Code).
- **Dependency-Scanner** (`npm audit`, `pip-audit`, `osv-scanner`) senden **nur Paketname+Version**
  an Advisory-APIs (npm-Registry, PyPI/OSV, `api.osv.dev`).
- **semgrep** lädt nur die **Regelsätze** (semgrep.dev), scannt Code lokal; **trivy** lädt eine
  **Vuln-DB** (ghcr.io, lokal gecacht, Refresh ~6 h), scannt lokal; **gitleaks/checkov** sind voll lokal.
- Upstream-Quellen (frei/öffentlich): **OSV.dev**, **GitHub Advisory DB**, **NVD/CVE**,
  Distro-Tracker (Debian/Alpine/RHEL), semgrep-Registry. **Kein bezahlter Feed, kein KI-Dienst.**
- Der Report weist transparent aus, welche Scanner online gingen.

## 13. Spätere Erweiterungen (post-v1)

- **`--offline`-Modus:** nur lokale/gecachte DBs, keine Dependency-API-Aufrufe (für sensible/interne
  Repos wie WEBER).
- Fertige **CI-Action** (GitHub Actions) auf Basis desselben `scan.py`.
- Eigene **semgrep-Regeln** für hauseigene Patterns.
- **MCP-Server**-Variante, falls plattformübergreifend nötig.

## 14. Tests

`tests/fixtures/vulnerable-app/` enthält gepflanzte Probleme, mindestens je eines pro Kategorie:
hartkodierter API-Key (Secrets), Paket mit bekanntem CVE (Deps), Injection-Sink z. B. String-gebaute
SQL / `eval` (SAST), unsicheres `Dockerfile` z. B. `FROM node:latest` + root (IaC).
`tests/run-tests.sh` läuft `scan.py` gegen die Fixtures und prüft:
1. dass jede Kategorie ihren gepflanzten Fund liefert,
2. dass fehlende Tools sauber **skippen** (Eintrag in `scanners_skipped`) statt zu crashen.
Damit wird `scan.py` testgetrieben entwickelt.

## 15. Fehlerbehandlung

- Tool fehlt → `skipped` + Install-Hinweis (nicht fatal).
- Tool crasht / non-zero ohne parsebaren Output → `errored`, stderr-Tail, weiter.
- Per-Tool-Timeout (Default 120 s) → `timeout`, weiter.
- Kein erkennbares Projekt am Pfad → klare Meldung, Exit 0 mit leeren Findings.
- Kaputtes Tool-JSON → `errored`, weiter.
- `scan.py` wirft nie eine unbehandelte Ausnahme, die den Gesamtlauf abbricht.

## 16. Lizenz

Eigene Guidance und eigener Code → keine Apache-Verstrickung mit VibeSec. VibeSec dient nur als
Ideengeber. Falls doch Textpassagen übernommen werden, kommen `NOTICE` + Attribution hinzu.
Repo erhält eine eigene `LICENSE`: **MIT**.

## 17. Installation

1. Repo unter `~/coding/vibesafe/` (bereits `git init`).
2. Symlink: `ln -s ~/coding/vibesafe ~/.claude/skills/vibesafe`.
3. Verifizieren, dass Claude Code den Skill lädt (Skill erscheint in der Liste, `description` triggert).
