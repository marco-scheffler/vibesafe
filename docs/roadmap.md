# vibesafe — Roadmap & Backlog

> Lebendes Dokument. „Now" = in Arbeit / v1.4.0. Alles darunter ist bewusst zurückgestellt,
> aber festgehalten, damit nichts verloren geht. Reihenfolge = grobe Hebelwirkung (Impact/Aufwand).
> Stand: 2026-07-01.

## Now — v1.4.0 (Automation & Adoption)

Spec: `docs/specs/2026-07-01-vibesafe-automation-design.md`.

- [x] Design/Spec
- [x] CI (`test` hermetisch + `live-detection` mit echtem Detection-Nachweis)
- [x] Exit-Codes + `--fail-on` / `--fail-on-error`
- [x] GitHub Action (`action.yml`) + pre-commit-Hook (`.pre-commit-hooks.yaml`)
- [x] Fingerprint-Baseline (`--baseline` / `--update-baseline`) + `.vibesafeignore`
- [x] Diff-/Staged-Scan (`--staged` / `--diff`, Post-Filter)
- [x] Doku (`references/automation.md`, SKILL.md, README, CHANGELOG) + Version-Bump 1.4.0

---

## Konkrete Code-Lücken (im Ist-Code gefunden, 2026-07-01)

Referenz für spätere Arbeit — jede ist faktisch, nicht spekulativ:

1. **Keine Cross-Tool-Dedup** — jede `normalize_*` hängt unabhängig an; dieselbe CVE erscheint via
   `npm audit` **+** `trivy` **+** `osv` mehrfach. (Fingerprint aus v1.4.0 ist die Grundlage zum Fix.)
2. **Sequentielle Ausführung** — `for tool … in _plan()` läuft Scanner nacheinander; trivy-DB +
   semgrep + osv summieren sich in der Wallclock.
3. **Stack-Detection ist Node/Python/Docker/TF-zentriert** — osv/semgrep laufen zwar generisch,
   aber Go/Rust/Ruby/PHP/Java werden nicht erkannt oder adressiert.
4. **Integrationstest bewies bisher keine Detection** — nur Invarianten (kein Crash, Redaction,
   Coverage). (Wird in v1.4.0 durch den live-Job geschlossen.)

---

## Tier 2 — Produkt-Tiefe (nächste Ausbaustufe)

- **Cross-Tool-Dedup** — Findings über Tools hinweg per Fingerprint zusammenführen (Quellen-Tools
  als Liste behalten). Behebt Code-Lücke #1.
- **Parallele Scanner-Ausführung** — Thread-/Prozess-Pool über `_plan()`-Jobs; Per-Tool-Timeout
  bleibt. Behebt Code-Lücke #2. Größter Wallclock-Gewinn für den Audit-Flow.
- **SARIF-Output** (`--format sarif`) — GitHub Code-Scanning / IDE-Annotationen; Standard-Interop.
  Kombiniert mit der GitHub Action → Findings im PR-„Security"-Tab.
- **Trend/History** — Report-Verlauf speichern, „N neu / M behoben seit letztem Scan" (baut auf
  Fingerprint + Baseline auf).

## Tier 3 — Coverage ausbauen

- **Mehr Ökosysteme** — Stack-Detection + Messaging für Go (`go.mod`), Rust (`Cargo.lock`,
  cargo-audit), Ruby (`Gemfile.lock`, bundler-audit), PHP (`composer.lock`, composer audit),
  Java/Maven (osv/trivy). Behebt Code-Lücke #3.
- **Eigene semgrep-Regeln** (`rules/`) — für die in `references/tools.md` dokumentierten Lücken
  (string-gebautes SQL, Framework-spezifische Sinks). Differenzierer ggü. reinen Public-Packs.
- **SBOM-Generierung** (CycloneDX/SPDX via trivy/syft) — Supply-Chain-Compliance.
- **Container-Image-Scan** — nicht nur `trivy fs` (Dockerfile-Misconfig), sondern gebautes Image.
- **`--offline`-Modus** — nur lokale/gecachte DBs, keine Dependency-API-Calls (sensible/interne
  Repos). War schon in der v1-Spec §13 vorgesehen.

## Tier 4 — Tiefere Agent-Integration (vibesafes USP ggü. „nur CLI-Scanner")

- **Fix→Re-Scan-Verify-Loop formalisieren** — nach angewandtem Fix automatisch nur die geänderten
  Dateien diff-scannen (nutzt v1.4.0 `--diff`) und Auflösung bestätigen.
- **Dedizierter `security-reviewer`-Subagent** im Plugin (`agents/`).
- **Optionaler opt-in Hook** (PreToolUse/Stop) — z. B. Scan vor Commit; sorgfältig wegen Perf.
- **`.vibesafe.toml` Projekt-Config** — excludes, timeout, thresholds, Tool-Auswahl zentral statt
  nur via CLI-Flags.

## Tier 5 — Distribution & Community (laufend)

- Slash-Command im Plugin (`/vibesafe-scan`) für erstklassige Entdeckbarkeit.
- Demo-GIF / asciinema (Scan → Fix → Re-Scan) im README.
- Eintrag in „awesome-claude-code"-Listen / Plugin-Directory, Ankündigung.
- CONTRIBUTING.md, Issue-/PR-Templates.
```
