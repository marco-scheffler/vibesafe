# vibesafe — Roadmap & Backlog

> Lebendes Dokument. „Now" = in Arbeit. Alles darunter ist bewusst zurückgestellt,
> aber festgehalten, damit nichts verloren geht. Reihenfolge = grobe Hebelwirkung (Impact/Aufwand).
> Stand: 2026-10-12.

## v1.8.1 — Hygiene

- [x] Action: Inputs via `env:` statt `${{ }}` im Skript (Script-Injection)
- [x] README: alle Dependency-Scanner (Go/Rust/Ruby/PHP/Java), Beispiele auf aktuelles Release
- [x] Lokaler Tool-State (`.tokensave/`, `.codex/`) nicht mehr getrackt

## v1.8.2 — CI-Wartung

- [x] Python-Minimum auf 3.9 (3.8 ist EOL)
- [x] Scanner-Installs gepinnt (kein `curl … main/install.sh | sh`, kein `@latest`), Actions per SHA
- [x] Beweglicher `v1`-Tag für die Action (pre-commit bleibt bewusst auf festem `rev`)
- [ ] `osv-scanner` v1.8.5 → v2 prüfen (CLI/JSON-Format geändert) — eigener PR

---

## Konkrete Code-Lücken (im Ist-Code gefunden, 2026-07-01)

Referenz für spätere Arbeit — jede ist faktisch, nicht spekulativ:

1. ~~**Keine Cross-Tool-Dedup**~~ — ✅ **behoben in v1.5.0**: dieselbe CVE von `npm audit` **+**
   `trivy` **+** `osv` wird jetzt per Fingerprint gemergt (`also_reported_by`).
2. ~~**Sequentielle Ausführung**~~ — ✅ **behoben in v1.5.0**: Scanner laufen parallel via
   `ThreadPoolExecutor` (`--jobs`, Default 4).
3. ~~**Stack-Detection ist Node/Python/Docker/TF-zentriert**~~ — ✅ **behoben (Go/Rust v1.7.0,
   Ruby/PHP/Java v1.8.0)**: alle gängigen Ökosysteme werden erkannt und adressiert.
4. ~~**Integrationstest bewies bisher keine Detection**~~ — ✅ **behoben in v1.4.0**: der
   `live-detection`-CI-Job weist mit echten Scannern Detection pro Kategorie nach.

---

## Tier 2 — Produkt-Tiefe (nächste Ausbaustufe)

- **Trend/History** — Report-Verlauf speichern, „N neu / M behoben seit letztem Scan" (baut auf
  Fingerprint + Baseline auf).

## Tier 3 — Coverage ausbauen

- **Mehr Ökosysteme** — ✅ **Go + Rust in v1.7.0**, **Ruby + PHP + Java in v1.8.0** (`bundler-audit`,
  `composer audit`, Java via `osv-scanner`). **Code-Lücke #3 vollständig behoben.**
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
