# vibesafe — Design-Spec: Cross-Tool-Dedup + Parallelität (v1.5.0)

- **Datum:** 2026-07-01
- **Status:** Genehmigt (Brainstorming abgeschlossen), bereit für Implementierungs-Planung
- **Autor:** Marco Scheffler
- **Basis:** Branch `feat/automation-adoption` (v1.4.0, PR #1) — dieses Feature ist darauf gestapelt.
- **Vorgänger-Spec:** `docs/specs/2026-07-01-vibesafe-automation-design.md`

## 1. Zweck

Behebt zwei im Ist-Code dokumentierte Lücken (siehe `docs/roadmap.md`, Tier 2):

1. **Cross-Tool-Dedup** — dieselbe Schwachstelle wird heute mehrfach gemeldet (z. B. eine
   lodash-CVE via `npm audit` **+** `trivy` **+** `osv-scanner`), weil jeder Normalizer unabhängig
   anhängt. Das verrauscht den Report.
2. **Sequentielle Ausführung** — Scanner laufen nacheinander; `trivy`-DB + `semgrep` + `osv`
   summieren sich in der Wallclock.

Beides nutzt bzw. ergänzt die v1.4.0-Bausteine (Fingerprint, isoliertes `_execute_job`).

## 2. Ziele / Nicht-Ziele

**Ziele**
- Dedup **standardmäßig an** (mit Escape-Hatch), Parallelität mit sinnvollem Default und Drosselung.
- Deterministische Report-Ausgabe unabhängig von Nebenläufigkeit.
- Rein test-getrieben, hermetisch; keine neuen Laufzeit-Abhängigkeiten (nur stdlib
  `concurrent.futures`).

**Nicht-Ziele**
- Keine Änderung an Normalizern/Scanner-Aufrufen selbst.
- Kein SARIF, keine neuen Ökosysteme (bleiben Roadmap).
- Keine Prozess-Parallelität (Threads genügen — Scanner sind Subprozesse/IO-bound).

## 3. Getroffene Entscheidungen

| Thema | Entscheidung |
|---|---|
| Dedup-Default | **Immer an**, abschaltbar mit `--no-dedup` |
| Merge-Regel | höchste Severity; Primary = schwerstes Finding (Tie-Break: Plan-Reihenfolge); Quell-Tools in `also_reported_by` |
| Parallelität | `ThreadPoolExecutor`, **`--jobs` Default 4**; `1` = sequenziell, `0` = alle gleichzeitig |
| Version | **1.5.0** (Features → Minor-Bump) |

## 4. Cross-Tool-Dedup

### 4.1 Datenmodell
Neues Feld an `Finding`: `also_reported_by: list | None = None` (die *anderen* Quell-Tools eines
gemergten Fundes, sortiert; `None`, wenn nicht gemergt). Erscheint automatisch in `report.json`.

### 4.2 `dedupe_findings(findings) -> (list, removed)`
- Gruppiert nach `fingerprint` unter Beibehaltung der First-Seen-Reihenfolge (`dict`).
- Pro Gruppe:
  - **Primary** = Finding mit der schwersten Severity; bei Gleichstand das zuerst gesehene
    (→ deterministisch, folgt der Plan-Reihenfolge). Alle Primary-Felder bleiben erhalten.
  - `severity` = die des Primary (= höchste der Gruppe).
  - `also_reported_by` = sortierte, deduplizierte Liste der `tool`-Werte der übrigen
    Gruppenmitglieder (ohne den Primary-Tool); leere Liste → `None`.
  - `committed` = `True`, wenn **irgendein** Gruppenmitglied `committed is True` (Secrets).
- Rückgabe: `(gemergte_liste, len(vorher) - len(nachher))`.
- Findings ohne `fingerprint` kommen nicht vor (die Pipeline ruft `annotate_fingerprints` davor).

### 4.3 Einbindung & Report
- Pipeline-Order: `annotate_committed → annotate_fingerprints → **dedupe (falls nicht --no-dedup)**
  → diff → ignore → baseline → build_report → gating`.
- `build_report`-Summary: neues Feld **`deduped`** (Anzahl entfernter Duplikate).
- `render_markdown`: hat ein Finding `also_reported_by`, wird an den Titel ` (auch: t1, t2)`
  angehängt.
- CLI: **`--no-dedup`** (Default: Dedup an). `build_report` selbst bleibt unverändert in der
  Zähl-Logik → bestehende Normalizer-/Report-Unit-Tests bleiben grün.

## 5. Parallele Ausführung

### 5.1 `worker_count(n_jobs, flag) -> int` (reine Funktion)
- `flag == 1` → `1` (sequenziell).
- `flag <= 0` → `max(1, n_jobs)` (alle gleichzeitig).
- sonst → `min(flag, n_jobs)` (bzw. `1`, wenn `n_jobs == 0`).

### 5.2 Ausführung in `main()`
- `jobs = _plan(stack, only)`; `workers = worker_count(len(jobs), a.jobs)`.
- `workers == 1` → bisheriger sequentieller Pfad (unverändert).
- sonst → `ThreadPoolExecutor(max_workers=workers)`: jeder Job über `_execute_job(...)`;
  Ergebnisse werden **index-basiert** (`results[i]`) in **Plan-Reihenfolge** eingesammelt.
- Danach identische Aggregation wie heute: `findings += fs`; `run/skipped/errored` nach `state`.
  Da in Plan-Reihenfolge zusammengesetzt, bleibt die Coverage-Liste deterministisch.
- Per-Tool-Timeout unverändert (in `run_tool`). `_execute_job` ist zustandslos (eigene tempfiles,
  `subprocess.run`) → thread-safe.
- CLI: **`--jobs N`** (Default 4).

## 6. Tests (TDD, hermetisch)

- **`dedupe_findings`**: gleicher Fingerprint aus drei Tools → 1 Finding, Severity = höchste,
  `also_reported_by` = die anderen zwei (sortiert), `removed == 2`; verschiedene Fingerprints
  unangetastet; `committed`-OR-Merge.
- **Markdown**: gemergtes Finding zeigt ` (auch: …)`.
- **`worker_count`**: `(3,1)→1`, `(3,0)→3`, `(3,4)→3`, `(5,4)→4`, `(0,0)→1`.
- **Äquivalenz**: `main()` auf `tests/fixtures/vulnerable-app` mit `--jobs 1` und `--jobs 0`
  liefert **identische** Findings (gleiche Fingerprint-Menge) und identische `scanners_run`-Menge.
- **`--no-dedup`**: injizierte Duplikate bleiben erhalten, wenn gesetzt; werden gemergt, wenn nicht.

Alle hermetisch (`VIBESAFE_NO_EPHEMERAL=1`); reine Funktionen bzw. `main()` gegen die Fixture.

## 7. Housekeeping
- `references/automation.md` + SKILL.md: `--no-dedup` und `--jobs` dokumentieren.
- `CHANGELOG.md`: Eintrag `1.5.0`. Version-Bump 1.5.0 in `plugin.json`, `marketplace.json`, README-Badge.
- `docs/roadmap.md`: Cross-Tool-Dedup + Parallelität von Tier 2 nach „Done" verschieben; Code-Lücken
  #1 und #2 als behoben markieren.

## 8. Risiken & Gegenmaßnahmen
- **Nichtdeterministische Coverage/Findings durch Threads** → index-basierte Einsammlung in
  Plan-Reihenfolge; Äquivalenz-Test `--jobs 1` vs `--jobs 0`.
- **Ressourcenspitzen** (semgrep+trivy parallel) → konservativer Default `--jobs 4`, drosselbar.
- **Übermäßige Dedup** (Fingerprint zu grob, kollabiert echte Distinct-Funde) → Fingerprint ist
  zeilenunabhängig by design (v1.4.0-Spec §4.2); `also_reported_by` macht Merges transparent;
  `--no-dedup` als Escape-Hatch.
