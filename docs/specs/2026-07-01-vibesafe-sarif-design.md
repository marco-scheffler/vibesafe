# vibesafe — Design-Spec: SARIF-Output + Code-Scanning-Upload (v1.6.0)

- **Datum:** 2026-07-01
- **Status:** Genehmigt (Brainstorming abgeschlossen), bereit für Implementierungs-Planung
- **Autor:** Marco Scheffler
- **Basis:** `main` (v1.5.0). Eigener Branch `feat/sarif-output`, kein Stacking.

## 1. Zweck

vibesafe soll seine normalisierten Findings als **SARIF 2.1.0** ausgeben, damit GitHub
**Code-Scanning** sie inline im PR-„Security"-Tab / als Annotationen anzeigen kann. Roadmap Tier 2.

## 2. Verifizierte Fakten (offizielle GitHub-Docs, 2026-07-01)

- Top-Level `sarifLog`: `$schema` (`https://json.schemastore.org/sarif-2.1.0.json`), `version` =
  `"2.1.0"`, `runs[]`.
- `runs[].tool.driver`: `name` (Pflicht), `rules[]` (reportingDescriptor). Jede Rule braucht `id`,
  `shortDescription.text`, `fullDescription.text`, `help.text`.
- `results[]`: **`message.text`** und **≥1 `locations[]`** sind für die Anzeige nötig. `ruleId` und
  `level` sind laut Tabelle optional (wir setzen beide). `level` ∈ `note | warning | error`.
- `location.physicalLocation`: `artifactLocation.uri` (relativ zum Repo-Root), `region.startLine`
  (+ `startColumn` etc.). Ein Result **ohne** Location wird akzeptiert, aber nicht am Code angezeigt.
- **`partialFingerprints`**: die Upload-Action **berechnet sie selbst**, wenn sie fehlen → wir
  lassen sie weg (kein Source-Line-Hashing im Scanner nötig).
- Upload: **`github/codeql-action/upload-sarif@v4`**, Input **`sarif_file`**, optional `category`;
  Job-Permission **`security-events: write`** (+ `actions: read`/`contents: read` für private Repos).
- Limits (unkritisch): 10 MB gzip/Datei, 20 runs/Datei, 25k results/run.

## 3. Getroffene Entscheidungen

| Thema | Entscheidung |
|---|---|
| SARIF-Ausgabe | **Immer** `report.sarif` neben `report.json`/`report.md` |
| Run-Struktur | **Ein `runs[]`-Eintrag pro Tool** |
| Action-Upload | **Opt-in Input `upload-sarif`** (Default `false`) → `upload-sarif@v4` |
| Version | **1.6.0** |

## 4. SARIF-Erzeugung in `scan.py`

### 4.1 `build_sarif(rep) -> dict`
Reine Funktion (wie `render_markdown`), Eingabe = das fertige `rep` (dessen `findings` bereits final,
d. h. nach Dedup/Diff/Ignore/Baseline). Ablauf:

1. Findings nach `tool` gruppieren (First-Seen-Reihenfolge → deterministisch).
2. Pro Tool ein `run`:
   - `tool.driver.name = <tool>`, `tool.driver.informationUri = "https://github.com/marco-scheffler/vibesafe"`.
   - `tool.driver.rules`: pro **distinktem `ruleId`** dieses Tools ein reportingDescriptor
     `{ id, shortDescription:{text}, fullDescription:{text}, help:{text} }`. Texte aus einem
     repräsentativen Finding dieses `ruleId` (siehe 4.3).
   - `results`: ein Result je Finding (4.2).
3. Top-Level: `{ "$schema": "...sarif-2.1.0.json", "version": "2.1.0", "runs": [...] }`.

### 4.2 Finding → SARIF-Result
- `ruleId` = `rule_id` ∣ `cve` ∣ `f"{category}/{tool}"` (Fallback, stabil).
- `level` = `_SARIF_LEVEL[severity]`: critical→`error`, high→`error`, medium→`warning`,
  low→`note`, info→`note`.
- `message.text` = Titel (inkl. `(also: …)`, wenn `also_reported_by` gesetzt — konsistent zum MD).
- `locations`: wenn `file` gesetzt →
  `[{ "physicalLocation": { "artifactLocation": {"uri": <file>}, "region": {"startLine": <line|1>, "startColumn": 1} } }]`.
  Wenn `file` fehlt → **kein `locations`** (Result gültig, nur nicht am Code verankert).
- `properties` = `{ category, severity, tool, cve, package, committed, also_reported_by }`
  (nur gesetzte Felder).

### 4.3 Rule-Deskriptoren
Für jeden distinkten `ruleId` eines Tools:
- `id` = ruleId.
- `shortDescription.text` = Titel des ersten Findings mit diesem ruleId (auf 120 Zeichen gekürzt).
- `fullDescription.text` = derselbe Titel (voll) bzw. `category`-Kontext.
- `help.text` = `remediation` des Findings (Fallback: `"See references/remediation.md."`).

### 4.4 Einbindung
- In `main()` nach `build_report(...)`: zusätzlich `(out_dir / "report.sarif").write_text(json.dumps(build_sarif(rep), indent=2))`.
- Pfad wird wie json/md in der Abschlusszeile mit ausgegeben.
- Kein neues CLI-Flag (immer erzeugt). Änderungen an bestehendem Verhalten: nur eine zusätzliche Datei.

## 5. GitHub-Action-Upload

`action.yml` erhält:
- Input **`upload-sarif`** (Default `"false"`).
- Nach dem Scan-Schritt ein bedingter Schritt (`if: inputs.upload-sarif == 'true'`):
  `uses: github/codeql-action/upload-sarif@v4` mit `sarif_file: ${{ runner.temp }}/vibesafe/report.sarif`.
- Der Scan-Schritt schreibt weiterhin nach `$RUNNER_TEMP/vibesafe` (report.json/md/sarif).
- Doku: der Aufrufer-Job braucht `permissions: security-events: write` und muss das Repo
  ausgecheckt haben (`actions/checkout`), damit die Fingerprint-Berechnung/Anzeige greift.

## 6. Docs / Version / Tests

- `references/automation.md`: neue Sektion „SARIF & code scanning" — `report.sarif` wird immer
  geschrieben; Beispiel-Workflow mit `upload-sarif: true` + `permissions: security-events: write`.
- `SKILL.md`: kurzer Hinweis, dass zusätzlich `report.sarif` entsteht (für CI/Code-Scanning).
- `CHANGELOG.md`: Eintrag `1.6.0`. Version-Bump 1.6.0 (`plugin.json`, `marketplace.json`, README-Badge).
- `docs/roadmap.md`: SARIF von Tier 2 → „Done".
- **Tests (hermetisch)** in `tests/test_scan.py`:
  - Top-Level: `version == "2.1.0"`, `$schema` vorhanden.
  - **Ein Run pro Tool**: zwei Findings von `gitleaks`/`semgrep` → zwei runs; ein weiteres
    `gitleaks`-Finding erhöht die run-Zahl nicht.
  - Level-Mapping (critical→error, medium→warning, low→note).
  - Location: mit `file` → `physicalLocation.artifactLocation.uri` + `region.startLine`; ohne `file`
    → kein `locations`-Schlüssel.
  - Rule-Deskriptor: `id`/`shortDescription.text`/`fullDescription.text`/`help.text` vorhanden.
  - `properties` trägt `category`/`severity`/`tool`.
  - `main()` schreibt `report.sarif` und es ist valides JSON mit `runs`.

## 7. Risiken & Gegenmaßnahmen
- **`sarif_file` als absoluter Pfad** (`$RUNNER_TEMP/...`) — falls die Action nur Repo-relative
  Pfade akzeptiert, alternativ `--out-dir "$GITHUB_WORKSPACE/.vibesafe"` schreiben und
  `sarif_file: .vibesafe/report.sarif` nutzen. Beim Action-Test verifizieren.
- **Datei-lose Dep-Findings** ohne Location werden nicht am Code angezeigt (nur in der Alert-Liste).
  Akzeptiert; die meisten Dep-Findings (osv/trivy) haben nach der v1.5.0-Pfad-Normalisierung eine
  Location (`package-lock.json`).
- **`uri` relativ zum Repo-Root**: gilt sauber, wenn das Ziel = Repo-Root ist (der CI-Normalfall
  `scan .`). Subdir-Scans können abweichen — dokumentiert.
