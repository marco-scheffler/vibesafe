# vibesafe — Design-Spec: Automation & Adoption (v1.4.0)

- **Datum:** 2026-07-01
- **Status:** Genehmigt (Brainstorming abgeschlossen), bereit für Implementierungs-Planung
- **Autor:** Marco Scheffler
- **Vorgänger-Spec:** `docs/specs/2026-06-13-vibesafe-skill-design.md` (v1)

## 1. Zweck

vibesafe v1 (siehe Vorgänger-Spec) liefert einen normalisierten Multi-Scanner-Report und
proaktive Guidance. Diese Erweiterung macht vibesafe von „ein Skill, den man fragt" zu „ein
Werkzeug, das sich automatisieren lässt und auf echten Bestandsprojekten nutzbar ist". Drei
Themen (die vom Nutzer priorisierten „TOP 3"):

1. **CI mit echtem Detection-Nachweis** — Tests laufen automatisiert; ein separater Job weist
   nach, dass die Scanner die gepflanzten Fixture-Findings tatsächlich erkennen.
2. **CI-/pre-commit-Fähigkeit** — Severity-abhängige Exit-Codes (`--fail-on`), eine
   wiederverwendbare GitHub Action und ein pre-commit-Hook.
3. **Nutzbarkeit auf Bestandscode** — Fingerprint-Baseline + `.vibesafeignore` (nur *neue*
   Findings zeigen / False Positives dauerhaft unterdrücken) und ein Diff-/Staged-Scan.

## 2. Ziele / Nicht-Ziele

**Ziele**
- Rückwärtskompatibilität: bestehendes CLI-Verhalten ändert sich nicht ohne neue Flags.
- Alle neuen `scan.py`-Funktionen test-getrieben (hermetisch, ohne installierte Scanner).
- Ein CI-Job, der Detection real beweist (Normalizer-Drift-Schutz).
- Progressive Disclosure bleibt gewahrt: SKILL.md schlank, Details in `references/`.

**Nicht-Ziele (dieser Iteration)**
- Cross-Tool-Deduplizierung (Fingerprint wird eingeführt, Dedup selbst ist Backlog Tier 2).
- SARIF-Output, Parallel-Ausführung, weitere Ökosysteme, eigene semgrep-Regeln, SBOM,
  `--offline`, Subagent, Config-Datei, Hooks → alle in `docs/roadmap.md`.
- Windows-Support (weiterhin macOS/Linux).

## 3. Getroffene Entscheidungen

| Thema | Entscheidung |
|---|---|
| Baseline | **Beides** — Fingerprint-Baseline (`vibesafe-baseline.json`) **und** `.vibesafeignore` |
| Exit-Codes | **Opt-in** — Default bleibt Exit 0; Gating nur mit `--fail-on <sev>` |
| Diff-Scan | **Post-Filter** — volle Scanner, danach Filter auf geänderte Dateien |
| Spec-Sprache | Deutsch (wie Vorgänger-Spec); SKILL.md/references bleiben Englisch |
| Spec-/Plan-Pfad | Repo-Konvention `docs/specs/` bzw. `docs/plans/` (nicht der Skill-Default) |
| Version | **1.4.0** (Features → Minor-Bump) |

## 4. `scan.py` — neue CLI-Oberfläche

```
scan.py [PATH]
        [--only secrets,deps,sast,iac,license]
        [--out-dir DIR] [--timeout 120] [--no-install-hints]     # bestehend
        [--fail-on {critical,high,medium,low,info}]               # NEU: Gating-Schwelle
        [--fail-on-error]                                         # NEU: auch bei Scanner-Fehlern failen
        [--baseline FILE]                                         # NEU: bekannte Fingerprints ausblenden
        [--update-baseline [FILE]]                               # NEU: Baseline schreiben und beenden
        [--staged]                                                # NEU: nur git-staged Dateien
        [--diff REF]                                              # NEU: nur seit REF geänderte Dateien
        [--ignore-file FILE]                                      # NEU: Pfad zu .vibesafeignore (Default: <target>/.vibesafeignore)
```

### 4.1 Exit-Codes

Konstanten in `scan.py`:

- `EXIT_OK = 0` — Lauf erfolgreich; kein Gating ausgelöst.
- `EXIT_FINDINGS = 1` — `--fail-on` gesetzt und ≥1 **gezeigtes** Finding auf/über der Schwelle.
- `EXIT_TOOL_ERROR = 3` — `--fail-on-error` gesetzt und ≥1 Scanner `errored`/`timeout`, **und**
  kein Policy-Fail (Policy-Fail hat Vorrang → dann `EXIT_FINDINGS`).
- `2` bleibt argparse-Usage-Fehlern vorbehalten (Default-Verhalten).

Ohne `--fail-on` und ohne `--fail-on-error` ist der Exit **immer 0** (rückwärtskompatibel).
Das Gating wertet die **final gezeigten** Findings aus (nach Diff/Ignore/Baseline, §4.5).

### 4.2 Fingerprint

Neues Feld `fingerprint: str` an `Finding` (und im `report.json` je Finding). Berechnung:

```
fingerprint = sha1( "|".join([
    category,
    rule_id or cve or "",
    package or "",
    file or "",
    normalized_title,          # title.strip().lower(), auf 200 Zeichen gekürzt wie schon im Normalizer
]) ).hexdigest()[:16]
```

**Bewusst ohne `line`** — Edits oberhalb eines Fundes sollen die Baseline nicht invalidieren.
Konsequenz: zwei ansonsten identische Funde in derselben Datei kollabieren auf denselben
Fingerprint (akzeptiert; wird in `references/automation.md` dokumentiert). Der Fingerprint ist
tool-unabhängig genug, um später (Backlog) Cross-Tool-Dedup zu tragen.

### 4.3 Baseline

- `--baseline FILE`: lädt `{"fingerprints": ["…", …]}` (unbekanntes/fehlendes File → leer, kein
  Fehler). Findings, deren Fingerprint enthalten ist, werden aus dem Report entfernt.
  `summary.baselined` = Anzahl entfernter Findings.
- `--update-baseline [FILE]`: nach dem Scan werden **alle aktuellen** Fingerprints nach FILE
  geschrieben (Default `vibesafe-baseline.json` im CWD), Format
  `{"generated_from": "<target>", "count": N, "fingerprints": [...]}`. Danach Exit `EXIT_OK`
  **ohne** Gating (Baseline-Erzeugung soll nie failen). `--update-baseline` und `--baseline`
  schließen sich gegenseitig aus (Usage-Fehler, wenn beide gesetzt).

### 4.4 `.vibesafeignore`

- Default-Pfad `<target>/.vibesafeignore`; überschreibbar via `--ignore-file`.
- Zeilenformat (Leerzeilen und `#`-Kommentare ignoriert):
  - `path:<glob>` — unterdrückt Findings, deren `file` (relativ zum Target) den Glob matcht.
  - `rule:<rule_id>` — unterdrückt per exakter `rule_id`.
  - `cve:<id>` — unterdrückt per exakter `cve` (case-insensitive).
  - `<glob>` (ohne Präfix) — wie `path:<glob>` (Ergonomie à la `.gitignore`).
- Glob-Matching via `fnmatch` gegen den *posix-relativen* Pfad des Findings. `summary.ignored` =
  Anzahl unterdrückter Findings.

### 4.5 Diff-/Staged-Scan (Post-Filter)

- `--staged`: geänderte Dateien = `git diff --cached --name-only` (relativ zum Repo-Root).
- `--diff REF`: geänderte Dateien = `git diff --name-only REF` (Arbeitsbaum gegen REF).
- Beide schließen sich gegenseitig aus. Kein Git-Repo / Git-Fehler → klare Meldung, Exit `EXIT_OK`
  mit leerem Ergebnis (nichts zu diffen).
- **Filterregel:** ein Finding bleibt, wenn sein `file` (posix-relativ zum Target aufgelöst) in der
  Änderungsmenge liegt. **Datei-lose** Findings (`file is None`, z. B. `npm audit`) bleiben **nur**,
  wenn mindestens ein **Dependency-Manifest/Lockfile** in der Änderungsmenge ist:
  `package.json, package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml,
  requirements*.txt, pyproject.toml, Pipfile, Pipfile.lock, poetry.lock, go.mod, go.sum,
  Cargo.lock, composer.lock, Gemfile.lock`.
- `summary.scope` ∈ `full | staged | diff:<ref>`; `summary.changed_files` = Anzahl.

### 4.6 Reihenfolge der Nachbearbeitung (verbindlich)

1. Scanner ausführen → rohe Findings.
2. `annotate_committed`.
3. **Fingerprint** je Finding berechnen.
4. **Diff/Staged**-Post-Filter (falls `--staged`/`--diff`).
5. **`.vibesafeignore`**-Suppression.
6. **`--baseline`**-Suppression.
7. `build_report` (Counts spiegeln die **gezeigten** Findings; plus `scope`, `changed_files`,
   `ignored`, `baselined`).
8. `--update-baseline`? → Fingerprints schreiben, Exit `EXIT_OK`.
9. `--fail-on` / `--fail-on-error` auswerten → Exit-Code (§4.1).

## 5. GitHub Actions CI

`.github/workflows/ci.yml`, Trigger `push` (main) + `pull_request`:

- **Job `test`** (hermetisch, schnell): Matrix Python `3.8`, `3.11`, `3.12` auf `ubuntu-latest`;
  Schritt: `VIBESAFE_NO_EPHEMERAL=1 python -m unittest discover -s tests -v`.
- **Job `live-detection`** (`ubuntu-latest`, single Python): installiert die echten Scanner
  (gitleaks + trivy + osv-scanner via ihre offiziellen Install-Wege, semgrep via `pipx`/`uvx`),
  dann `VIBESAFE_LIVE=1 python -m unittest tests.test_live_detection -v`. Netzwerk erlaubt
  (trivy-DB, osv-API, semgrep-Regeln). Nicht in der PR-Merge-Gate-Pflicht, falls flaky — aber
  sichtbar.

### 5.1 `tests/test_live_detection.py`

- Übersprungen, wenn `VIBESAFE_LIVE` **nicht** gesetzt ist (`unittest.skipUnless`).
- Läuft `scan.main([...])` gegen `tests/fixtures/vulnerable-app`, liest `report.json`, prüft:
  - je Kategorie ≥1 Finding: `secrets` (config.js-Key), `sast` (app.py), `deps` (lodash),
    `iac` (Dockerfile) — **tolerant** (Kategorien, keine exakten Rule-IDs, die driften).
  - der gepflanzte Secret-Wert taucht **nirgends** im Report auf (Redaction-Invariante).
  - Coverage-Line listet die gelaufenen Scanner.

## 6. GitHub Action (`action.yml`)

Composite Action im Repo-Root:

- **Inputs:** `path` (Default `.`), `fail-on` (Default `''` = kein Gating), `only`, `timeout`.
- **Steps:** Python bereitstellen → Scanner installieren → `python "$GITHUB_ACTION_PATH/scripts/scan.py"
  "$path" --out-dir "$RUNNER_TEMP/vibesafe" [--fail-on …] [--only …] [--timeout …]` →
  `report.json`/`report.md` als Artefakt hochladen. `scan.py` selbst liefert den Gating-Exit.
- Referenziert das gebündelte `scripts/scan.py` über `$GITHUB_ACTION_PATH` (Action ist im selben
  Repo; funktioniert via `uses: marco-scheffler/vibesafe@v1.4.0`).

## 7. pre-commit (`.pre-commit-hooks.yaml`)

```yaml
- id: vibesafe
  name: vibesafe security scan (staged)
  entry: python3 scripts/scan.py --staged --fail-on high
  language: system
  pass_filenames: false
  always_run: true
```

`language: system` (stdlib-only Skript; die externen Scanner müssen auf dem Host im PATH sein —
in `references/automation.md` dokumentiert). `--staged` hält den Hook schnell; `--fail-on high`
blockt Commits ab High.

## 8. Doku & Housekeeping

- **Neu** `references/automation.md`: CI, GitHub Action, pre-commit, Exit-Codes, Baseline/Ignore,
  Diff-Scan (inkl. Fingerprint-Trade-off). Hält SKILL.md schlank.
- **SKILL.md**: Mode-2-Ergänzung um die neuen Flags + Hinweis auf `references/automation.md`.
- **README.md**: CI-Badge, Abschnitt „Automate it (CI / pre-commit)", Version 1.4.0.
- **`references/tools.md`**: kurzer Verweis auf Exit-Codes/Baseline.
- **`CHANGELOG.md`** (neu): Eintrag `1.4.0`.
- **Version-Bump 1.4.0**: `plugin.json`, `.claude-plugin/marketplace.json`, README-Badge.
- **`docs/roadmap.md`** (neu): Tier 2–4 + zurückgestellte Optionen inkl. konkreter Code-Lücken.

## 9. Tests (TDD, hermetisch)

Neue Unit-Tests in `tests/test_scan.py` (oder Modul `tests/test_automation.py`):

- **Fingerprint**: Stabilität (gleiche Semantik → gleicher Fingerprint), Zeilen-Unabhängigkeit
  (unterschiedliche `line` → gleicher Fingerprint), unterschiedliche Kategorie/Rule → verschieden.
- **Baseline**: `--baseline` blendet passende Fingerprints aus; `summary.baselined` korrekt;
  fehlendes File → keine Ausnahme.
- **`.vibesafeignore`**: Parsing der drei Präfixe + bare Glob; Suppression korrekt; `summary.ignored`.
- **Diff/Staged**: Auflösung der Änderungsmenge (mit gemocktem `git`-Output), Post-Filter inkl.
  Datei-lose-Dep-Regel (Manifest geändert → behalten, sonst weg).
- **`--fail-on`**: Exit-Logik für alle Schwellen; `--fail-on-error`; Vorrang Policy vor Tool-Fehler;
  Default (ohne Flags) → 0.

Alle hermetisch (reine Funktionen bzw. `main()` mit injizierten Findings / gemocktem Plan; keine
echten Scanner nötig). Live-Detection separat (§5.1), nur unter `VIBESAFE_LIVE=1`.

## 10. Risiken & Gegenmaßnahmen

- **Live-Job flaky** (Netz/DB) → nicht Merge-Gate-Pflicht; Kategorien statt Rule-IDs prüfen.
- **Baseline-Fingerprint zu grob/fein** → Zeilen-Ausschluss dokumentiert; Feld im Report sichtbar,
  damit nachvollziehbar.
- **Diff-Datei-lose-Dep-Heuristik** unvollständig → Manifest-Liste zentral gepflegt, im Report via
  `scope` transparent.
- **Exit-Code-Bruch** → Default ohne neue Flags bleibt 0 (durch Tests abgesichert).
```
