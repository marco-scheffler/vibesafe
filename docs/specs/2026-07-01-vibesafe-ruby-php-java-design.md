# vibesafe — Design-Spec: Ruby + PHP + Java Ökosysteme (v1.8.0)

- **Datum:** 2026-07-01
- **Status:** Genehmigt (Brainstorming abgeschlossen), bereit für Implementierungs-Planung
- **Basis:** `main` (v1.7.0). Branch `feat/ruby-php-java-ecosystems`.

## 1. Zweck

Erweitert vibesafe um **Ruby**, **PHP** und **Java** — je nach Verfügbarkeit eines geeigneten Tools
mit einem ökosystem-spezifischen SCA-Tool zusätzlich zur bestehenden generischen osv-Abdeckung.
Zusätzlich eine kleine **JS-Verfeinerung** (`npm audit` nur bei vorhandenem Lockfile). Schließt
Roadmap Tier 3 „Mehr Ökosysteme" und **Code-Lücke #3 vollständig** ab (Go/Rust waren v1.7.0).

## 2. Entscheidungen

| Thema | Entscheidung |
|---|---|
| Umfang | **Ruby + PHP + Java**; JS wird verfeinert (nicht neu, war schon abgedeckt) |
| Ruby-Tool | `bundler-audit` (`bundler-audit check --format json`) — nativ |
| PHP-Tool | `composer audit` (`composer audit --format=json`) — nativ, Job-Name `composer` |
| Java-Tool | **keins** — osv-scanner (läuft generisch) deckt `pom.xml`/`gradle.lockfile` ab |
| JS-Verfeinerung | `npm audit`-Job an `npm_lock` (package-lock/npm-shrinkwrap) statt an `node` binden |
| Java sichtbar machen | `summary["stack"]` = erkannte Ökosysteme + `**Detected:**`-Zeile im Markdown |
| Version | **1.8.0** |

## 3. Verifizierte Fakten (gegen Upstream-Quellcode/Doku)

- **bundler-audit** (rubysec/bundler-audit, `cli/formats/json.rb`): `check --format json` gibt
  `JSON.generate(report.to_h)` auf stdout aus, **keine** Custom-Serialisierung.
  `report.to_h` → `{version, created_at, results:[...]}`. Jedes `unpatched_gem`-Result:
  `{type:"unpatched_gem", gem:{name, version}, advisory:{...}}`. `advisory.to_h`-Keys:
  `path, id, url, title, date, description, cvss_v2, cvss_v3, cvss_v4, cve, osvdb, ghsa,
  unaffected_versions, patched_versions, criticality`. `patched_versions` sind
  `Gem::Requirement` → serialisieren via Default zu Versions-**Strings** (Array). `criticality`
  ∈ `none|low|medium|high|critical` (bzw. `null` ohne CVSS). `id` ist die kanonische Kennung
  (z. B. `"CVE-2021-22885"` / `"GHSA-…"`), `cve` die reine Nummer (`"2021-22885"`). Exit non-zero
  bei Funden, JSON trotzdem auf stdout → im bestehenden `_execute_job`-Pfad „ok". Braucht
  `Gemfile.lock`; ohne → non-zero + leerer stdout → `errored` (graceful). Nutzt gebündelte
  ruby-advisory-db (offline nutzbar).
- **composer audit** (Composer ≥ 2.4, `--format=json`): stdout-JSON
  `{advisories:{ "<pkg>":[{advisoryId, packageName, affectedVersions, title, cve, link,
  reportedAt, sources:[{name, remoteId}]}], …}, abandoned:{…}}`. **Kein einheitliches
  Severity-Feld** → Default `high` (wie pip-audit/cargo-audit). Braucht `composer.lock`; ohne →
  non-zero + Fehlermeldung auf stderr, leerer stdout → `errored` (graceful). Binary heißt
  `composer`, Subcommand `audit`.
- **Java:** osv-scanner unterstützt nativ `pom.xml` und `gradle.lockfile`; läuft bereits
  unbedingt in `_plan` (kein neuer Job nötig).

## 4. Detection

`detect_stack` (scan.py:292) ergänzt vier Schlüssel:
```python
"ruby": (path / "Gemfile.lock").exists() or has("Gemfile.lock", "Gemfile"),
"php": (path / "composer.json").exists() or has("composer.json", "composer.lock"),
"java": has("pom.xml", "build.gradle", "build.gradle.kts"),
"npm_lock": (any((path / f).exists() for f in ("package-lock.json", "npm-shrinkwrap.json"))
             or has("package-lock.json", "npm-shrinkwrap.json")),
```
`node` behält seine Semantik (JS-Projekt vorhanden). `npm_lock` ist ein interner Sub-Flag für
das npm-Job-Gating und erscheint **nicht** in der Detected-Anzeige.

## 5. Scanner-Integration

### 5.1 `_plan` — Job-Änderungen
```python
# JS-Verfeinerung: nur mit Lockfile (yarn/pnpm laufen über osv)
if stack["npm_lock"]:
    jobs.append(("npm", ["audit", "--json"], normalize_npm_audit))
...
if stack["ruby"]:
    jobs.append(("bundler-audit", ["check", "--format", "json"], normalize_bundler_audit))
if stack["php"]:
    jobs.append(("composer", ["audit", "--format=json"], normalize_composer_audit))
# Java: kein neuer Job — osv-scanner deckt pom.xml/gradle.lockfile generisch ab.
```
- Beide neuen Tools sind **nativ** (kein uvx/pipx) → `_NATIVE_ONLY += {"bundler-audit", "composer"}`.
- `bundler-audit` binär, cwd = target (braucht `Gemfile.lock`). `composer` binär, Subcommand `audit`.
- `resolve_runner(tool)` liefert `[tool]` wenn installiert, sonst `None` → `skipped` (graceful)
  mit Install-Hint.
- `CATEGORY_OF += {"bundler-audit": "deps", "composer": "deps"}` (für `--only deps`).
- `INSTALL_HINTS += {"bundler-audit": "gem install bundler-audit",
  "composer": "install Composer — https://getcomposer.org"}`.
- **Display-Name-Entkopplung** (wie `npm` → `npm-audit`): in `_execute_job` wird
  `name = "npm-audit" if tool == "npm" else tool` zu einer Map erweitert:
  `name = {"npm": "npm-audit", "composer": "composer-audit"}.get(tool, tool)`.
  So heißt der Job (und `resolve_runner`) `composer`, der Report/Coverage aber `composer-audit`.

### 5.2 `normalize_bundler_audit(raw)`
```python
_BUNDLER_SEV = {"critical": "critical", "high": "high", "medium": "medium",
                "low": "low", "none": "info"}

def normalize_bundler_audit(raw) -> list:
    out = []
    for r in raw.get("results") or []:
        if r.get("type") != "unpatched_gem":
            continue
        gem = r.get("gem") or {}
        adv = r.get("advisory") or {}
        patched = ", ".join(str(x) for x in (adv.get("patched_versions") or [])) or "a patched version"
        cve_num = adv.get("cve")
        aliases = [adv.get("id"), (f"CVE-{cve_num}" if cve_num else None)]
        out.append(Finding(
            tool="bundler-audit", category="deps",
            severity=_BUNDLER_SEV.get(str(adv.get("criticality") or "").lower(), "high"),
            title=adv.get("title") or f"Vulnerable dependency: {gem.get('name')}",
            package=gem.get("name"), cve=_first_cve(aliases, adv.get("id")),
            rule_id=adv.get("id"), file="Gemfile.lock",
            remediation=f"Upgrade {gem.get('name')} to {patched}."))
    return out
```
Nicht-`unpatched_gem`-Results (`insecure_source`) werden übersprungen (kein gem/advisory).

### 5.3 `normalize_composer_audit(raw)`
```python
def normalize_composer_audit(raw) -> list:
    out = []
    for pkg_name, advisories in (raw.get("advisories") or {}).items():
        for adv in advisories or []:
            name = adv.get("packageName") or pkg_name
            affected = adv.get("affectedVersions")
            rem = (f"Upgrade {name} beyond the affected range ({affected})."
                   if affected else f"Upgrade {name} to a patched version.")
            out.append(Finding(
                tool="composer-audit", category="deps", severity="high",  # composer omits severity
                title=adv.get("title") or f"Vulnerable dependency: {name}",
                package=name,
                cve=_first_cve([adv.get("cve"), adv.get("advisoryId")], adv.get("advisoryId")),
                rule_id=adv.get("advisoryId"), file="composer.lock",
                remediation=rem))
    return out
```

## 6. Report-Sichtbarkeit (`summary["stack"]`)

- `build_report(...)` bekommt einen neuen Keyword-Parameter `stack=None` (Default → kein Bruch
  bestehender Aufrufer/Tests). `summary["stack"]` = übergebene Liste oder `[]`.
- `main()` berechnet `detected = sorted(k for k, v in stack.items() if v and k not in ("git", "npm_lock"))`
  und übergibt `stack=detected`.
- `render_markdown`: wenn `s.get("stack")`, eine Zeile `**Detected:** node, java, …` (vor/bei der
  Coverage-Zeile). Rein informativ; gibt v. a. der Java-Detection einen sichtbaren Effekt.

## 7. Dedup-Interaktion

`bundler-audit`/`composer-audit` liefern `category=deps`. Der bestehende `dedupe_key`
(`category|cve/rule_id|package|file|line`) merged Überlappungen mit osv, wenn dieselbe CVE +
Package + Datei matchen. Advisory-IDs (RUSTSEC/GHSA/PKSA vs. CVE) differieren teils → kein Merge;
`also_reported_by` macht Mehrfachquellen sichtbar. Akzeptiert (keine ID-Alias-Auflösung).

## 8. Diff-/Staged-Scan

`_MANIFESTS += {"pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"}`, damit
Java-Dep-Findings (die osv fileweise oder als Manifest-Treffer liefert) bei `--diff`/`--staged`
erhalten bleiben. `Gemfile.lock`/`composer.lock` sind bereits enthalten.

## 9. Tests (hermetisch)

- `detect_stack`: `Gemfile.lock` → `ruby`; `composer.json` → `php`; `pom.xml` → `java`;
  `package-lock.json` → `npm_lock`; leeres Verzeichnis → alle False.
- `normalize_bundler_audit`: Fixture `tests/fixtures/raw/bundler-audit.json` (dokumentiertes
  Schema aus §3) → Finding(deps, bundler-audit, package, cve, file=`Gemfile.lock`, severity aus
  `criticality`, remediation enthält patched-Version). `insecure_source`-Result wird ignoriert.
- `normalize_composer_audit`: Fixture `tests/fixtures/raw/composer-audit.json` → Finding(deps,
  composer-audit, package aus `packageName`, cve, file=`composer.lock`, remediation enthält
  `affectedVersions`).
- `_plan`: `stack["ruby"]` → `bundler-audit`; `stack["php"]` → `composer`; `npm` nur bei
  `stack["npm_lock"]` (nicht bei nur `node`); `--only deps` behält alle. Java erzeugt keinen
  neuen Job.
- `summary["stack"]`: `main()` auf einem Verzeichnis mit `pom.xml` → `"java"` in
  `report.json.summary.stack`; `npm_lock`/`git` **nicht** in der Liste.
- Graceful: fehlendes Tool → `skipped` mit Install-Hint (deckt der bestehende Pfad ab).
- Bestehende Plan-Tests (`TestPlanGoRust` u. a.) bekommen die neuen Stack-Keys in ihren
  synthetischen `base`-Dicts, da `_plan` direkt indiziert.

## 10. Docs / Version

- `references/tools.md`: Scanner-Matrix += Ruby (`bundler-audit`) / PHP (`composer audit`) /
  Java (osv-scanner) Zeilen; Datenquellen (RubySec-DB, Packagist-Advisories) im Privacy-Teil.
- `CHANGELOG.md`: `1.8.0`. Version-Bump 1.7.0 → 1.8.0 (`plugin.json`, `marketplace.json`,
  README-Badge).
- `docs/roadmap.md`: Tier 3 „Mehr Ökosysteme" — Ruby/PHP/Java erledigt; **Code-Lücke #3
  vollständig behoben**.

## 11. Risiken

- **bundler-audit / composer audit JSON** gegen Upstream-Quellcode bzw. Doku verifiziert (§3),
  aber lokal nicht ausführbar → Normalizer defensiv (`.get()` überall), Fixtures nach
  dokumentiertem Schema; bei Feld-Drift kein Crash (leere Liste). Spätere Live-Detection fängt
  Abweichungen.
- **Lockfile-Abhängigkeit:** bundler-audit ohne `Gemfile.lock` / composer ohne `composer.lock`
  → `errored` (graceful); osv deckt die Manifeste weiter ab. Kein Merge-/Exit-Gate am Live-Job.
- **JS-Verfeinerung** ist eine bewusste Verhaltensänderung: reine yarn/pnpm-Projekte planen
  `npm audit` nicht mehr ein (statt es erroren zu lassen); osv-Abdeckung bleibt. Für
  package-lock-Projekte unverändert.
- **Keine lokalen Live-Fixtures** (Tools nicht installiert) → Unit-Tests über erfasste
  Roh-Fixtures, wie die bestehenden Normalizer.
