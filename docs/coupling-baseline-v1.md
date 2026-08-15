# Grabowski Coupling Baseline v1

## Zweck

`tools/coupling_baseline.py` erzeugt eine revisionsgebundene, read-only Architektur-Baseline. Die Baseline entscheidet **nicht**, welcher Seam als Nächstes geschnitten wird. Sie macht die bisherige Vermutung „Resources vor Tasks“ falsifizierbar.

Der Analyzer ist stdlib-only, mutiert weder Runtime noch StateStore und fügt kein MCP- oder öffentliches Tool hinzu.

## Gemessene Größen

Die Baseline bindet sich an den exakten Git-HEAD und erfasst:

- statische Python-Importkanten zwischen `src/grabowski*.py`;
- Fan-in und Fan-out;
- Strongly Connected Components (Tarjan);
- Module, die mindestens drei klassifizierte Autoritätsdomänen importieren;
- Funktionen, die importierte Projektmodule aus mindestens zwei Autoritätsdomänen referenzieren;
- Git-Co-Change über einen begrenzten Commit-Horizont;
- statische Testkopplung aus `tests/test_*.py`.

Die Autoritätsdomänen sind nur ein **Messklassifikator**. Sie verleihen keine Autorität und definieren keine neue Modularchitektur.

## Bewusste Nichtbehauptungen

### Reverse Imports

Ein „Reverse Import“ setzt eine gewünschte Schichtenrichtung voraus. Diese Richtung ist gerade Gegenstand von P5–P7. v1 emittiert deshalb alle gerichteten Importkanten, klassifiziert aber ohne kanonischen Layer-Vertrag keine davon als falsch.

**Fehlt:** kanonischer Layer-Vertrag.
**Nötig für:** ein hartes automatisches Gate „kein neuer Reverse Import“.

### Runtime-Fehler und Stack-Häufigkeit

Repositoryzustand ist keine Runtime-Telemetrie. v1 erfindet deshalb keine Produktionshäufigkeiten.

**Fehlt:** revisions- und zeitgebundener Log-/Runtime-Evidenzkorpus.
**Nötig für:** Priorisierung von Seams nach realer Fehlerhäufigkeit.

Diese Lücken werden maschinenlesbar in `evidence_gaps` ausgegeben.

## Reproduzierbarer Lauf

```text
python3 tools/coupling_baseline.py --repo . --max-commits 500
```

Optional kann das kanonische JSON mit `--output <path>` geschrieben werden. `report_sha256` bindet den vollständigen Reportinhalt, ausgenommen das Digestfeld selbst.

## Merge- und Folgeentscheidungen

Die Baseline ist kein willkürliches Prozent-Gate. Ein späterer Seam-PR soll mindestens folgende qualitative Invarianten erfüllen:

1. keine neue Import-SCC;
2. kein neuer Reverse Import, sobald ein Layer-Vertrag existiert;
3. mindestens eine konkret benannte unerwünschte Abhängigkeit verschwindet;
4. keine neue Autoritätsquelle;
5. keine neue Mutation;
6. öffentliche Verträge bleiben stabil oder werden explizit versioniert.

Die P5/P6-Reihenfolge wird erst aus der Baseline plus realer Runtime-Evidenz entschieden. Eine große SCC allein beweist nicht, dass ihr größtes Modul zuerst extrahiert werden sollte.
