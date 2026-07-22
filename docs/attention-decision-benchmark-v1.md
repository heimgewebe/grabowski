# Attention Decision Lookup Benchmark V1

## Zweck

Dieser Benchmark misst den belegten Skalierungs-Hotspot der decision-aware Attention-Projektion: vollständige Verzeichnisiteration, lexikographische Sortierung, Dateinamensklassifikation und Attempt-Matching. Er ändert weder Task-Historie noch Decision-Evidenz.

## Entscheidungsschwellen

Ein persistenter oder rebuildbarer Index wird erst empfohlen, wenn mindestens eine reproduzierbare Schwelle überschritten wird:

- p95 bei 10.000 Decision-Dateien: mehr als 250 ms;
- p95 bei 50.000 Decision-Dateien: mehr als 1.000 ms.

Die Schwellen beziehen sich bewusst nur auf den Lookup-Hotspot. Ein späterer Index muss weiterhin create-only Decision-Dateien als Primär-Evidenz behandeln, vollständig rebuildbar sein und Drift-, Crash- und Recovery-Tests besitzen.

## Modi

`tools/benchmark_attention_decisions.py` erzeugt standardmäßig synthetische Verzeichnisse mit 100, 1.000, 10.000 und 50.000 gültigen Decision-Dateinamen und gibt Median, p95 und Maximum als JSON aus. Mit `--live-root` und `--live-task-db` kann zusätzlich ein existierender Decision-Store gegen die aktuellen Attempts aus der Task-SQLite-Datenbank gemessen werden. Die Datenbank wird im SQLite-Read-only-Modus geöffnet; ein fehlender Live-Store wird nicht angelegt.

## Interpretation

`index_promotion.recommended=false` bedeutet nicht, dass ein Index nie sinnvoll wird. Es bedeutet nur, dass die aktuell definierten Skalierungsgrenzen nicht belegt überschritten wurden. Erst eine reproduzierbare Überschreitung rechtfertigt den zusätzlichen Persistenz-, Rebuild- und Recovery-Aufwand.

## Referenzmessung vom 22. Juli 2026

Auf `heim-pc` mit sieben Iterationen ergab der Benchmark:

- 10.000 Decision-Dateien: p95 17,712 ms;
- 50.000 Decision-Dateien: p95 102,161 ms;
- Live-Store: drei Verzeichniseinträge, zwei an aktuelle Task-Attempts gebundene Decision-Kandidaten, p95 0,046 ms.

Ergebnis: `index_promotion.recommended=false`. Gegenüber den Promotionsschwellen besteht derzeit ausreichend Reserve; eine zusätzliche SQLite-Projektion oder ein Cache wird deshalb nicht eingeführt.
