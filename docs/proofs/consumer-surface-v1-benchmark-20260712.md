# Consumer Surface v1 – Wirkungsnachweis

Stand: 2026-07-12

## Ergebnis

Der Standardmodus unterschreitet die früher gemessene JSON-Größe auf allen fünf Oberflächen um mindestens 50 Prozent.

| Oberfläche | Vorher | Standard Median | Reduktion | Median Laufzeit | P90 Laufzeit |
|---|---:|---:|---:|---:|---:|
| status | 7579 B | 2760 B | 63.58 % | 73.507 ms | 73.553 ms |
| context | 37597 B | 5860 B | 84.41 % | 20.057 ms | 20.112 ms |
| checkout | 11458 B | 4816 B | 57.97 % | 11.943 ms | 11.960 ms |
| tasks | 113239 B | 52370 B | 53.75 % | 8.487 ms | 8.537 ms |
| friction | 60842 B | 29216 B | 51.98 % | 37.385 ms | 37.392 ms |

Abnahme: **PASS**.

## Datenumfang

- Checkout: 20 von 59 Worktrees, Limit 20.
- Tasks: 20 von 1349 Treffern, Limit 20.
- Friction: 50 Einträge, Limit 50, weitere vorhanden: true.
- Context: Profil `concise`.
- Pro Fall fünf Stichproben; ausgewiesen sind Median und P90.

## Sicherheits- und Vollständigkeitsgrenze

- Pflichtwarnungen, empfohlene nächste Aktion und Nichtaussagen bleiben auch bei Feldprojektion erhalten.
- Cursor sind an Sicht, Filter und Snapshot gebunden; Mehrseitenläufe sind ohne Duplikate oder Lücken getestet.
- Der Evidence-Modus behält vollständige Klassifikation, Proposals, Protokolle und Auditformen.

## Nicht belegt

- JSON-Bytes sind keine Modell-Token.
- Lokale Laufzeit ist keine Connector-Zuverlässigkeit.
- Die statischen Vorherwerte und der heutige Livebestand sind kein simultaner A/B-Versuch.
- Größen- und Laufzeitmessung beweisen nicht allein die Workflow-Korrektheit.

Maschinenlesbarer Beleg: `docs/proofs/consumer-surface-v1-benchmark-20260712.json`.
