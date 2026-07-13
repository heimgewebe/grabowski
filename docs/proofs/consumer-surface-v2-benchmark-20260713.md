# Consumer Surface v2 – Wirkungsnachweis

Stand: 2026-07-13

## Ergebnis

Der Standardmodus unterschreitet die historischen Vorherwerte weiterhin auf allen fünf großen Oberflächen um mindestens 50 Prozent.

| Oberfläche | Vorher | Standard Median | Reduktion | Median Laufzeit | P90 Laufzeit |
|---|---:|---:|---:|---:|---:|
| status | 7579 B | 2781 B | 63.31 % | 74.559 ms | 74.760 ms |
| context | 37597 B | 5455 B | 85.49 % | 21.286 ms | 21.553 ms |
| checkout | 11458 B | 4781 B | 58.27 % | 12.378 ms | 12.534 ms |
| tasks | 113239 B | 55243 B | 51.22 % | 8.125 ms | 8.182 ms |
| friction | 60842 B | 28142 B | 53.75 % | 34.488 ms | 34.577 ms |

Zusätzlich sinkt `context(evidence)` von 49247 B auf 32092 B. Das entspricht einer weiteren Reduktion um **34.83 %** gegenüber dem v1-Wirkungsnachweis.

Abnahme: **PASS**.

## Erhaltene Evidence

- erwarteter Werkzeugvertrag als Anzahl plus SHA-256;
- vollständige Capability-Zuordnung nach Werkzeug, Kategorie und Risikoklasse;
- Deployment-, Policy-, Audit- und Worktree-Evidence;
- Warnungen, nächste Aktion und Top-Level-Nichtaussagen;
- explizite Same-UID-Vertrauensgrenze und Origin-Bindung für neue Job-Receipts;
- Finalizer-Limits gelten nur im Finalizer-Prozess und verändern nicht die Semantik des Durable Jobs;
- ein fehlgeschlagenes Entfernen des temporären Publish-Links rollt ein sichtbares create-only-Ziel zurück;
- syntaktisch gültige Legacy-Jobnamen bleiben in der vorgefilterten Outbox-Liste lesbar.

## Datenumfang

- Checkout: 20 von 61 Worktrees, Limit 20.
- Tasks: 20 von 1375 Treffern, Limit 20.
- Friction: 50 Einträge, Limit 50, weitere vorhanden: true.
- Context: Profil `concise`, 120 Capability-Records und 61 Worktree-Records.
- Pro Fall fünf Stichproben; ausgewiesen sind Median und P90.

## Sicherheits- und Vollständigkeitsgrenze

- Cursor-Snapshotwechsel fordern zum Neustart der Pagination auf; Cursor bleiben ohne künstliche Ablaufzeit.
- Neue Job-Receipts sind an Origin-Hash und Startwerkzeug gebunden; alte Schema-1-Receipts bleiben lesbar.
- Die Origin-Bindung ist Defense-in-Depth innerhalb eines autorisierten Same-UID-Modells und keine vollständige Untrusted-Isolation.
- Vollständige Python-3.12-Kompatibilität wird durch die CI-Matrix geprüft; lokal verfügbar ist Python 3.10.12.

## Nicht belegt

- JSON-Bytes sind keine Modell-Token.
- Lokale Laufzeit ist keine Connector-Zuverlässigkeit.
- Die statischen Vorherwerte und der heutige Livebestand sind kein simultaner A/B-Versuch.
- Größen- und Laufzeitmessung beweisen nicht allein die Workflow-Korrektheit.

Maschinenlesbarer Beleg: `docs/proofs/consumer-surface-v2-benchmark-20260713.json`.
