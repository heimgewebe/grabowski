# Consumer Surface v2 – Wirkungsnachweis

Stand: 2026-07-13

## Ergebnis

Der Standardmodus unterschreitet die historischen Vorherwerte weiterhin auf allen fünf großen Oberflächen um mindestens 50 Prozent.

| Oberfläche | Vorher | Standard Median | Reduktion | Median Laufzeit | P90 Laufzeit |
|---|---:|---:|---:|---:|---:|
| status | 7579 B | 2781 B | 63.31 % | 75.987 ms | 76.139 ms |
| context | 37597 B | 5455 B | 85.49 % | 21.153 ms | 21.225 ms |
| checkout | 11458 B | 4781 B | 58.27 % | 12.434 ms | 12.447 ms |
| tasks | 113239 B | 52145 B | 53.95 % | 8.221 ms | 8.235 ms |
| friction | 60842 B | 28119 B | 53.78 % | 35.153 ms | 35.515 ms |

Zusätzlich sinkt `context(evidence)` von 49247 B auf 32093 B. Das entspricht einer weiteren Reduktion um **34.83 %** gegenüber dem v1-Wirkungsnachweis.

Abnahme: **PASS**.

## Erhaltene Evidence

- erwarteter Werkzeugvertrag als Anzahl plus SHA-256;
- vollständige Capability-Zuordnung nach Werkzeug, Kategorie und Risikoklasse;
- Deployment-, Policy-, Audit- und Worktree-Evidence;
- Warnungen, nächste Aktion und Top-Level-Nichtaussagen;
- explizite Same-UID-Vertrauensgrenze und Origin-Bindung für neue Job-Receipts;
- ausführbarer Negativvertrag: gemeinsame Kontrolle von Metadaten und Launcher-Precondition ist nicht authentifiziert;
- Hauptprozessausgang und aggregierter `ExecStopPost`-/Postflightfehler werden getrennt ausgewiesen;
- Finalizer-Limits gelten nur im Finalizer-Prozess und verändern nicht die Semantik des Durable Jobs;
- strukturierte Finalizerfehler bleiben im langlebigen Job-Stderr sichtbar;
- der sichtbare Verzeichnispfad wird nach dem Publish erneut an den geöffneten Directory-FD gebunden;
- ein fehlgeschlagenes Entfernen des temporären Publish-Links oder ein Pfadbindungsfehler rollt nur das eigene sichtbare Ziel zurück;
- ein inzwischen fremd ersetzter Ziel-Inode wird beim Rollback nicht gelöscht;
- Cleanup-Fehler verdecken keinen bereits festgestellten primären Fehler;
- syntaktisch gültige Legacy-Jobnamen bleiben für Schema 1 lesbar; Schema 2 verlangt kanonische Job-IDs.

## Datenumfang

- Checkout: 20 von 61 Worktrees, Limit 20.
- Tasks: 20 von 1381 Treffern, Limit 20.
- Friction: 50 Einträge, Limit 50, weitere vorhanden: true.
- Context: Profil `concise`, 120 Capability-Records und 61 Worktree-Records.
- Pro Fall fünf Stichproben; ausgewiesen sind Median und P90.

## Sicherheits- und Vollständigkeitsgrenze

- Cursor-Snapshotwechsel liefern das stabile Präfix `cursor_snapshot_changed:` und fordern zum Neustart der Pagination auf; Cursor bleiben ohne künstliche Ablaufzeit.
- Neue Job-Receipts sind an Origin-Hash und Startwerkzeug gebunden; alte Schema-1-Receipts bleiben lesbar.
- Die Origin-Bindung ist **keine Isolation**. Kontrolliert ein Same-UID-Prozess Metadaten und Finalizer-Precondition gemeinsam, kann er einen konsistenten gefälschten Vertrag herstellen.
- Das create-only Publishing ersetzt kein vorhandenes Ziel und schützt nicht gegen Löschung oder Ersetzung nach erfolgreichem Abschluss.
- Vollständige Python-3.12-Kompatibilität wird durch die CI-Matrix geprüft; lokal verfügbar ist Python 3.10.12.

## Nicht belegt

- JSON-Bytes sind keine Modell-Token.
- Lokale Laufzeit ist keine Connector-Zuverlässigkeit.
- Die statischen Vorherwerte und der heutige Livebestand sind kein simultaner A/B-Versuch.
- Größen- und Laufzeitmessung beweisen nicht allein die Workflow-Korrektheit.
- Same-UID-Ausführung ist keine Sicherheitsdomäne für vollständig untrusted Code.

Maschinenlesbarer Beleg: `docs/proofs/consumer-surface-v2-benchmark-20260713.json`.
