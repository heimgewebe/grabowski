# Root Task Lifetime v1

## Zweck

Root Task Lifetime v1 definiert den Lebensdauer- und Wahrheitsvertrag für lokale, privilegierte Langläufer im bestehenden Grabowski-Taskmodell. Der unprivilegierte MCP-Prozess stößt ausschließlich eine root-eigene systemd-Unit über den Privileged Broker an; anschließend besitzt die System-Unit den Nutzprozess unabhängig vom aufrufenden Prozess.

## Ausführungsmodell

- Gewöhnliche lokale und entfernte Tasks behalten das Backend `systemd-user` im Scope `user`.
- Lokale Power-Worker-Kommandos verwenden `systemd-root-broker` im Scope `system`.
- Jeder persistente Datensatz bindet `execution_backend`, `systemd_scope` und `authoritative_unit`.
- Der Unit-Name bleibt kanonisch und entspricht exakt `_task_unit`. Manuell oder in einem künftig anderen Format erzeugte Units werden nicht still übernommen.
- Start, Status, Journal, Cancel und Resume routen ausschließlich anhand des gespeicherten Vertrags. Ein Root-Beobachtungsfehler fällt niemals auf `systemctl --user` zurück.

## Privilegiengrenze

Der Root-Broker akzeptiert für diesen Modus nur den eng konfigurierten Katalog der `sleep-heim*`-Übergabeskripte. Der Start verlangt den root-eigenen Recovery-Gate; reine Beobachtung und Stop bleiben verfügbar, damit ein bereits laufender oder unklarer Task wieder angeheftet beziehungsweise beendet werden kann.

Prefix-Matching ist ein Befehlskatalog, keine Argumentsandbox. Eine Erweiterung des Katalogs muss deshalb die Argumentsemantik, den Stop-Grace, die benötigten Dateisystemrechte und die systemd-Härtung des neuen Befehls ausdrücklich festlegen.

Die aktuellen Übergabeskripte benötigen Hostwartungsrechte. Daher sind `NoNewPrivileges=no`, `ProtectSystem=off` und `ProtectHome=no` bewusst gesetzt. Der Schutz entsteht aus Recovery-Gate, absolutem Executable-Katalog, kanonischer Unit-Bindung, Ressourcenlimits, kurzer Stop-Frist und Root-Audit; diese Properties stellen keine allgemeine Sandbox dar.

## Zustands- und Wiederholungsvertrag

`outcome_unknown` ist ein nichtterminaler Aufmerksamkeitszustand. Er entsteht, wenn Root-Wahrheit nicht zuverlässig gelesen werden kann, etwa bei Broker- oder Client-Timeout, ungültiger Broker-Antwort oder nicht beobachtbarer Unit. In diesem Zustand gelten folgende Regeln:

- kein Abschluss-Receipt,
- keine Ressourcenfreigabe,
- kein direkter oder Reconcile-basierter Retry,
- spätere Status- und Reconcile-Beobachtungen dürfen wieder auf `running` oder einen sicher belegten terminalen Zustand übergehen.

Auch eine frisch als `completed` beobachtete Unit darf nicht durch direkten Resume erneut gestartet werden. Bereits terminal gespeicherte Datensätze werden vor jeder Beobachtung und jedem Launch abgewiesen. Damit entsteht aus Statusverzögerungen kein Doppelstart. Scheitern Broker-Bereitschaft, Referenzerzeugung oder der lokale Client bereits vor einem belegten Dispatch, wird der Versuch terminal als fehlgeschlagen gespeichert und sein Lease freigegeben; erst Fehler nach möglicher Brokerannahme bleiben `outcome_unknown`.

## Ressourcenbindung

Laufende und unbekannte Tasks erneuern ihre Ressourcen-Leases bei Status- und Reconcile-Beobachtungen. Für `outcome_unknown` gilt höchstens die globale Grenze von sieben Tagen. Ein abgelaufener Lease wird nur neu erworben, wenn die Ressource weiterhin frei ist; fremder Besitz bleibt ein harter, sichtbarer Konflikt.

Root-Laufzeiten müssen mindestens 300 Sekunden unter der globalen Lease-Grenze enden. Zeitablauf allein erzeugt keinen Zustand `abandoned`, weil er nicht beweist, dass die root-eigene Unit beendet ist.

## Datenbankvertrag

Schema 3 ergänzt die Ausführungsbindung, ohne die inzwischen vorhandenen Task-Metadaten oder Abfrageindizes zu verlieren. Migrationen aus Schema 1 oder 2 laufen vollständig unter `BEGIN IMMEDIATE`:

1. Versionsstand nach Erwerb der Writer-Sperre erneut lesen.
2. Fehlende aktuelle Spalten ergänzen.
3. Legacy-Datensätze konservativ auf `systemd-user`, `user` und die bisherige Unit zurückfüllen.
4. Abfrageindizes herstellen.
5. Erst danach die Versionsmarke auf 3 setzen und committen.

Ein etabliertes Schema 3 führt beim Öffnen keine Backfill- oder Reparaturschreibvorgänge aus. Fehlende Pflichtspalten oder Indizes führen stattdessen zu einem expliziten Fehler.

## Zeit- und Loggrenzen

Die Brokerzeit endet vor dem jeweiligen Client-Deadline:

| Operation | Brokermaximum | Clientmaximum |
|---|---:|---:|
| `show` | 15 s | 30 s plus 15 s Clientpuffer |
| `journal` | 30 s | 30 s plus 15 s Clientpuffer |
| `start` | 60 s | 60 s plus 15 s Clientpuffer |
| `stop` | 60 s | 60 s plus 15 s Clientpuffer |

Root-Units begrenzen Journalausgaben auf 1000 Nachrichten je 30 Sekunden. Die aktuellen Übergabeskripte erhalten zehn Sekunden `TimeoutStopSec`. Länger sauber beendende Arbeitslasten benötigen vor einer Katalogerweiterung ein eigenes validiertes Stop-Grace-Feld.

## Belegpflicht

Der Vertrag benötigt Tests für:

- unveränderte User-Task-Semantik,
- Root-Start über den Broker,
- backend- und scopegebundene Status-, Log- und Cancel-Pfade,
- fehlenden User-Scope-Fallback,
- unbekannten Start mit fortbestehendem Lease und späterer Wiederanheftung,
- atomare Legacy-Migration und schreibfreien Schema-3-Fast-Path,
- Broker-Timeouts, ungültige JSON-Antworten und Recovery-Gate-Grenzen,
- Journal-Rate-Limit und kanonische Unit-Namen,
- blockierten Resume bei unbekanntem, abgeschlossenem oder bereits terminalem Task.
