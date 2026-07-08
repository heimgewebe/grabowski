# Grabowski Omniperator Control Plane

## Ziel

Grabowski soll langlaufende Benutzeraufgaben lokal und auf registrierten Hosts ausführen können, ohne den tunnelgebundenen MCP-Prozess selbst zu entsanden. Rootwirkungen und Recovery bleiben getrennte Ebenen.

## Topologie

```text
ChatGPT
  -> gehärteter Grabowski-MCP-Kern
     -> persistente Taskdatenbank
     -> lokale transiente User-systemd-Units
     -> SSH/Fleet -> Remote-User-systemd-Units
     -> benannter Operationskatalog
     -> separater root-eigener Privileged Broker
```

Der MCP-Kern bleibt loopbackgebunden und behält seine Diensthärtung. Breite Benutzerprozesse laufen als eigene `grabowski-task-*.service`-Units. Jede Unit besitzt eine eigene Cgroup, Laufzeit- und Ressourcenbudgets sowie einen persistenten Taskdatensatz.

## Taskvertrag

Die Taskdatenbank liegt standardmäßig unter:

```text
~/.local/state/grabowski/tasks.sqlite3
```

Sie verwendet SQLite WAL, `synchronous=FULL`, Modus `0600` und lehnt Symlinks ab. Ein Task speichert mindestens:

- Host und systemd-Unit,
- Versuchszähler,
- Zustand und Resume-Policy,
- argv-Hash und redigierte Darstellung,
- Arbeitsverzeichnis,
- Laufzeit- und Ressourcenbudgets,
- Launchergebnis und letzte Beobachtung.

Unterstützte Resume-Policies:

- `never`
- `retry-safe`
- `verify-then-retry`
- `manual`

`resume` setzt keinen Prozess fort. Es erzeugt nach Beobachtung des alten Zustands einen neuen, nummerierten Versuch. Der Aufrufer muss eine zur Operation passende Resume-Policy wählen.

## Fleet und Operationen

Die bereits vorhandenen Fleet- und Operationsmodule werden Teil des Runtime-Vertrags:

- `grabowski_fleet_list`
- `grabowski_fleet_run`
- `grabowski_operation_list`
- `grabowski_operation_plan`
- `grabowski_operation_run`

Fleet-Aufrufe bleiben argv-basiert. Benannte Operationen behalten Preflight, Action, Postflight und umgekehrten Rollback.

## Recovery-Gate

`grabowski_recovery_status` aktiviert selbst nichts. Das Tool bewertet fail-closed:

- Integrität der Auditkette,
- Deployment-Provenienz,
- frischen lokalen Backup-/Restore-Beleg,
- aktiven und aktivierten Backup-Timer,
- frischen serverseitigen Backup-, Restore- und Repository-Check,
- Bereitschaft des root-eigenen Brokers.

Benutzer-Power-Tasks und privilegierte Aktionen besitzen getrennte Gates. Der Root-Gate kann erst grün werden, wenn auch der Broker hostseitig installiert und geprüft ist.

Runtime-Gesundheit und Recovery-Evidence sind getrennte Wahrheiten. Ein grüner Runtime-Status beweist nicht, dass Restore-Pfade frisch geprüft sind. `grabowski_recovery_status` gibt deshalb zusätzlich `recovery_evidence_boundary` aus. Bei der Standardkonfiguration meldet die Boundary `uses_default_heimserver_backend=true`; ist dieser Pfad nicht frisch und zielgleich belegt, bleiben Power-Worker und privilegierte Aktionen blockiert. Ein Custom-Recovery-Ziel meldet `custom_recovery_target_configured=true`, gilt aber erst als Recovery-Evidence, nachdem Backup-, Restore-Sentinel- und Repository-Check gegen exakt dieses konfigurierte Ziel bestanden haben. Details: `docs/non-heimserver-recovery-boundary.md`.

## Recovery-Server

Die versionierte Compose-Datei unter `deploy/heimserver/` beschreibt einen begrenzten Restic-REST-Dienst:

- ausschließlich `127.0.0.1:18081`,
- Zugriff vom Heim-PC über SSH-Tunnel,
- append-only und private Repositories,
- 30-GiB-Maximum,
- read-only Containerwurzel,
- keine Linux-Capabilities,
- CPU-, RAM- und PID-Limits,
- gepinntes Image-Digest.

Die Compose-Datei allein ist kein Recovery-Beleg. Erst ein erfolgreiches Backup mit Restore-Sentinel und Repository-Check erzeugt das vom Gate akzeptierte Evidence-Objekt.

## Nicht Teil dieses Cutovers

- Aktivierung des Trusted-Owner-Profils,
- Entsandung des MCP-Kerndienstes,
- Installation des Rootbrokers,
- Browser- oder Desktopsteuerung,
- Veröffentlichung eines neuen Connector-Snapshots.

Diese Schritte folgen erst nach bestandenem Recovery-Gate und eigenen End-to-End-Tests.
