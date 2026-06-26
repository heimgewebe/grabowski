# Grabowski Control Plane v1

## Zweck

Diese Stufe ergänzt den bestehenden MCP-Vertrag, ohne einen neuen Connector-Snapshot vorauszusetzen. Die vorhandene Fähigkeit `terminal_execute` ruft dafür typisierte lokale CLIs auf.

## Fleet

Die Registry liegt unter `~/.config/grabowski/fleet.json`; das versionierte Beispiel ist `config/fleet.example.json`.

```bash
/home/alex/.local/share/grabowski-mcp/.venv/bin/python tools/grabowski_fleet_cli.py list
/home/alex/.local/share/grabowski-mcp/.venv/bin/python tools/grabowski_fleet_cli.py run heimserver hostname
```

Hosts sind ausschließlich registrierte lokale oder SSH-Ziele. SSH verwendet `BatchMode=yes`, deaktiviert Forwardings, begrenzt den Verbindungsaufbau und erzeugt den Remote-Befehl aus einer argv-Liste mit POSIX-Quoting. Pro Host gilt eine Executable-Allowlist; `*` ist die explizite Power-Policy.

## Operationsrezepte

Die Registry liegt unter `~/.config/grabowski/operations.json`; das Beispiel ist `config/operations.example.json`.

Ein Rezept besteht aus geordneten Phasen:

1. `preflight`
2. `action`
3. `postflight`
4. `rollback`

Parameter dürfen nur als vollständige Tokens `${name}` eingesetzt werden. Teilinterpolation und Shell-Templates sind verboten. Scheitert eine verpflichtende Action oder ein Postflight, laufen Rollback-Schritte in umgekehrter Reihenfolge. Ergebnisse und Parameter-Hash werden auditiert.

## Privilegierter Broker

`config/privileged-actions.example.json` definiert root-eigene argv-Vorlagen. Alle Beispielaktionen sind deaktiviert. `grabowski_privileged_broker_status` prüft nur Readiness; ohne root-eigenen Broker, root-eigene Konfiguration und Request-Client bleibt der Pfad fail-closed.

Die Installation des Root-Brokers ist bewusst kein unprivilegierter Selbstumbau. Ein solcher Broker muss außerhalb des normalen MCP-Prozesses installiert und durch minimale `sudoers`-Regeln an exakt einen Request-Client gebunden werden.

## Secrets

`grabowski_secret_use` ist der Standardpfad. `grabowski_secret_reveal` ist Break-Glass und verlangt zusätzlich zur Hash-Vorbedingung:

- eine nichtleere Begründung,
- die explizite Bestätigung, dass der Inhalt in den Chatkontext gelangt.

Nur der Hash der Begründung wird auditiert.

## Connector-Probe

`tools/connector_probe.py` vergleicht die im Client sichtbaren Toolnamen mit `config/runtime-entrypoint.json`. Damit wird ein eingefrorener oder veralteter Connector-Snapshot nachweisbar, ohne neue MCP-Werkzeuge vorauszusetzen.
