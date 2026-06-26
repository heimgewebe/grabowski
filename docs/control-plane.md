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

`config/privileged-actions.example.json` definiert root-eigene argv-Vorlagen. Alle Beispielaktionen sind deaktiviert. Der Broker besteht aus:

- `src/grabowski_privileged_broker.py`: Referenz-, TTL-, Template- und Replay-Prüfung,
- `tools/grabowski_privileged_broker.py`: root-seitiger Handler ohne Shell,
- `tools/grabowski_privileged_request.py`: begrenzter Unix-Socket-Client,
- `systemd/grabowski-privileged-broker.socket` und `@.service`: gruppenbegrenzte Socket-Aktivierung.

Der Handler akzeptiert nur kurzlebige, hashgebundene Referenzen aus `grabowski_privileged_action_reference`, ersetzt ausschließlich das vollständige Token `{target}`, verlangt absolute Executables und markiert jede Request-ID vor der Ausführung als verbraucht. Auditdaten enthalten Ziel- und argv-Hashes, nicht Begründung oder Secretwerte.

`grabowski_privileged_broker_status` prüft Binary, root-eigene Konfiguration, Socket und Client. Die Hostinstallation ist bewusst kein unprivilegierter Selbstumbau: Dateien müssen root-eigen unter `/usr/local` und `/etc` installiert, der Socket aktiviert und der Operator der Gruppe `grabowski` hinzugefügt werden. Bis dahin bleibt der Pfad fail-closed.

## Secrets

`grabowski_secret_use` ist der Standardpfad. `grabowski_secret_reveal` ist Break-Glass und verlangt zusätzlich zur Hash-Vorbedingung:

- eine nichtleere Begründung,
- die explizite Bestätigung, dass der Inhalt in den Chatkontext gelangt.

Nur der Hash der Begründung wird auditiert.

## Connector-Probe

`tools/connector_probe.py` vergleicht die im Client sichtbaren Toolnamen mit `config/runtime-entrypoint.json`. Damit wird ein eingefrorener oder veralteter Connector-Snapshot nachweisbar, ohne neue MCP-Werkzeuge vorauszusetzen.
