# Privileged Broker Bootstrap

Dieser Bootstrap ist die einzige absichtlich externe Root-Stufe. Vorher bleibt der Broker vollständig inaktiv.

## Zu installierende Artefakte

| Repository | Root-eigenes Ziel | Modus |
|---|---|---:|
| `src/grabowski_privileged_broker.py` | `/usr/local/lib/grabowski/grabowski_privileged_broker.py` | `0644` |
| `tools/grabowski_privileged_broker.py` | `/usr/local/libexec/grabowski-privileged-broker` | `0755` |
| `tools/grabowski_privileged_request.py` | `/usr/local/bin/grabowski-privileged-request` | `0755` |
| `config/privileged-actions.example.json` | `/etc/grabowski/privileged-actions.json` | `0600` |
| `systemd/grabowski-privileged-broker.socket` | `/etc/systemd/system/` | `0644` |
| `systemd/grabowski-privileged-broker@.service` | `/etc/systemd/system/` | `0644` |
| `tmpfiles/grabowski.conf` | `/etc/tmpfiles.d/grabowski.conf` | `0644` |

Danach wird eine Systemgruppe `grabowski` angelegt, der Operator dieser Gruppe hinzugefügt und `systemd-tmpfiles --create /etc/tmpfiles.d/grabowski.conf` ausgeführt. Das versionierte tmpfiles-Fragment stellt sicher, dass `/run/grabowski` dauerhaft `root:grabowski` mit Modus `0750` gehört; `SocketGroup=grabowski` allein setzt nur die Gruppe des Sockets, nicht die des Elternverzeichnisses. Erst anschließend werden `systemctl daemon-reload` und ausschließlich `grabowski-privileged-broker.socket` aktiviert. Neue Gruppenmitgliedschaften gelten erst in einer frischen Login-Sitzung.

## Aktivierung einer Aktion

Die mitgelieferte Konfiguration enthält nur deaktivierte Beispielaktionen. `edit_system_service` bleibt ein deaktiviertes Restart-Beispiel; `reset_failed_systemd_unit` ist ein enger Pfad für `systemctl reset-failed {target}` und ist ebenfalls standardmäßig deaktiviert. Eine Aktivierung ist erst zulässig, nachdem Zielregex, absolutes argv-Template und Timeout einzeln geprüft wurden. Der Platzhalter `{target}` darf ausschließlich als vollständiges argv-Token vorkommen.

`operator_power_argv` ist der maximale Operatorpfad. Er nutzt `mode=argv-json`; `target` enthält ein JSON-Objekt mit `argv` und `cwd`. Der Broker verlangt absolute Executables, bounded argv-Länge, `cwd_pattern`, Timeout und eine explizite `allow_shell`-Entscheidung. Mit `allow_shell=false` sind nur direkte bekannte Shell-Executables blockiert; das ist keine Sandbox und verhindert keine Interpreter wie Python, awk oder busybox. Mit `allow_shell=true` wird auch die direkte Shell-Form bewusst zugelassen. In beiden Fällen darf die Aktion nur mit root-seitiger `gate`-Prüfung für Kill-Switch und frische Recovery-Marker aktiviert werden.

`reset_failed_systemd_unit` darf nur Failed-State-Metadaten einer explizit gematchten `.service`-Unit löschen. Der Pfad darf keine Units starten, stoppen, restarten, enablen, disablen oder editieren. Für Fälle wie einen stale `user@111.service`-Fail bleibt vor der Ausführung eine read-only Prüfung von `systemctl --failed` und `getent passwd <uid>` nötig.

## Abnahme

1. `grabowski_privileged_broker_status` meldet Binary, Konfiguration, Socket und Client als gültig.
2. Eine abgelaufene, manipulierte oder wiederverwendete Referenz wird abgelehnt.
3. Eine deaktivierte Aktion wird abgelehnt.
4. Ein freigegebener Testdienst kann neu gestartet werden; Audit enthält nur Hashes und Status.
5. Nach Deaktivierung der Aktion wird derselbe Auftrag wieder abgelehnt.

Die Root-Stufe ist standardmäßig kein generischer Shellzugang. Generische Root-Handlungsfähigkeit existiert nur über `operator_power_argv`, bleibt in der Beispielkonfiguration deaktiviert und benötigt eigene Tests, Recovery-Gate und Audit-Evidence.
