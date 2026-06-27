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

Die mitgelieferte Konfiguration enthält nur `edit_system_service` und setzt `enabled` auf `false`. Eine Aktivierung ist erst zulässig, nachdem Zielregex, absolutes argv-Template und Timeout einzeln geprüft wurden. Der Platzhalter `{target}` darf ausschließlich als vollständiges argv-Token vorkommen.

## Abnahme

1. `grabowski_privileged_broker_status` meldet Binary, Konfiguration, Socket und Client als gültig.
2. Eine abgelaufene, manipulierte oder wiederverwendete Referenz wird abgelehnt.
3. Eine deaktivierte Aktion wird abgelehnt.
4. Ein freigegebener Testdienst kann neu gestartet werden; Audit enthält nur Hashes und Status.
5. Nach Deaktivierung der Aktion wird derselbe Auftrag wieder abgelehnt.

Die Root-Stufe ist kein generischer Shellzugang. Neue Aktionsklassen benötigen jeweils ein neues festes Template und eigene Tests.
