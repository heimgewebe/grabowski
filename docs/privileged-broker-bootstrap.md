# Privileged Broker Bootstrap

Dieser Bootstrap ist die einzige absichtlich externe Root-Stufe. Vorher bleibt der Broker vollständig inaktiv.

## Zu installierende Artefakte

| Repository | Root-eigenes Ziel | Modus |
|---|---|---:|
| `src/grabowski_privileged_broker.py` | `/usr/local/lib/grabowski/grabowski_privileged_broker.py` | `0644` |
| `tools/grabowski_privileged_broker.py` | `/usr/local/libexec/grabowski-privileged-broker` | `0755` |
| `tools/grabowski_privileged_request.py` | `/usr/local/bin/grabowski-privileged-request` | `0755` |
| `tools/grabowski_rootbroker_cutover.py` | `/usr/local/libexec/grabowski-rootbroker-cutover` | `0755` |
| `config/privileged-actions.example.json` | `/etc/grabowski/privileged-actions.json` | `0600` |
| `systemd/grabowski-privileged-broker.socket` | `/etc/systemd/system/` | `0644` |
| `systemd/grabowski-privileged-broker@.service` | `/etc/systemd/system/` | `0644` |
| `systemd/grabowski-privileged-broker@.service.d/recovery-source.conf` | `/etc/systemd/system/grabowski-privileged-broker@.service.d/recovery-source.conf` | `0644` |
| `tmpfiles/grabowski.conf` | `/etc/tmpfiles.d/grabowski.conf` | `0644` |

Danach wird eine Systemgruppe `grabowski` angelegt, der Operator dieser Gruppe hinzugefügt und `systemd-tmpfiles --create /etc/tmpfiles.d/grabowski.conf` ausgeführt. Das versionierte tmpfiles-Fragment stellt sicher, dass `/run/grabowski` dauerhaft `root:grabowski` mit Modus `0750` gehört; `SocketGroup=grabowski` allein setzt nur die Gruppe des Sockets, nicht die des Elternverzeichnisses. Erst anschließend werden `systemctl daemon-reload` und ausschließlich `grabowski-privileged-broker.socket` aktiviert. Neue Gruppenmitgliedschaften gelten erst in einer frischen Login-Sitzung.

Das Recovery-Source-Drop-in hält das Home-Verzeichnis mit `ProtectHome=tmpfs` verborgen. Vorherige Bind-Mount-Listen werden geleert. Sichtbar sind ausschließlich der feste Quellbeleg `last-server-recovery.json` und, falls vorhanden, der feste Kill-Switch. Eine Freigabe des gesamten Recovery-Verzeichnisses ist nicht Teil des Vertrags. `ProtectHome=yes` darf hier nicht verwendet werden: systemd kann darunter keine verschachtelten `BindReadOnlyPaths` erreichbar machen.

## Bestehende Installation auf den kanonischen Publisher migrieren

Eine bereits aktive Rootbroker-Installation wird nicht durch Kopieren der Beispielkonfiguration ersetzt. Dafür existiert ausschließlich `tools/grabowski_rootbroker_cutover.py`. Der Helper bindet sich an einen ausdrücklich angegebenen vollständigen Commit, liest Broker, Client, Helper, Recovery-Source-Drop-in und Publishervertrag direkt aus dessen Git-Objekten und lehnt einen abweichenden Checkout-HEAD ab. Ein veränderter Arbeitsbaum ist damit keine Installationsquelle.

Ohne `--apply` erzeugt der Helper nur einen Plan. Dieser vergleicht installierte und gewünschte SHA-256-Werte und beweist, welche Konfigurationsanteile erhalten bleiben. Mit `--apply` verlangt der Helper UID 0, einen bereits aktiven Rootbroker-Socket und einen exklusiven root-eigenen Lock unter `/run/grabowski/rootbroker-cutover.lock`. Ein inaktiver oder nicht eindeutig prüfbarer Socket blockiert vor Backup und Mutation; der Helper aktiviert keinen zuvor inaktiven Rootbroker.

Der Mutationspfad ist eng begrenzt:

1. Die bestehende Konfiguration muss Schema 2 enthalten und `operator_power_argv` bereits aktiviert haben.
2. Kill-Switch-Pfad, Recovery-Marker-Pfad, Maximalalter und Root-Eigentumsvertrag des bestehenden Power-Gates müssen exakt zum versionierten Publisher passen.
3. Der Helper ergänzt ausschließlich `publish_recovery_marker` und `gate.configured_target`. Alle sonstigen Aktionen und alle übrigen Felder von `operator_power_argv` müssen bytewertgleich bleiben.
4. Sämtliche Python-Artefakte werden vor der ersten Mutation aus dem gebundenen Commit geladen, digestgeprüft und kompiliert. Das Recovery-Source-Drop-in muss bytegenau aus Publisher-Quellpfad und Kill-Switch-Pfad ableitbar sein; breite oder zusätzliche Home-Freigaben werden abgelehnt.
5. Vor jeder Änderung werden root-eigene Preimages mit SHA-256, Modus, UID und GID unter `/var/lib/grabowski/rootbroker-cutover-backups` gesichert und unmittelbar vor dem Replace erneut geprüft.
6. Installationen erfolgen über private temporäre Dateien, Datei-`fsync`, atomaren Replace, Readback und Directory-`fsync`.
7. Nach der Installation des Drop-ins führt der Helper `systemctl daemon-reload` aus, bevor der Socket wieder startet. Jeder Fehler einschließlich Reload-, Start- oder Erfolgs-Receipt-Fehler löst die Wiederherstellung aller Preimages, einen erneuten Reload und die Wiederherstellung des vorherigen Socket-Zustands aus.
8. Erfolg und Fehler werden root-eigen unter `/var/lib/grabowski/rootbroker-cutover-receipts` belegt. Der Erfolgsbeleg bindet installierte SHA-256-Werte und den abgeschlossenen Reload.
9. Bei Erfolg installiert der Helper auch sich selbst root-eigen unter `/usr/local/libexec/grabowski-rootbroker-cutover`. Spätere Prüfungen benötigen daher kein veränderbares Helper-Skript aus einem Benutzercheckout.

Die einmalige Ausführung über eine Desktop-Autorisierung oder einen anderen ausdrücklich freigegebenen Rootpfad ist eine echte Privilegiengrenze. Sie darf weder durch einen veralteten Recovery-Marker noch durch eine Erweiterung des Brokerkatalogs um einen generischen Installations- oder Shellpfad umgangen werden.

## Aktivierung einer Aktion

Die mitgelieferte Konfiguration lässt allgemeine Rootaktionen deaktiviert. Nur der feste Publisher `publish_recovery_marker` ist aktiviert; er besitzt keinen argv-Pfad und kann ausschließlich einen streng validierten Recovery-Beleg vom fest konfigurierten Quellpfad in den fest konfigurierten root-eigenen Zielpfad überführen. `edit_system_service` bleibt ein deaktiviertes Restart-Beispiel; `reset_failed_systemd_unit` ist ein enger Pfad für `systemctl reset-failed {target}` und ist ebenfalls standardmäßig deaktiviert. Eine Aktivierung ist erst zulässig, nachdem Zielregex, absolutes argv-Template und Timeout einzeln geprüft wurden. Der Platzhalter `{target}` darf ausschließlich als vollständiges argv-Token vorkommen.

`operator_power_argv` ist der maximale Operatorpfad. Er nutzt `mode=argv-json`; `target` enthält ein JSON-Objekt mit `argv` und `cwd`. Der Broker verlangt absolute Executables, bounded argv-Länge, `cwd_pattern`, Timeout und eine explizite `allow_shell`-Entscheidung. Optional kann `allowed_argv_prefixes` gesetzt werden; dann akzeptiert der Broker nur argv, die mit einem der katalogisierten Präfixe beginnen. `policy_intent` kann diese Konfiguration ausdrücklich als trusted-owner-high-power-Katalog kennzeichnen. Prefixe sind keine vollständige Argument- oder Zielvalidierung; für maximale Handlungsfähigkeit dürfen sie breit sein, müssen aber über Audit, Recovery-Gate und Kill-Switch kontrolliert werden. Mit `allow_shell=false` sind nur direkte bekannte Shell-Executables blockiert; das ist keine Sandbox und verhindert keine Interpreter wie Python, awk oder busybox. Mit `allow_shell=true` wird auch die direkte Shell-Form bewusst zugelassen. In beiden Fällen darf die Aktion nur mit root-seitiger `gate`-Prüfung für Kill-Switch und frische Recovery-Marker aktiviert werden.

`reset_failed_systemd_unit` darf nur Failed-State-Metadaten einer explizit gematchten `.service`-Unit löschen. Der Pfad darf keine Units starten, stoppen, restarten, enablen, disablen oder editieren. Für Fälle wie einen stale `user@111.service`-Fail bleibt vor der Ausführung eine read-only Prüfung von `systemctl --failed` und `getent passwd <uid>` nötig.

## Kanonischer Recovery-Freshness-Vertrag

`grabowski_recovery_server_probe` schreibt nach erfolgreichem Backup, bytegleichem Restore und Repository-Check atomar den benutzereigenen Quellbeleg. Anschließend erzeugt es eine einmalige, digest- und generationsgebundene Brokerreferenz für `publish_recovery_marker`. Der Rootbroker prüft vor und unmittelbar vor dem Schreiben erneut Quellpfad, Besitzer-UID, Dateimodus, exakte JSON-Schlüssel, Ziel, Alter, Snapshot-ID und SHA-256. Die Aktion führt kein frei wählbares Programm aus.

Der Rootbroker veröffentlicht `/var/lib/grabowski/power-worker-recovery-gate.json` unter exklusivem Dateilock mit temporärer Datei, `fsync`, atomarem `replace` und anschließendem Readback. Ältere Generationen und gleichzeitige Kollisionen werden abgelehnt; eine identische Wiederholung ist idempotent. Der kanonische Datensatz ist `root:root`, Modus `0644`: für den unprivilegierten Status lesbar, aber nicht beschreibbar. Er enthält keine Secrets, sondern ausschließlich Zeit, Maximalalter, Ziel, Snapshot-ID und Quell-/Datensatzdigests.

`grabowski_recovery_status` und das Rootbroker-Power-Gate lesen danach denselben kanonischen Datensatz und melden dieselbe `generated_at_unix`, `age_seconds`, `max_age_seconds`, `freshness_reason`, `record_sha256` und `source_record_sha256`. Fehlende, partielle, malformed, future-dated, stale oder zielabweichende Datensätze bleiben auf beiden Seiten fail-closed. Der Benutzer-Quellbeleg allein autorisiert keine privilegierte Aktion.

Diese Kopplung stellt kohärente Recovery-Freshness und root-eigenen Schreibschutz her. Sie ist keine unabhängige kryptografische Attestierung gegen den angemeldeten Trusted Owner; der Rootbroker bleibt ein eng katalogisierter Capability-Broker mit Audit, Kill-Switch und festen Pfaden.

## Abnahme

1. `grabowski_privileged_broker_status` meldet Binary, Konfiguration, Socket und Client als gültig.
2. Eine abgelaufene, manipulierte oder wiederverwendete Referenz wird abgelehnt.
3. Eine deaktivierte Aktion wird abgelehnt.
4. Ein freigegebener Testdienst kann neu gestartet werden; Audit enthält nur Hashes und Status.
5. Nach Deaktivierung der Aktion wird derselbe Auftrag wieder abgelehnt.

Die Root-Stufe ist standardmäßig kein generischer Shellzugang. Generische Root-Handlungsfähigkeit existiert nur über `operator_power_argv`, bleibt in der Beispielkonfiguration deaktiviert und benötigt eigene Tests, Recovery-Gate und Audit-Evidence.
