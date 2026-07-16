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

## Temporäre Git-Checkouts

Verlinkte Worktrees werden über `grabowski_checkout_inventory`,
`grabowski_checkout_retain`, `grabowski_checkout_archive` und
`grabowski_checkout_cleanup` verwaltet. Cleanup ist Dry-Run-first: Apply
benötigt Plan-ID und Plan-Hash eines frischen Dry-Runs. Archivierung erzeugt
dauerhafte Recovery-Refs unter `refs/grabowski/checkouts/...`; Branches werden
nicht gelöscht und es wird keine forcierte Dateisystemlöschung verwendet.

Details: [`docs/checkout-lifecycle.md`](checkout-lifecycle.md).

## Privilegierter Broker

`config/privileged-actions.example.json` definiert root-eigene argv-Vorlagen, einen optionalen Power-Worker-Modus und den festen Root-Task-systemd-Modus. Allgemeine Hochleistungsaktionen bleiben deaktiviert; der eng katalogisierte Root-Task-Modus und die Recovery-Publikation sind als konkrete Betriebsverträge aktiviert. Der Broker besteht aus:

- `src/grabowski_privileged_broker.py`: Referenz-, TTL-, Template-, Power-argv- und Replay-Prüfung,
- `tools/grabowski_privileged_broker.py`: root-seitiger Handler ohne implizite Shell,
- `tools/grabowski_privileged_request.py`: begrenzter Unix-Socket-Client,
- `systemd/grabowski-privileged-broker.socket` und `@.service`: gruppenbegrenzte Socket-Aktivierung.

Der Handler akzeptiert nur kurzlebige, hashgebundene Referenzen. Template-Aktionen ersetzen ausschließlich das vollständige Token `{target}`. Power-Aktionen verwenden `mode=argv-json`: `target` ist ein JSON-Objekt mit `argv` und `cwd`. Der Broker verlangt absolute Executables, prüft `cwd_pattern`, `max_argv`, `allow_shell` und markiert jede Request-ID vor der Ausführung als verbraucht. Auditdaten enthalten Ziel-, cwd- und argv-Hashes, nicht Begründung oder Secretwerte. Strukturierte Broker-Ablehnungen und Zielbefehlsfehler werden dem Socket-Client gemeldet; der Broker-Prozess beendet solche behandelten Request-Ergebnisse mit Exit 0, damit keine failed systemd-Instanzen entstehen. Unerwartete interne Brokerfehler bleiben Host-Service-Fehler.

Persistente lokale Power-Worker-Tasks verwenden `operator_root_task_systemd_unit` mit `mode=root-task-systemd`. Der unprivilegierte Taskdatensatz speichert `execution_backend`, `systemd_scope` und `authoritative_unit`; normale Tasks bleiben `systemd-user` im User-Scope. Root-Tasks starten nur den kurzen Übergabebefehl `systemd-run --system` über den Broker, danach besitzt die root-eigene Unit den Nutzprozess. Status, Logs, Cancel und Resume verwenden ausschließlich den gespeicherten Backend-/Scope-Vertrag; wenn Root-Wahrheit nicht beobachtbar ist, bleibt der Task `outcome_unknown` oder die Operation blockiert und fällt nicht auf `systemctl --user` zurück. Schema-1/2-Datenbanken werden unter `BEGIN IMMEDIATE` atomar auf Schema 3 migriert; bereits etablierte Schema-3-Datenbanken führen weder Backfill-Updates noch eine Versionsschreibung bei jedem Lesezugriff aus.

`outcome_unknown` ist absichtlich nicht terminal. Es erzeugt kein Abschluss-Receipt und gibt keine Ressource frei. Laufende und unbekannte Tasks erneuern ihre Leases bei Status- und Reconcile-Beobachtungen; unbekannte Zustände erhalten höchstens die globale siebentägige Lease-Grenze. Root-Laufzeiten müssen 300 Sekunden darunter bleiben, damit Lease- und Stop-Grace auch am Laufzeitmaximum erhalten bleiben. Nach Ablauf darf nur neu gebunden werden, wenn die Ressource weiterhin frei ist. Es gibt keinen zeitgesteuerten `abandoned`-Übergang, weil Zeitablauf allein nicht beweist, dass eine root-eigene Unit beendet ist.

Die Broker-Zeitgrenze ist operationsabhängig: `show` höchstens 15 Sekunden, `journal` höchstens 30 Sekunden, `start` und `stop` höchstens 60 Sekunden. Damit endet der Root-Broker vor dem jeweils größeren Client-Deadline. Root-Units begrenzen Journalausgaben zusätzlich mit `LogRateLimitIntervalSec=30s` und `LogRateLimitBurst=1000`. `TimeoutStopSec=10s`, `NoNewPrivileges=no`, `ProtectSystem=off` und `ProtectHome=no` sind keine allgemeine Sandbox-Konfiguration, sondern der bewusst enge Vertrag für die aktuell allein katalogisierten `sleep-heim*`-Übergabeskripte. Vor einer Erweiterung des Katalogs müssen Argumentsemantik, Stop-Grace und Systemd-Härtung pro Befehl neu festgelegt werden. Prefix-Matching allein validiert keine nachfolgenden Argumente.

`grabowski_privileged_broker_status` prüft Binary, root-eigene Konfiguration, Socket und Client. `grabowski_power_run` ist der maximale Operatorpfad: Es erzeugt eine kurzlebige `operator_power_argv`-Referenz, verlangt gültige Audit-Chain, Kill-Switch-freiheit, Broker-Bereitschaft und `grabowski_recovery_status.ready_for_user_power_worker=true` sowie `ready_for_privileged_actions=true`, bevor es den Root-Broker aufruft. Die Hostinstallation ist bewusst kein unprivilegierter Selbstumbau: Dateien müssen root-eigen unter `/usr/local` und `/etc` installiert, der Socket aktiviert und der Operator der Gruppe `grabowski` hinzugefügt werden. Bis dahin bleibt der Pfad fail-closed.

Für stale systemd-Fehlzustände gibt es als enges Template `reset_failed_systemd_unit` mit `/usr/bin/systemctl reset-failed {target}`. Die Aktion bleibt in der Beispielkonfiguration deaktiviert und darf nur Zielnamen matchen, die als `.service`-Unit explizit zugelassen sind. `operator_power_argv` bleibt ebenfalls deaktiviert, bis der Host bewusst maximale Operator-Handlungsfähigkeit erlauben soll. Mit `allow_shell=false` werden nur direkte bekannte Shell-Executables wie `/bin/sh`, `/bin/bash` und `/usr/bin/env` blockiert. Mit `allowed_argv_prefixes` kann der Host zusätzlich einen expliziten Admin-Katalog wie `systemctl is-active`, `systemctl status`, `apt-get update`, `docker compose`, `chown`, `chmod`, `mount` und `umount` erzwingen. Der Katalog kann für trusted-owner-Betrieb bewusst breit sein und über `policy_intent` als High-Power-Schiene markiert werden; er ist aber nur Prefix-Matching, keine vollständige Argument- oder Zielvalidierung. Das ist keine Sandbox: Ein aktiviertes `operator_power_argv` bleibt beliebige Root-Ausführung über absolute argv. Die root-eigene `gate`-Konfiguration muss deshalb Kill-Switch und frische Recovery-Marker zusätzlich im Broker prüfen; mit `allow_shell=true` wird auch die direkte Shell-Form bewusst zugelassen.

## Secrets

`grabowski_secret_use` ist der Standardpfad. `grabowski_secret_reveal` ist Break-Glass und verlangt zusätzlich zur Hash-Vorbedingung:

- eine nichtleere Begründung,
- die explizite Bestätigung, dass der Inhalt in den Chatkontext gelangt.

Nur der Hash der Begründung wird auditiert.

## Typisierte Lesespur

Die Runtime registriert eine eigene Read-Surface fuer schmale Kontext-, Git-, GitHub- und User-Service-Abfragen. Die Werkzeuge besitzen feste Argumentformen, begrenzte Ausgaben und wahrheitsgemaesse MCP-Annotationen. GitHub-Lesen bleibt wegen des externen Zugriffs `openWorldHint=true`; lokal geschlossene Diagnostik bleibt `false`. Generische Terminal-, Git-, GitHub- und Service-Werkzeuge werden nicht entfernt, sind aber nur Fallback. Die Projektionen `core`, `operator` und `full` stammen aus demselben Runtime-Vertrag und Katalog. Details stehen in `docs/typed-read-surface.md`.

## Live-Werkzeugvertrag und Self-Deploy

`grabowski_status` veröffentlicht zusätzlich erwartete und registrierte Werkzeuganzahl, Hashes beider Namensmengen sowie begrenzte Driftlisten. Der Client-Snapshot bleibt von der Runtime aus unbeobachtbar; weichen Anzahl oder Hash des Clients ab, ist ein Connector-Refresh erforderlich.

`grabowski_runtime_deploy_schedule` ist der enge Selbstaktualisierungspfad. Er bindet die Zielrevision an den sauberen kanonischen `main`-Checkout und startet einen verzögerten dauerhaften Job. Dadurch überlebt der Deploymentprozess den Neustart der Dienste, die den ursprünglichen MCP-Request transportieren.

## Connector-Probe

`tools/connector_probe.py` startet die installierte Runtime über MCP-stdio, liest deren vollständiges `tools/list` und vergleicht drei Ebenen:

1. Werkzeugnamen des versionierten Runtime-Vertrags gegen die laufende Runtime,
2. Werkzeugnamen des Clients gegen die laufende Runtime,
3. normalisierte `inputSchema`-Fingerprints sicherheitskritischer Sentinel-Werkzeuge.

Das beobachtete Client-Artefakt verwendet `schema_version: 1` und eine `tools`-Liste. Ein Element ist entweder nur ein Werkzeugname oder ein Objekt mit `name` und `inputSchema`. Für alle Sentinel-Werkzeuge muss das Schema enthalten sein; eine reine Namensliste gilt daher bewusst nicht als vollständiger Beleg.

Aktueller Sentinel ist `grabowski_secret_reveal`, weil ein veralteter Connector dessen neue Break-Glass-Parameter unsichtbar machen kann, obwohl weiterhin 34 von 34 Werkzeugnamen übereinstimmen. Beschreibungen und JSON-Schema-Titel werden aus dem Fingerprint entfernt; operative Felder, Required-Listen, Typen und Defaults bleiben bindend.

Die Runtime kann den eingefrorenen Client-Snapshot nicht selbst auslesen. Die Probe benötigt deshalb ein aus dem Clientvertrag erzeugtes Beobachtungsartefakt. Sie diagnostiziert Drift deterministisch, aktualisiert den Connector aber nicht selbst.
