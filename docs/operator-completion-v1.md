# Operator Completion v1

Dieser Slice ergänzt den Control-Plane-Kern um die verbleibenden unprivilegierten Betriebsbausteine. Backup und Recovery-Evidenz sind ausdrücklich nicht Teil dieses Changes.

## Ressourcen und Tasks

`grabowski_resources` verwaltet persistente, typisierte Leases für Repositories, Pfade, Ports, Dienste, Browserprofile und Displays. Die SQLite-Datenbank verwendet WAL, `synchronous=FULL`, restriktive Rechte und atomare Mehrfachbelegung. Persistente Tasks erwerben deklarierte Leases vor Start oder Resume und geben sie bei Fehlstart, Abbruch oder terminaler Beobachtung frei.

`grabowski_task_reconcile` gleicht Taskdatensätze mit User-systemd-Units ab. Nur `retry-safe` darf automatisch wiederaufgenommen werden; das Recovery-Gate gilt nur für erkannte Power-Aufgaben; normale User-Space-Tasks starten unabhängig vom Backup-Nachweis. Beispiel-Units ermöglichen Reconciliation nach Boot und periodisch.

## Artefakte

`artifact_stat`, `artifact_push` und `artifact_pull` arbeiten nur mit regulären Dateien. Quell- und Zielvorbedingungen sind SHA-256-gebunden. Veröffentlichung erfolgt über temporäre Dateien, erneute Hashprüfung, atomare Umbenennung und Directory-`fsync`. SSH bleibt BatchMode mit deaktivierten Forwardings. `repos/merges`, Secret-Roots und Browserprofil-Roots sind ausgeschlossen. Antworten enthalten Provenienz und Hashes, keine Inhalte.

## Browser und GUI

Browserworker starten einen separaten agenteneigenen Browser in einer transienten User-systemd-Unit. Sie übernehmen keine bestehenden Nutzertabs. CDP ist fest an `127.0.0.1` gebunden; Port und Profil werden geleast. Executables müssen absolut und explizit erlaubt sein.

GUI-Worker starten Xvfb und einen argv-basierten Kindprozess in derselben Unit. Es entsteht kein VNC-, Xpra- oder sonstiger Remote-Display-Listener. Xvfb läuft mit `-nolisten tcp`; Display und isolierte XDG-Verzeichnisse sind workergebunden. Hostvoraussetzung ist ein installiertes `Xvfb`.

## Privilegierter Broker

Der Rootpfad bleibt getrennt und templatebasiert. Das Checkout-Statuswerkzeug prüft die Installation nun ohne MCP-Paket und gibt keine Inhalte aus. Standardaktionen bleiben deaktiviert. Die tatsächliche Rootinstallation bleibt eine explizite Hostoperation nach `privileged-broker-bootstrap.md`; ein generischer Root-Shell-Pfad wurde nicht eingeführt.

## Live-Cutover

Vor einem Deployment sind die Live-Policy um die neuen Capabilities zu ergänzen, gewünschte Reconcile-Units zu installieren, Xvfb bereitzustellen und der Connector-Tool-Snapshot zu aktualisieren. Bis dahin bleibt die laufende Runtime unverändert.

## Vollprofil

`trusted-owner` ist die kanonische Betriebsform für maximale Funktionalität.
Die neuen Capability-Namen werden im Operator-Kern ausdrücklich durchgereicht;
damit funktionieren Ressourcen-, Artefakt-, Browser- und GUI-Werkzeuge nicht
nur im Contract, sondern auch zur Laufzeit. Namensbasierte Verbote gelten im
Vollprofil nicht.
