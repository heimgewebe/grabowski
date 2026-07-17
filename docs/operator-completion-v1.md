# Operator Completion v1

Dieser Slice ergänzt den Control-Plane-Kern um die verbleibenden unprivilegierten Betriebsbausteine. Backup und Recovery-Evidenz sind ausdrücklich nicht Teil dieses Changes.

## Ressourcen und Tasks

`grabowski_resources` verwaltet persistente, typisierte Leases für Repositories, Pfade, Ports, Dienste, Browserprofile und Displays. Die SQLite-Datenbank verwendet WAL, `synchronous=FULL`, restriktive Rechte und atomare Mehrfachbelegung. Persistente Tasks erwerben deklarierte Leases vor Start oder Resume.

Bei einem terminalen Taskzustand ist nicht mehr der Taskdatensatz die erste Autorität. Der Ressourcen-Writer widerruft in einer `BEGIN IMMEDIATE`-Transaktion alle Leases des kanonischen `task:<id>`-Owners und persistiert denselben terminalen Übergang samt vollständiger Lease-Beobachtung, Projektionshash und Beobachtungshash. Erst danach wird der Taskdatensatz als Projektion aktualisiert und ein hashgebundenes Lifecycle-Receipt geschrieben. Abstürze zwischen diesen Phasen hinterlassen höchstens eine veraltete Projektion: Status-, Listen-, Reconcile-, Resume- und Delegationspfade reparieren sie deterministisch aus dem Ressourcenübergang. Ein älterer Row-first-Zustand wird umgekehrt erkannt, in die Ressourcenautorität übernommen und dabei von noch lebenden Leases bereinigt. Nach einer Terminalisierung kann derselbe Task-Owner keine neuen Leases erwerben.

Merge-Delegation und Terminalisierung werden über eine kurzlebige Task-Autoritätsadoption im selben Ressourcen-Writer serialisiert. Gewinnt der Merge zuerst, blockiert Terminalisierung bis Cleanup oder spätestens bis zur delegationsgebundenen Ablaufzeit. Gewinnt Terminalisierung zuerst, sind alle Task-Leases widerrufen und weitere Merge-Adoptionen blockieren. Das Lifecycle-Receipt bindet Transition, Taskprojektion, angeforderte Ressourcen, sämtliche vorgefundenen Owner-Leases, tatsächlich widerrufene und fehlende Schlüssel sowie Recovery-Status und Zeitpunkte; private Lease-Metadaten werden nicht ausgegeben.

`grabowski_task_reconcile` gleicht Taskdatensätze mit User-systemd-Units ab. Der Legacy-Einstieg bleibt als Kompatibilitätspfad erhalten, führt aber nur noch Zustandsabgleich und Lease-Pflege aus; `auto_resume=True` wird als deaktivierter Legacy-Pfad markiert und startet keine Prozesse. Wiederanlauf erfolgt ausschließlich über den expliziten Resume-Pfad mit Begründung und Bound. Beispiel-Units verwenden periodisch `--mode refresh`.

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
