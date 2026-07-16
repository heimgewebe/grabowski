# Juno iPad Agent v1

## Zweck

Der Juno iPad Agent macht ein bewusst gestartetes Juno-Skript über das private
Tailscale-Netz als Grabowski-Ausführungsknoten erreichbar. Er führt beliebigen
Python-Code mit genau den Rechten des laufenden Juno-Prozesses aus.

Das bedeutet:

- vollständige Python-Ausführung innerhalb der Juno-Sandbox,
- Zugriff auf Juno-Dateien und ausdrücklich freigegebene Dokumentordner,
- Zugriff auf Juno- und iPad-APIs, soweit iPadOS die jeweilige Berechtigung
  erteilt hat,
- kein Root-Zugriff auf iPadOS,
- kein automatischer Zugriff auf andere App-Sandboxes,
- keine Garantie für dauerhafte Hintergrundausführung.

Der Agent ist kein Produktionsserver. Er ist ein mobiler, sitzungsgebundener
Worker, Testknoten und Sensorzugang.

## Dateien

- `tools/juno/juno_ipad_agent.py`: Agent für Juno auf dem iPad
- `tools/juno/juno_job_client.py`: signierender Client auf dem heim-pc
- `juno_ipad_agent.key`: bei der einmaligen Kopplung lokal erzeugter gemeinsamer Schlüssel, niemals einchecken
- `grabowski_workspace/`: lokaler Arbeits-, Job- und Auditbereich auf dem iPad

## Start auf dem iPad

1. `juno_ipad_agent.py` auf dem iPad in einen eigenen Ordner legen.
2. Den Agent in Juno öffnen und starten.
3. Die Tailscale-Verbindung aktiv lassen.
4. Beim ersten Start wartet der Agent einmalig auf die Kopplung vom heim-pc.
5. Auf dem heim-pc den Client mit `pair` ausführen.

Der Schlüssel wird dabei im Arbeitsspeicher erzeugt und über den verschlüsselten
Tailscale-Pfad an den ungekoppelten Agenten übermittelt. Auf beiden Geräten wird
er anschließend als private Datei gespeichert. Eine Schlüsseldatei muss nicht
über Chat, Taildrop oder Zwischenablage transportiert werden.

Standardbindung:

```text
0.0.0.0:8765
```

Unabhängig von dieser Socket-Bindung akzeptiert der Handler nur Quelladressen
aus dem Tailscale-IPv4-/IPv6-Bereich sowie Loopback für lokale Tests. Direkte
Anfragen aus WLAN oder öffentlichem Internet werden vor Health- und
Authentifizierungslogik mit HTTP 403 abgewiesen. Die einmalige Kopplung wird
zusätzlich nur von der fest gebundenen heim-pc-Tailscale-IP `100.68.88.111`
akzeptiert.

Der lokale Stoppschalter bleibt die Stopptaste in Juno. Zusätzlich existiert
ein signierter Shutdown-Endpunkt.

## Aufruf vom heim-pc

Der Client liest standardmäßig:

```text
~/.config/grabowski/secrets/juno-ipad-agent.key
```

und verbindet sich mit:

```text
http://100.111.206.65:8765
```

Beispiele:

```bash
python3 tools/juno/juno_job_client.py health
python3 tools/juno/juno_job_client.py pair
python3 tools/juno/juno_job_client.py run /pfad/auftrag.py --timeout 60
python3 tools/juno/juno_job_client.py list --limit 20
python3 tools/juno/juno_job_client.py status job-...
python3 tools/juno/juno_job_client.py shutdown
```

Ein Auftrag kann ein JSON-kompatibles Ergebnis über die vorbelegte Variable
`GRABOWSKI_RESULT` liefern:

```python
print("Prüfung läuft")
GRABOWSKI_RESULT = {
    "status": "ok",
    "workspace": str(GRABOWSKI_WORKSPACE),
    "metadata": GRABOWSKI_METADATA,
}
```

Vorbelegte Namen:

- `GRABOWSKI_JOB_ID`
- `GRABOWSKI_WORKSPACE`
- `GRABOWSKI_METADATA`
- `GRABOWSKI_RESULT`

## Protokoll

### Offen beziehungsweise einmalig gekoppelt

- `GET /health`
- `POST /v1/pair` nur im ungekoppelten Zustand und nur von `100.68.88.111`

Der Health-Endpunkt enthält keine Geheimnisse. Er belegt nur Laufzeit,
Plattform, Arbeitsbereich, Kopplungszustand und den ausdrücklich aktivierten
Ausführungsmodus. `POST /v1/pair` akzeptiert exakt einen 32-Byte-Schlüssel. Eine
Wiederholung mit demselben Schlüssel ist idempotent; ein anderer Schlüssel wird
nach erfolgreicher Kopplung abgewiesen.

Ist bereits eine private kanonische heim-pc-Schlüsseldatei vorhanden, verwendet
der Client sie für die Kopplung und verändert sie nicht. Andernfalls schreibt er
den neuen Schlüssel zuerst create-only in eine private Pending-Datei. Erst nach
erfolgreicher oder idempotent bestätigter Kopplung wird diese atomar zur
kanonischen Schlüsseldatei befördert. Bei einem unklaren Transportausgang bleibt
die Pending-Datei für einen identischen Retry erhalten. `--replace-secret` ist
ausschließlich für einen bewusst vorbereiteten Schlüsselwechsel vorgesehen.

### Signiert

- `POST /v1/jobs`
- `GET /v1/jobs?limit=N`
- `GET /v1/jobs/<job-id>`
- `POST /v1/shutdown`

Jede signierte Anfrage trägt:

- Unix-Zeitstempel,
- einmalige Nonce,
- SHA-256 des Bodys,
- HMAC-SHA-256 über Methode, Pfad einschließlich Query, Zeitstempel, Nonce und
  Body-Hash.

Akzeptiert werden nur Zeitstempel innerhalb von 90 Sekunden. Bereits verwendete
Nonces werden während der laufenden Sitzung abgewiesen. Job-IDs sind zusätzlich
create-only; derselbe Auftrag wird nicht still überschrieben oder erneut
verwendet.

Tailscale stellt die Netzabschottung und Transportvertraulichkeit bereit. Das
HMAC bindet Absender, Inhalt und Frische der Anfrage. Der HTTP-Dienst selbst
terminiert kein TLS.

## Persistenz und Belege

Je Job entstehen unter `grabowski_workspace/jobs/<job-id>/`:

- `request.json`
- `status.json`
- `result.json` nach terminalem Abschluss

`audit.jsonl` enthält append-only Ereignisse mit Job-ID, Code-Hash, Zustand,
Zeitpunkten und Resultat-Hash. Der Schlüssel wird weder im Audit noch in einem
Jobbeleg gespeichert.

Nach einem Neustart werden vorhandene Jobs ohne terminales Resultat als
`abandoned_after_restart` abgeschlossen. Sie werden nicht automatisch erneut
ausgeführt.

## Grenzen des Vollzugriffs

Der Agent führt absichtlich beliebigen Code im eigenen Prozess aus. Daraus
folgt:

- Ein Auftrag kann Dateien im erreichbaren Juno-Bereich lesen, verändern oder
  löschen.
- Ein Auftrag kann Netzwerkzugriffe ausführen.
- Ein Auftrag kann Juno-Geräte-APIs ansprechen, wenn Berechtigungen bestehen.
- Ein Auftrag kann den Agent-Prozess beschädigen oder beenden.
- Ein Auftrag kann den Auditbereich verändern, weil echte Prozessisolation auf
  iPadOS in Juno nicht bereitgestellt wird.

Code-Ausführung ist seriell, nicht parallel. stdout und stderr werden jeweils
auf 256 KiB begrenzt. Code ist auf 384 KiB begrenzt; Requests auf 512 KiB.

Der Timeout ist **kooperativ für ausgeführten Python-Code**. Reine
Python-Schleifen werden über Tracing abgebrochen. Ein blockierender nativer
Aufruf, eine C-Erweiterung, ein Systemdialog oder ein Netzaufruf ohne eigenen
Timeout kann nicht zuverlässig unterbrochen werden. In diesem Fall bleibt die
Juno-Stopptaste der harte Abbruchpfad.

## Schlüsselwechsel

1. Agent stoppen.
2. `juno_ipad_agent.key` auf dem iPad kontrolliert entfernen.
3. Agent neu starten; er wechselt in den ungekoppelten Zustand.
4. Auf dem heim-pc `pair --replace-secret` ausführen.
5. Einen signierten Testjob ausführen.
6. Eventuelle alte Pending-Dateien nur nach erfolgreichem Readback entfernen.

Der Schlüssel darf nicht in Repository, Kommandozeile, URL, Chat, Log oder
Screenshot erscheinen.

## Geeignete Aufgaben

- iPad-spezifische API- und Netzdiagnosen
- Weltgewebe-Feldaufnahme und GeoJSON-Erzeugung
- lokale Bild-, Daten- und Geometrieanalyse
- RepoLens- und Parser-Tests direkt auf iPadOS
- Sensor-, Standort- oder Bluetooth-Experimente mit expliziten iPad-Rechten
- Notfallanalyse, wenn der Knoten bewusst gestartet wurde

Nicht als alleinige Grundlage geeignet:

- unbeaufsichtigte Dauerüberwachung
- kritische Produktionsdeployments
- Recovery, die ohne sichtbare Juno-Sitzung garantiert funktionieren muss
- harte Ausführungsisolation gegen bösartigen Jobcode
