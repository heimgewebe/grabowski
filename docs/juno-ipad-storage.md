# Juno iPad Storage Scopes v1

## Ziel und Grenze

Der Storage-Scope-Vertrag macht alle **regulär vom Nutzer ausgewählten**
iPadOS-Dateiordner für den Juno-Knoten nutzbar. Er erweitert nicht die
Berechtigungen von Juno und umgeht keine App-Sandbox.

„Das gesamte iPad“ bedeutet in diesem Vertrag deshalb:

- vollständige, typisierte Nutzung der Juno-eigenen beschreibbaren Bereiche,
- dauerhafte Aufnahme aller Ordner, die iPadOS Juno über den System-Dateidialog
  regulär freigibt,
- belegte Klassifikation aller übrigen Bereiche als intern, auswahlpflichtig,
  sitzungsgebunden oder nicht zugänglich.

Nicht umfasst sind insbesondere private Container anderer Apps,
iPadOS-Systembereiche, fremde Schlüsselbunde, nicht separat freigegebene Fotos,
Kontakte, Nachrichten, Safari-Daten und das Root-Dateisystem.

## Architektur

Die Aufnahme besteht aus zwei getrennten Schritten:

1. `tools/juno/juno_storage_grant.py` läuft sichtbar und interaktiv in Juno.
   Es öffnet den iPadOS-Systemdialog und nimmt genau einen vom Nutzer gewählten
   Ordner auf. Das Skript wartet nicht blockierend auf den Dialog; Auswahl,
   Abbruch und lokale Bestätigung laufen über den iPadOS-Delegate zurück.
2. Die typisierten Grabowski-Werkzeuge lösen die gespeicherte Freigabe später
   im Juno-Agenten auf und führen ausschließlich die jeweils erklärte,
   begrenzte Dateioperation aus.

Das interaktive Skript speichert eine iPadOS-`security-scoped bookmark`. Das ist
eine von iPadOS erzeugte, persistierbare Referenz auf den ausgewählten Ordner.
Die Referenz enthält keine von Grabowski erfundene Berechtigung; sie ist nur so
weit wirksam, wie der Dokumentanbieter und iPadOS den Zugriff erlauben.

Grant-Dateien liegen privat unter:

```text
<Juno-Python-Home>/Library/Application Support/GrabowskiJunoAgent/storage-grants/
```

Vertrag:

- Verzeichnis: Eigentümer ist der Juno-Prozessnutzer, Modus exakt `0700`.
- Grant-Datei: reguläre Datei, genau ein Hardlink, gleicher Eigentümer, Modus
  exakt `0600`.
- Bookmark-Bytes werden weder im Chat noch in Grabowski-Antworten oder Receipts
  ausgegeben.
- Jeder Grant besitzt eine ID, einen Bookmark-SHA-256 und einen separaten
  Evidence-SHA-256 über Pfad-, Provider- und Erstellungsmetadaten.
- Grant-Dateien sind create-only. Eine vorhandene Grant-ID wird nicht ersetzt.

## Lokale Ordneraufnahme auf dem iPad

Die Aufnahme erfolgt einzeln, damit Zustimmung und Beleg eindeutig bleiben:

1. Juno-Agent stoppen, falls er die interaktive Ausführung blockiert.
2. `juno_storage_grant.py` in Juno öffnen und starten.
3. Im Systemdialog genau einen Ordner auswählen.
4. Die iPadOS-Freigabe bestätigen.
5. Das Skript darf bereits beendet erscheinen; den Systemdialog dennoch
   abschließen und auf die lokale Meldung `Freigabe gespeichert` mit Grant-ID
   warten.
6. Juno-Agent erneut starten.
7. Grabowski führt anschließend Grant-, Lese-, Schreib- und Neustartprüfung aus.

Sinnvolle Reihenfolge:

1. iCloud Drive / Downloads,
2. „Auf meinem iPad“ / gewünschter Projektordner,
3. Working Copy oder weitere sichtbare Dokumentanbieter,
4. externe Datenträger,
5. in Dateien eingebundene Netzwerkfreigaben.

Ein Anbieter wird nur dann als dauerhaft aufgenommen gewertet, wenn sein Grant
nach Juno-Neustart erneut aufgelöst werden kann. Ein iPad-Neustart ist die
stärkere, separate Persistenzprüfung.

## Typisierte Werkzeuge

Alle Werkzeuge sind an die exakte Agent-Instanz (`started_at`) und eine frische
Sitzungseskalation gebunden. Auch logisch lesende Aktionen gelten technisch als
Mutation, weil sie einen Juno-Job und lokale Receipts erzeugen.

### Inventar und Berechtigung

- `ipad_capability_manifest`: Juno-Sandbox, persistente interne Pfade und private
  Grant-Zusammenfassungen.
- `ipad_storage_inventory`: löst alle gültigen Grants auf und meldet aktuelle
  Lesbarkeit und Beschreibbarkeit.
- `ipad_storage_grant_status`: liest einen oder alle Grant-Belege ohne
  Bookmark-Bytes.
- `ipad_permission_probe`: öffnet genau einen Grant und prüft Rechte ohne
  Schreibzugriff.

### Dateioperationen

- `ipad_file_stat`: Metadaten eines exakten Pfads.
- `ipad_directory_list`: nur unmittelbare Einträge, keine Rekursion; Ausgabe
  und tatsächlich durchlaufene Provider-Einträge sind getrennt hart begrenzt.
  Eine am Scan-Limit abgeschnittene Teilansicht wird ausdrücklich markiert.
- `ipad_file_read`: eine reguläre Datei bis **176 KiB**, mit SHA-256. Die
  Rohdaten werden zu 240.300 Base64-Bytes; selbst bei maximal erlaubten
  Provider- und Pfadmetadaten bleiben mindestens 16 KiB Reserve unter dem
  256-KiB-Ergebnisvertrag des Juno-Agenten. 220–240 KiB Rohdaten wären deshalb
  gerade nicht transportsicher.
- `ipad_file_create`: nur create-only; Vorzustand muss `absent` sein; Payload
  wird vor und nach der Übertragung gehasht und ist auf **176 KiB** begrenzt.
- `ipad_file_replace`: gleichverzeichnisgebundener Ersatz bis **176 KiB** nur bei passendem
  SHA-256 des vorhandenen Inhalts und passendem Payload-SHA-256; der Vorinhalt
  wird unmittelbar vor dem Umschalten erneut geprüft. Der Grant-Wurzelpfad und
  alle Elternverzeichnisse bleiben während Stat, List, Read, Create und Replace
  über Dateideskriptoren festgehalten; ein nachträglicher Symlink-Tausch ändert
  daher nicht das Operationsziel. Root-Öffnungen vergleichen vor und nach dem
  Öffnen Geräte-, Inode-, Typ-, Eigentümer-, Link- und Änderungsidentität und
  brechen bei Abweichung ab. Ein nicht unterstütztes descriptor-gebundenes
  `replace` fällt nicht auf pfadbasierte Semantik zurück. Nach einem fehlgeschlagenen
  Create oder Replace wird ein verbliebener Eintrag identifiziert und mit einer
  `cleanup_reference` gemeldet, aber nicht automatisch per Namen gelöscht: POSIX und
  die Python-API bieten kein atomisches "unlink nur bei identischer Inode". Ein
  `stat`-geprüftes anschließendes `unlink` hätte selbst wieder ein TOCTOU-Fenster und
  könnte eine inzwischen fremde Datei entfernen. Dokumentanbieter können außerdem
  abweichende Atomaritäts- und Dauerhaftigkeitsgarantien haben.

Nicht freigeschaltet:

- Löschen,
- Verschieben oder Umbenennen,
- rekursive Dateioperationen,
- Folgen von Symlinks,
- absolute oder aufwärts gerichtete Pfade,
- generischer Zugriff außerhalb eines exakten Grants.

## Bindungen jeder Schreibaktion

Ein Schreib-Receipt bindet mindestens:

- Agent-ID und exakte Agent-Instanz,
- Grant-ID und Grant-Evidence-SHA-256,
- erwarteten Provider-Hinweis,
- relativen Zielpfad,
- erwarteten Vorzustand beziehungsweise Vorinhalt-SHA-256,
- Payload-SHA-256,
- Job-ID, Code-SHA-256, Request-SHA-256 und Resultat-SHA-256.

Der Provider-Hinweis ist zunächst eine belegte Pfadklassifikation, keine
behauptete Herstelleridentität. Eine echte Provider-Identität darf erst
angegeben werden, wenn Juno/iPadOS sie zuverlässig liefert.

## Persistenzprüfung

Ein Grant gilt in Stufen:

1. **aufgenommen**: Systempicker, Bookmark-Erzeugung und unmittelbarer Readback
   waren erfolgreich.
2. **aktuell nutzbar**: Permission-Probe und Metadatenzugriff funktionieren.
3. **lesend belegt**: begrenzter Lesetest mit SHA-256 funktioniert.
4. **schreibend belegt**: create-only Sentinel und Hash-Readback funktionieren.
5. **Juno-persistent**: nach Beenden und Neustart von Juno erneut nutzbar.
6. **Geräte-persistent**: nach iPad-Neustart erneut nutzbar.

Da v1 keine Löschaktion veröffentlicht, wird eine Schreib-Sentinel-Datei nicht
remote entfernt. Sie muss entweder als klar benannte Belegdatei verbleiben oder
später durch eine gesonderte, ausschließlich auf exakt diesen Beleg gebundene
Cleanup-Aktion entfernt werden.

## Capability-Map

Jeder Eintrag enthält mindestens:

- `logical_name`
- `path`
- `provider`
- `exists`
- `readable`
- `writable`
- `persistent`
- `externally_granted`
- `verification_time`
- `evidence_hash`
- `limitations`

Die Map unterscheidet:

### Vollständig aufgenommen

Dauerhaft auflösbare Grants mit belegtem Lese- und Schreibzugriff nach den
geforderten Neustarts.

### Teilweise aufgenommen

Nur lesbare, sitzungsgebundene, offline befindliche oder erneut auswahlpflichtige
Provider.

### Nicht zugänglich

iPadOS-Systembereiche und private Daten anderer Apps ohne regulären Export- oder
Dokumentanbieterpfad.

Eine Prozentangabe darf nur Kategorien mit klar definiertem Nenner bewerten.
Sie ist keine Prozentangabe des physischen iPad-Dateisystems.

## Live-Ausgangsbefund vom 16. Juli 2026

Belegt wurden im damals laufenden Juno-Prozess:

- Juno-interne Documents-, Library-, Application-Support-, Python-Home-,
  Agent-State- und Workspace-Pfade: vorhanden, lesbar und beschreibbar,
- Cache und Temp: lesbar und beschreibbar, aber nicht als persistent gewertet,
- systemweites Mobile-Documents-Verzeichnis, Shared-App-Group-Wurzel und
  Media-Wurzel: vorhanden, für Juno direkt weder les- noch beschreibbar,
- noch keine extern aufgelöste Dokumentanbieterfreigabe,
- verfügbare iPadOS-Ordnerpicker-, Security-Scope- und Bookmark-Methoden,
- erfolgreiche Bookmark-Erzeugung und -Auflösung gegen Junos eigenen
  Dokumentordner.

Dieser Ausgangsbefund belegt die technische Mechanik, aber noch keine externe
Provider-Persistenz. Dafür ist mindestens eine sichtbare lokale Ordnerauswahl
und der anschließende Neustart-Readback erforderlich.
