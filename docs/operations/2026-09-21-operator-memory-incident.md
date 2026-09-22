# Untersuchung: Grabowski-Speicherwachstum und Hostausfall am 21. September 2026

Erstellt am 22. September 2026. Untersuchungsstand: 21. September 2026,
22:22 CEST (UTC+02:00). Ein gesonderter Nachtrag beschreibt die begrenzte
Live-Prüfung bei der Berichtserstellung. Dieser Bericht ist historische Evidenz,
keine aktuelle Betriebsfreigabe und kein ausgelieferter Fix.

## Ergebnis und Grenzen

Ein konkreter proportionaler Speicherverbrauch wurde isoliert: Der kalte
Runtime-Health-Pfad verifiziert die gesamte segmentierte Audit-Kette und hält
historische Segmentdaten im Speicher. Eine einzelne vollständige Verifikation
von rund 1,28 Millionen Datensätzen in 76 Archivsegmenten erreichte etwa
1,247 GiB Spitzen-RSS. Der bereits vorhandene Snapshot-Lesepfad prüfte später
eine vergleichbar große Kette bei etwa 145 MiB Spitzen-RSS.

Das erklärt einen erheblichen Speicherbedarf einzelner Reads. Es beweist noch
nicht den vollständigen Mechanismus des zuvor gemeldeten Wachstums auf rund
50 GiB. Insbesondere sind gleichzeitige Reads, vollständige JSON-Projektionen
und die Lebensdauer ihrer Daten noch nicht als vollständige Ursache vermessen.

Im vorherigen Boot sind schwerer Memory Pressure und Swap-Reclaim-Störungen
belegt. Ein OOM-Kill des Operators oder der endgültige Ausfall-/Resetmechanismus
ist für diesen Boot nicht nachgewiesen. Die belegten OOM-Kills dort betreffen
einen anderen, auf 512 MiB begrenzten Dienst.

Die Untersuchung priorisierte Host-Sicherheit und Ursachenklärung. Am Ende
waren User- und System-Operator ohne Hauptprozess. Die User-Unit erhielt
Speichergrenzen und eine Startsperre; die bootaktivierte System-Unit blieb
ungeschützt. Weder Abschluss **A — behoben** noch vollständiger Abschluss
**B — sicher terminalisiert** war erreicht. Ein normaler Wiederanlauf wurde
nicht freigegeben.

## Quellen und Beleggrenzen

- Die Übergabe meldete zuvor etwa 49,8 GiB Operator-RSS sowie nach einem Reboot
  erneut etwa 8,44 GB Cgroup-Speicher nach neun Minuten. Diese Werte sind
  übernommener Kontext, keine in diesem Lauf wiederholten Messungen.
- Frische Betriebsbelege kamen aus systemd, Prozess-/Cgroup-Reads, dem lokalen
  persistenten Journal und unabhängigen `großer adler`-Beobachtungen.
- Boot-Forensik nutzte den vorhandenen lokalen Read-only-Zugang zu
  `journalctl --list-boots`, dem vorherigen Kernel- und Systemjournal sowie
  `last -x`. Die Auswertung des vorherigen Journals erfasste 479.874 Zeilen.
- Die begrenzten Diagnoseprozesse verwendeten das installierte Release des
  Commits `8b5431753923ff2dbc9d13badd6bd2eb34719742`.
- Während des Laufs wurde außerhalb dieser Untersuchung auf
  `385a2ac7e8812994d2aaeb03aa2d406deb2aa1af` gewechselt. Der betrachtete Diff
  betrifft Agent-Rollen, Bureau-Intake und zugehörige Tests; er ist kein RAM-Fix.
- Bureau-Kandidat `candidate-c913d4d46069032b7348ec21`, Event `17111`, hält die
  wesentlichen Befunde und offenen Arbeiten dauerhaft fest. Kandidatenaufnahme
  ist keine Task-Publikation oder Ausführungsfreigabe.

Die folgenden Zahlen sind eine redaktionelle Übertragung der beobachteten
Toolausgaben. Vollständige Journale, Audit-Inhalte und private Laufzeitdaten
werden nicht mit diesem Bericht veröffentlicht. Die Diagnoseausgaben wurden
nicht als separates unveränderliches Beweisbundle gesichert; der Bericht
behauptet deshalb keine nachträgliche lückenlose Reproduzierbarkeit aller
Hostbeobachtungen. Quellcodebezüge sind unten an einen exakten Commit gebunden.

## Boot-Forensik

Der vorherige aufgezeichnete Boot reicht am 21. September von 03:36:54 bis
20:36:28 CEST. Der nächste beginnt um 21:36:42 CEST.

| Beobachtung | Aussagekraft |
| --- | --- |
| OOM-Kills um 16:09:48, 19:31:02 und 19:36:35 | Jeweils `CONSTRAINT_MEMCG` für `grabowski-runtime-retention.service`, Limit 512 MiB; kein Beleg eines Operator-OOM-Kills. |
| Swap-Reclaim-Warnung um 20:32 und wiederholte Speicherknappheit | Schwerer Memory Pressure ist belegt. Journald meldet bis unmittelbar vor Journalende speicherbedingtes Flushen. |
| Timeouts und stark verzögerte Verarbeitung gegen Bootende | Mit Hostüberlastung vereinbar; keine eigenständige Kausalitätszuordnung. |
| Kein gefundener sauberer Shutdown-/Poweroff-/Suspend-Abschluss, keine gefundene Kernel-Panic | Der abschließende Mechanismus bleibt offen. Fehlende Journalzeilen beweisen keinen Stromverlust. |
| `last -x` mit Crash-Enden und späterem Reboot | Stützt einen nicht sauber dokumentierten Sitzungsabschluss, unterscheidet aber nicht die Ausfallursache. |

**Klassifikation:** Schwerer Memory Pressure ist belegt. Ob der Operator den
endgültigen Ausfall verursachte und ob Reset, Stromverlust oder ein anderer
Mechanismus den Boot beendete, bleibt unbestimmt. Die Root-Partition war bei
späteren Live-Reads etwa zu drei Vierteln belegt; ein volles Root-Dateisystem
wurde nicht festgestellt. Temperatursnapshots liefern keinen Beweis einer
thermischen Abschaltung.

Es wurden höchstens drei Hypothesen parallel geführt: Operator-bedingter
Memory Pressure, eine andere primäre Ausfallursache und ein unabhängiger
Recovery-/Autoritätsdefekt. Die gefundenen Retention-OOMs dürfen die erste
Hypothese nicht scheinbar bequem zum vollständigen Ausfallbeweis machen.

## Frischer Verlauf und Schutzmaßnahmen

Alle Zeiten dieser Tabelle beziehen sich auf den 21. September, CEST.

| Zeitpunkt | Beobachtung oder eigene Aktion |
| --- | --- |
| 21:55:42 | Adler findet entgegen dem Übergabestand einen laufenden User-Operator: Cgroup 1.807.892.480 Byte, RSS 1.493.984 KiB, hohe CPU-Last. |
| 21:56:32 | Cgroup 1.990.881.280 Byte und RSS 1.686.944 KiB: erneutes Wachstum innerhalb etwa 50 Sekunden. |
| 21:56:47–21:57:13 | Eigener Stopp über Grabowski; der Tooltransport bricht ab. Adler bestätigt anschließend beide Units ohne Hauptprozess. |
| 21:59:54 | Erneuter Start außerhalb der hier ausgeführten Aktionen. Die Initiatoridentität ist nicht bewiesen. |
| Vor 22:04:25 | Über Grabowski gesetzte Laufzeitgrenzen: 4 GiB RAM, 512 MiB Swap und konfigurierte CPU-Quota 100 %. Speichergrenzen wurden in systemd und Cgroup zurückgelesen. |
| 22:04:25 | Kernel belegt einen Memcg-OOM-Kill des User-Operators an der 4-GiB-Grenze. Der Defekt besteht fort; die Begrenzung greift. |
| 22:04:28 | Noch wirksames `Restart=on-failure` startet den Dienst erneut. |
| 22:05:39–22:05:47 | Erneuter eigener Stopp; Adler bestätigt beide Hauptprozesse als beendet. |
| 22:07:04 | Weiterer Start außerhalb dieses Laufs. |
| 22:08:57–22:09:27 | Die System-Unit scheitert wiederholt an der bereits vom User-Operator belegten Listeneradresse; `NRestarts=10`. |
| 22:11:36 | Neuer User-Prozess auf Release `385a2ac7e881`; Adler bestätigt die tatsächliche Prozessbindung. |
| Ab 22:13 | Dauerhafter User-Drop-in erstellt, zurückgelesen und User-Manager neu geladen. |
| 22:19:20 und 22:22:26 | Nach abschließendem Stopp bestätigt Adler User-Unit `inactive/dead` und System-Unit `failed`, jeweils `MainPID=0`. |

Ein Transportfehler wurde bei Stopps nicht als Wirkungsbeleg verwendet; erst
der unabhängige Readback entschied über den erreichten Zustand.

Der über Grabowski erstellte User-Drop-in
`grabowski-operator.service.d/95-incident-memory-containment.conf` setzte:

```ini
[Unit]
RefuseManualStart=yes

[Service]
Restart=no
MemoryMax=4G
MemorySwapMax=512M
CPUQuota=100%
```

Zum Abschluss wurden `RefuseManualStart=yes`, `Restart=no`, die beiden
Speichergrenzen und die deaktivierte User-Autostartbindung zurückgelesen.
Die CPU-Quota war konfiguriert; wegen des nicht gefundenen `cpu.max` wurde
keine wirksame CPU-Begrenzung behauptet. Der Drop-in ist Schadensbegrenzung,
kein Root-Cause-Fix. Eine spätere Rücknahme muss genau diesen Drop-in über
den autorisierten Writer bearbeiten, den Manager neu laden und den
Zielzustand zurücklesen; sie setzt ein bestandenes Wiederanlauf-Gate voraus.

Der letzte Host-Read um 22:22:35 zeigte etwa 47 GiB verfügbaren RAM,
206 MiB belegten Swap und Load 7,95 / 4,43 / 3,68. Der letzte Disk-Read lag
bei 74 % Root-Belegung. Ein lokaler Read fand keinen TCP-Listener des
Operators. Das ist ein zeitgebundener Abschlussstand, keine Dauerzusage.

## Isolierter RAM-Auslöser

Der relevante Pfad im untersuchten Release ist:

1. [`grabowski_runtime_health`](https://github.com/heimgewebe/grabowski/blob/8b5431753923ff2dbc9d13badd6bd2eb34719742/src/grabowski_read_surface.py#L1535)
   ruft `_verify_audit_log` auf.
2. [`_verify_audit_log_unlocked` und `_verify_audit_log`](https://github.com/heimgewebe/grabowski/blob/8b5431753923ff2dbc9d13badd6bd2eb34719742/src/grabowski_mcp.py#L4180)
   lesen die Kette unter einem gemeinsamen Audit-Lock.
3. [`_read_audit_chain_unlocked`](https://github.com/heimgewebe/grabowski/blob/8b5431753923ff2dbc9d13badd6bd2eb34719742/src/grabowski_mcp.py#L3995)
   verwendet standardmäßig `retain_verified_segment_data=True`. Bei kalter
   Verifikation bleiben die historischen Segmentbytes in der Komponentenliste.
4. [`_audit_records_snapshot`](https://github.com/heimgewebe/grabowski/blob/8b5431753923ff2dbc9d13badd6bd2eb34719742/src/grabowski_mcp.py#L4560)
   materialisiert darüber hinaus die vollständigen JSON-Datensätze. Das ist ein
   zusätzlicher Kandidat für Verstärkung bei Projektionen und Parallelität,
   aber noch kein gemessener vollständiger 50-GiB-Erklärungsweg.

Der vorhandene
[`capture_verified_audit_snapshot`](https://github.com/heimgewebe/grabowski/blob/8b5431753923ff2dbc9d13badd6bd2eb34719742/src/grabowski_audit_query.py#L397)
verifiziert den veränderlichen Kopf unter Lock, anschließend unveränderliche
Vorgänger außerhalb dieses Locks und mit
`retain_verified_segment_data=False`. Er bietet einen bestehenden Ansatz für
eine Reparatur ohne neue Audit-Architektur. Die Integritäts- und
Fail-closed-Eigenschaften müssen bei einer Umstellung erhalten bleiben.

### Begrenzte Read-only-Proben

Die Proben liefen in kurzlebigen Prozessen des exakt gebundenen alten Releases,
ohne produktiven Service-Neustart. Für die stdio-Probe galten 2 GiB
Adressraumlimit, 20 Sekunden CPU-Zeit und 25 Sekunden Wallclock-Limit.
Die direkten Verifikationsproben waren auf 2 GiB Adressraum, 40 Sekunden
CPU-Zeit und 45 Sekunden Wallclock begrenzt. Es wurden keine vollständigen
Audit-Datensätze ausgegeben.

| Probe | Datenmenge / Ergebnis | RSS / Laufzeit |
| --- | --- | --- |
| stdio-Initialisierung, danach etwa drei Sekunden idle | Initialisierung erfolgreich; noch kein Health-Aufruf | Etwa 76.764 KiB RSS, im kurzen Idle-Fenster stabil |
| Einzelner kalter `runtime_health`-Aufruf | Keine erfolgreiche Health-Antwort vor Begrenzung | Wachstum auf 1.135.028 KiB innerhalb etwa 23 Sekunden; Prozess durch CPU-Zeitbegrenzung beendet |
| Direkter kalter `_verify_audit_log` | Gültige Kette; 1.280.752 Datensätze, 76 Archivsegmente | Baseline 59.328 KiB, Spitze 1.307.948 KiB; 24,065 Sekunden |
| Erster Snapshot-Vergleich bei laufendem Operator | `Audit lock acquisition timed out` | Fehlgeschlagener Vergleich, kein Erfolgsbeleg |
| Erneuter kalter Snapshot-Read nach Operator-Stopp | Gültige Kette; 1.281.062 Datensätze, 76 Archivsegmente; 8.181.087 Byte im Snapshot gehalten | Baseline 60.324 KiB, Spitze 148.624 KiB; 22,739 Sekunden |

Die beiden erfolgreichen direkten Reads stammen aus unterschiedlichen
Zeitpunkten; die Kette war inzwischen um 310 Datensätze gewachsen. Sie bilden
keinen Vergleich auf identischem Snapshot und keinen Langzeit-/Concurrency-Test.
Sie belegen dennoch vollständige Verifikation einer vergleichbar großen Kette
mit wesentlich geringerer Spitzen-RSS im vorhandenen Snapshot-Pfad.

Metadata-Reads großer Task-/Resource-SQLite-Dateien fanden keine einzelne
riesige rekursive Datensatzstruktur als Erklärung. Das schließt andere
Collector-, Cache- oder Task-Lebensdauerprobleme nicht aus. Wiederholte
Audit-Lock-Timeouts in den Dienstlogs bleiben ein weiterer relevanter Befund.

## Recovery- und Broker-Befund

Die ursprünglich gemeldeten fehlenden Broker-Artefakte müssen nach
Ausführungskontext getrennt werden:

| Kontext | Befund |
| --- | --- |
| Primärer Host | Root-eigener Broker, Konfiguration, Socket und Bootstrap-Recovery-Helper vorhanden; primärer Broker-Status meldete Bereitschaft. Lokaler Journal-Read funktioniert ohne diesen privilegierten Pfad. |
| Maulwurf-Fallback | Dort fehlen Broker-Artefakte, Backup-Sentinel und kanonische Recovery-Evidenz; der abgefragte Backup-Timer ist nicht vorhanden. Recovery bleibt fail-closed. |
| Fallback-Recovery-Probe | Zusätzlich durch `local recovery repository operation lock is unavailable` blockiert; keine Reparatur oder Lock-Übernahme durchgeführt. |

Auf dem primären Host sind gleichnamige User- und System-Units vorhanden.
Die System-Unit blieb `enabled`, mit `Restart=on-failure`, ohne RAM-/Swap-Limit
und ohne den User-Drop-in. Damit besteht ein Reboot-Risiko trotz gestoppter
Prozesse am Untersuchungsende.

Der dokumentierte allgemeine Root-Broker-Pfad verlangt die vom
Root-Systemmanager beobachtete exakte `MainPID` der **System-Unit**.
Ein User-Operator oder ein Terminal-Kind besitzt diese Autorität nicht;
siehe [Broker-Vertrag](../privileged-broker-bootstrap.md). Das ist eine
Autoritäts-/Recovery-Lücke in der beobachteten Konstellation, kein Anlass,
den unsicheren System-Operator nur zum Erlangen von Root-Rechten zu starten.
Es wurden weder Broker-Dateien ad hoc kopiert noch Sicherheitsgates umgangen.

## Offene Arbeiten und Bureau-Bindung

Der vorhandene Kandidat `candidate-c913d4d46069032b7348ec21`
("Bound Grabowski operator memory growth and audit-lock contention") wurde
über den primären Grabowski-Writer von Event `16040` auf Event `17111`
fortgeschrieben. Der Readback nach dem Stopp bestätigte Event `17111`,
Status `observed`, Assessment `promote`. **Ein veröffentlichter Folgetask ist
damit noch nicht belegt.** Die letzte erfolgreiche Snapshot-Gegenprobe fand
nach diesem Event statt und wird mit diesem Bericht ergänzt.

| Offene Arbeit | Bezug / benötigter Abschlussbeleg |
| --- | --- |
| Audit-Health und vollständige Projektionen speicherschonend gestalten | Bestehender RAM-Kandidat; Verifikationssemantik erhalten, konkrete Speicher-Lebensdauer und Parallelität messen. |
| Regression für kalten Start und konkurrierende Reads | Repräsentative segmentierte Kette; RSS, Cgroup, Swap, CPU und Lock-Wartezeit über mehrere Messpunkte; echte Langzeitstabilität. |
| User-/System-Konflikt und rebootfesten Ressourcenschutz beheben | Autorisierter Root-Recovery-Pfad ohne Start eines unbegrenzten Operators; unabhängiger systemd-/Cgroup-Readback. |
| Restart-Initiatoren nachvollziehbar machen | Bestehender Kandidat `candidate-0234668d8cec6f729a291f02`; Zeitpunkt allein identifiziert keinen Akteur. |
| Maulwurf-Kontext, Recovery-Voraussetzungen und Repository-Lock klären | Bestehender verwandter Kandidat `candidate-2cadb98f4e280f34fc5ef508`; Primär- und Fallbackzustand getrennt halten, keine fremden Locks übernehmen. |
| Verlässlichen Read-only-Journalzugang im Operatorpfad erhalten | Lokaler Zugang ist bereits vorhanden; verwandter Adler-Log-Kandidat `candidate-65a188ffca3a2ba70a63a3b1` berücksichtigt fehlende Anwendungsjournal-Einträge. |
| Endgültigen Boot-Ausfallmechanismus und verbleibende Publikation klären | Vorhandene lokale Boot-Evidenz weiter nutzen; Kandidatenprüfung und Veröffentlichung ohne Dubletten abschließen. |

Zusätzlich wurden die bestehenden Registry-Referenzen
`GRABOWSKI-OPERATOR-SURFACE-V1-T086` (Audit-Pagination),
`GRABOWSKI-OPERATOR-SURFACE-V1-T110` (Reconcile-/Watchdog-Last),
`GRABOWSKI-OPERATOR-SURFACE-V1-T030` (Broker-/Recovery-Frische) und
`HEIMGEWEBE-RESILIENZ-V1-T010` (Runtime-/Broker-Recovery) gefunden.
Diese Referenzen ersetzen keinen frischen Bureau-Status oder eine Zuweisung
neuer Arbeit an bereits abgeschlossene Tasks.

Vor einer normalen Startfreigabe fehlen weiterhin: ein überprüfter Fix oder
belastbar beherrschter Auslöser, Schutz in der tatsächlich gestarteten Unit,
ein begrenzter Test desselben Start-/Health-Pfads und mehrere unabhängige
Prozess-/Cgroup-Messpunkte mit stabilem Verbrauch. Ein grüner Health-Status
oder ein Speicherlimit allein genügt nicht. Die `gegner`-Gegenprobe endete
für diese Freigabe mit **PARK/STOP**; sie ist keine externe Evidenzquelle und
kein unabhängiges Review.

## Nachtrag zur Berichtserstellung am 22. September

Die für diesen Dokumentations-PR ausgeführte begrenzte Live-Prüfung fand
Grabowski wieder erreichbar. Adler beobachtete um 06:04 CEST einen seit
05:59:18 laufenden User-Prozess auf Release `385a2ac7e881`, mit
1.436.585.984 Byte Cgroup-Speicher und 682.140 KiB RSS. Ein systemd-Read
bestätigte weiterhin 4 GiB RAM-Limit, 512 MiB Swap-Limit und `Restart=no`,
aber jetzt `RefuseManualStart=no`.

Dieser Zustand unterscheidet sich vom Abschlussstand des Vorabends. Die
Berichtserstellung hat weder diesen Start noch die Änderung der Startsperre
ausgeführt oder deren Urheber bestimmt. Eine einzelne neue Messung beweist
keinen RAM-Fix und keine sichere Wiederanlauffreigabe. Der PR dokumentiert
die Untersuchung; er ändert weder Laufzeitcode noch Dienste oder Deployment.
