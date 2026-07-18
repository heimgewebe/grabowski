# Coding-Agent-Routing v2 — adaptive Qualitätssteuerung

## Kanonische Regel

Der Router verteilt keine Arbeit nach Anbieterquote. Er wählt zuerst eine ausreichend starke Route, dann Aufgabenfit, Effort, Harness, erwartete Nacharbeit, Kontingent und Latenz. Providerunabhängigkeit ist ausschließlich ein Review-Gate.

## Hierarchie

- **S:** GPT-5.6 Sol high und Claude Fable 5. Sol xhigh ist eine teure Eskalationsroute derselben Spitzenklasse.
- **A:** Claude Opus 4.8, Sol medium, Terra high, Sonnet 5 high und Grok 4.5 high. Opus ist für Review, Urteil und Root-Cause-Analyse besonders stark, aber kein allgemeiner Spitzen-Writer.
- **B:** Terra medium, Luna high, Sonnet 5 medium und Gemini 3.1 Pro high.
- **C:** Flash-, GPT-OSS-, ältere Agy-Claude- und lokale/unklare Fallbacks. Kosten- oder Auth-Wege mit unklarer Nullkosten-Garantie bleiben gesperrt.

Jules ist ein verwalteter Remote-Harness. Die interne Platzhalteridentität behauptet kein zugrunde liegendes Modell.

## Gleicher Spitzenrang ohne künstliche Mischung

Sol high und Fable teilen denselben Startprior. Für denselben Aufgabentyp können beide als Co-Primärroute erscheinen. Das ist keine Erlaubnis für zwei parallele Writer. Die konkrete Einzelroute ergibt sich aus Aufgabenprofil, Effort, Harness, belastbaren lokalen Ergebnissen, Nacharbeit und Kontingent. Reine Run-Zahlen oder Anbieteranteile haben keinen Einfluss.

## Selbstlernen

Lokale Ergebnisse überschreiben Hersteller- und Benchmark-Priors erst ab fünf vergleichbaren Läufen derselben Route und Aufgabenklasse. Verwendet werden First-Pass-, CI- und Merge-Erfolg, Nacharbeit, Rollbacks, falsche Behauptungen, Scope-Verstöße, Laufzeit und Kontingentverbrauch. Zugangstests werden getrennt gespeichert und nie als Qualitätserfolg gezählt. Bayesianische Schrumpfung und harte Kappen verhindern, dass wenige Läufe die Hierarchie umwerfen.

## Sicherheit und Kosten

Automatische Ausführung bleibt deaktiviert. Empfehlungen sind beratend, ein einzelner mutierender Writer bleibt Pflicht, kritische Reviews müssen aus einer anderen Providerfamilie stammen. PAYG, API-Key- und unbekannte Kostenpfade bleiben gesperrt.

Statische Kosten-, PAYG-, Reserve- und Parallelitätspolitik stammt ausschließlich aus dem versionierten Katalog. Der dynamische Laufzeitstatus darf nur Verfügbarkeit, Restquote, Cooldown, aktive Sitzungen und Verifikationszeit ergänzen. Unbekannte Felder, ungültige Werte oder zukünftige Zeitstempel sperren den betroffenen Pool fail-closed.

Kontingentpools bilden eine Elternkette. Der Router erweitert jeden an einer Route genannten Pool automatisch um alle Elternpools und prüft jeden Pool genau einmal. Sperre, Erschöpfung, Cooldown, Reservegrenze, Parallelitätsgrenze oder Kostenunsicherheit eines Elternpools sperrt damit auch jede Kindroute, selbst wenn der Elternpool in der Route nicht zusätzlich ausgeschrieben ist.

## Automatische Katalogaktualisierung

Der Live-Katalog verfällt nach 3.600 Sekunden fail-closed. `grabowski-coding-agent-probe.timer` erneuert ihn deshalb alle 45 Minuten mit höchstens drei Minuten Jitter. Der Timer startet ausschließlich den bestehenden Metadatenpfad `agent-route probe`; er ruft keine Empfehlungs-, Beobachtungs- oder Ausführungsfunktion auf.

`coding_agent_probe_scheduler.py` verlangt zusätzlich einen privaten SHA-256-Pin für die konkrete `agent-route`-Datei, öffnet diese ohne Symlink-Folge und führt beide Unterbefehle über denselben offenen Dateideskriptor aus. Danach entfernt es bekannte API-Key-Variablen aus der Kindprozessumgebung, hält eine nichtblockierende exklusive Sperre, begrenzt Laufzeit und Ausgabemenge und verlangt anschließend einen separaten `agent-route status`-Readback. Vorherige `history`-Daten müssen bytewertgleich in der JSON-Struktur erhalten bleiben. Der Router schreibt den eigentlichen State atomar; der Scheduler publiziert zusätzlich einen privaten atomaren Erfolgs- oder Fehlerbeleg. Ein gescheiterter Probe-Lauf autorisiert keine Ausführung und lässt den Router nach Ablauf der Freshness weiterhin fail-closed.

Die versionierten Installationsquellen sind:

- `tools/coding_agent_probe_scheduler.py`
- `systemd/grabowski-coding-agent-probe.service.example`
- `systemd/grabowski-coding-agent-probe.timer.example`

Die Live-Ziele liegen unter `%h/.local/libexec/grabowski/` und `%h/.config/systemd/user/`; der aktuelle Router-Pin liegt privat unter `%h/.config/grabowski/coding-agent-probe-scheduler-router.sha256`. Nur `%h/.local/state/grabowski/coding-agent-router` ist für den Dienst schreibbar. Die Unit verwendet ausschließlich Härtungsdirektiven, die im unprivilegierten systemd-User-Manager des Heim-PC funktionieren; capability-verändernde Direktiven wie `PrivateDevices`, `ProtectKernelModules` und `ProtectKernelLogs` bleiben dort bewusst aus, weil sie den Prozess vor `ExecStart` mit `218/CAPABILITIES` beenden. Netzwerkzugriff wird nicht als Qualitäts- oder Modellausführung gewertet; die aufgerufenen Unterbefehle sind auf Versions-, Auth- und Modellinventar-Metadaten beschränkt.
