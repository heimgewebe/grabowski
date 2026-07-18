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
