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

## Getrennte Writer- und Review-Routen

Die bisherige ID `claude-fable-5-high` wird nicht still von Planung auf Mutation umgedeutet. Sie bleibt als deaktivierter, plan-only Kompatibilitätsalias mit explizitem `disabled_reason` sichtbar. Fest codierte Inspektion sieht deshalb weiterhin eine nicht mutierende Route; jede Rangfolge verwirft sie fail-closed.

Die neue aktive Writer-ID ist `claude-fable-5-writer-high`. Sie verwendet `claude -p --safe-mode --permission-mode acceptEdits --model claude-fable-5 --effort high` und `writer_only=true`. Top-Class-Policy und Co-Primär-Rangfolge referenzieren ausschließlich diese ID. Die neue ID ist absichtlich eine brechende Änderung für Aufrufer, die eine aktive Fable-Writer-ID fest codiert haben; Aufrufer müssen auf die neue ID wechseln. Die Fable-Routenhistorie ist leer, deshalb ist keine Ergebnis- oder Lernhistorienmigration erforderlich.

Unabhängige Fable-Reviews laufen über die weiterhin aktive ID `claude-fable-5-review-high` mit `--permission-mode plan` und `review_only=true`. Plan-Modus ist für unabhängige, kritische und Security-Reviews passend, weil die Route analysiert, ohne den geprüften Stand zu verändern. Die Opus-Route `claude-opus-4.8-high` ist ebenfalls eine plan-only Review-Route und deshalb bewusst aus der Writer-Rangfolge entfernt; ihre Qualitätsprior bleibt für Review und Urteil erhalten, ohne eine mutierende Primärroute zu behaupten.

Plan-Semantik gilt global: Jede Route mit plan als Permission- oder Approval-Modus muss `review_only=true` sein, mindestens eine als `independent_review=true` klassifizierte Review-Aufgabe anbieten und darf keine Writer-Aufgabe anbieten. Das gilt auch für deaktivierte und lokale Routen. Writer-only-Routen brauchen umgekehrt mindestens eine Writer-Aufgabe und dürfen keine Review-Aufgabe enthalten. Eine aktivierte externe Route ohne tatsächliche Writer- oder Review-Fähigkeit macht den gesamten Katalog ungültig.

`route_role`, `writer_capable` und `review_capable` werden aus der tatsächlichen Partition der Task-Klassen plus den einschränkenden Rollenflags abgeleitet, nicht aus den Flags allein. Writer-Ranking verlangt `writer_capable`; Reviewer-Ranking verlangt `review_capable`. Explizite Review-Aufgaben wählen daher eine reviewer-fähige Primärroute und melden `primary_role=reviewer`; normale Coding-Aufgaben melden `primary_role=writer`. Ein kritischer Review darf weiterhin einen zweiten, provider- und lineage-unabhängigen Reviewer verlangen.

`acceptEdits` ist gewählt, weil eine Writer-Route im separat autorisierten Arbeitsraum Änderungen anwenden können muss, ohne die Schutzgrenzen von `--safe-mode` zu umgehen. Ein `auto`-Modus würde die Freigabeentscheidung weiter delegieren; `bypassPermissions` beziehungsweise vergleichbare Permission-Bypässe würden die Sicherheitsgrenze aufheben. Beides ist hier ausdrücklich ausgeschlossen. `acceptEdits` erteilt weder automatische Ausführungsautorität noch Integrations-, Merge- oder Deployment-Rechte. Es bleibt bei höchstens einem mutierenden Writer; Katalog und Empfehlung starten keine Route automatisch.

`argv_prefix` bleibt in dieser Version die kanonische Befehlsquelle. Permission- und Approval-Modi werden zentral, reihenfolgeunabhängig und für beide CLI-Schreibweisen (`--flag value` und `--flag=value`) validiert; der abgeleitete Wert erscheint als strukturiertes Feld `permission_mode` in Katalog- und Routingausgaben. Ein eigenständiges autoritatives Katalogfeld wäre eine separate Schemamigration und wird nicht neben dem bestehenden Befehlsvertrag als zweite Wahrheit eingeführt.

## Selbstlernen

Lokale Ergebnisse überschreiben Hersteller- und Benchmark-Priors erst ab fünf vergleichbaren Läufen derselben Route und Aufgabenklasse. Verwendet werden First-Pass-, CI- und Merge-Erfolg, Nacharbeit, Rollbacks, falsche Behauptungen, Scope-Verstöße, Laufzeit und Kontingentverbrauch. Zugangstests werden getrennt gespeichert und nie als Qualitätserfolg gezählt. Bayesianische Schrumpfung und harte Kappen verhindern, dass wenige Läufe die Hierarchie umwerfen.

## Sicherheit und Kosten

Automatische Ausführung bleibt deaktiviert. Empfehlungen sind beratend, ein einzelner mutierender Writer bleibt Pflicht, kritische Reviews müssen aus einer anderen Providerfamilie stammen. PAYG, API-Key- und unbekannte Kostenpfade bleiben gesperrt.

Statische Kosten-, PAYG-, Reserve- und Parallelitätspolitik stammt ausschließlich aus dem versionierten Katalog. Der dynamische Laufzeitstatus darf nur Verfügbarkeit, Restquote, Cooldown, aktive Sitzungen und Verifikationszeit ergänzen. Unbekannte Felder, ungültige Werte oder zukünftige Zeitstempel sperren den betroffenen Pool fail-closed.

Kontingentpools bilden eine Elternkette. Der Router erweitert jeden an einer Route genannten Pool automatisch um alle Elternpools und prüft jeden Pool genau einmal. Sperre, Erschöpfung, Cooldown, Reservegrenze, Parallelitätsgrenze oder Kostenunsicherheit eines Elternpools sperrt damit auch jede Kindroute, selbst wenn der Elternpool in der Route nicht zusätzlich ausgeschrieben ist.

## Automatische Katalogaktualisierung

Der Live-Katalog verfällt nach 3.600 Sekunden fail-closed. `grabowski-coding-agent-probe.timer` erneuert ihn deshalb alle 45 Minuten mit höchstens drei Minuten Jitter. Der Timer startet ausschließlich den bestehenden Metadatenpfad `agent-route probe`; er ruft keine Empfehlungs-, Beobachtungs- oder Ausführungsfunktion auf.

`coding_agent_probe_scheduler.py` verlangt zusätzlich einen privaten SHA-256-Pin für die konkrete `agent-route`-Datei, öffnet diese ohne Symlink-Folge und führt beide Unterbefehle über denselben offenen Dateideskriptor aus. Danach entfernt es bekannte API-Key-Variablen aus der Kindprozessumgebung, hält eine nichtblockierende exklusive Sperre, begrenzt Laufzeit und Ausgabemenge bereits beim parallelen Lesen der Kindprozess-Pipes und verlangt anschließend einen separaten `agent-route status`-Readback. Vorherige `history`-Daten müssen bytewertgleich in der JSON-Struktur erhalten bleiben. Der Router schreibt den eigentlichen State atomar; der Scheduler publiziert zusätzlich einen privaten atomaren Erfolgs- oder Fehlerbeleg. Ein gescheiterter Probe-Lauf autorisiert keine Ausführung und lässt den Router nach Ablauf der Freshness weiterhin fail-closed.

Die versionierten Installationsquellen sind:

- `tools/coding_agent_probe_scheduler.py`
- `systemd/grabowski-coding-agent-probe.service.example`
- `systemd/grabowski-coding-agent-probe.timer.example`

Die Live-Ziele liegen unter `%h/.local/libexec/grabowski/` und `%h/.config/systemd/user/`; der aktuelle Router-Pin liegt privat unter `%h/.config/grabowski/coding-agent-probe-scheduler-router.sha256`. Nur `%h/.local/state/grabowski/coding-agent-router` ist für den Dienst schreibbar. `MemoryMax=512M` und `TasksMax=50` begrenzen zusätzlich einen fehlerhaften Kindprozess. Die Unit verwendet ausschließlich Härtungsdirektiven, die im unprivilegierten systemd-User-Manager des Heim-PC funktionieren; capability-verändernde Direktiven wie `PrivateDevices`, `ProtectKernelModules` und `ProtectKernelLogs` bleiben dort bewusst aus, weil sie den Prozess vor `ExecStart` mit `218/CAPABILITIES` beenden. Netzwerkzugriff wird nicht als Qualitäts- oder Modellausführung gewertet; die aufgerufenen Unterbefehle sind auf Versions-, Auth- und Modellinventar-Metadaten beschränkt.
