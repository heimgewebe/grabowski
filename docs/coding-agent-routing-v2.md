# Coding-Agent-Routing v3 — Direct-first mit Review und Kontrast

## Kanonische Regel

ChatGPT/Grabowski führt jede autoritative Implementierung selbst aus. Das gilt unabhängig von Dateizahl, Laufzeit, Neuheit, Risiko oder vermutetem Arbeitsumfang. Große Arbeit wird zerlegt, isoliert, getestet und integriert, aber nicht wegen ihrer Größe an einen externen Writer abgegeben.

Externe Agents haben zwei zulässige Rollen:

1. **Review:** unabhängige Prüfung eines Plans, Diffs, Tests oder Ergebnisses.
2. **Kontrastprogrammierung:** ein ausdrücklich angeforderter, isolierter Gegenentwurf oder Alternativpatch zum Vergleich.

Beide Rollen sind beratend. Ein Agentenresultat wird niemals automatisch angewendet, ausgewählt, committet, gemergt oder deployt. ChatGPT/Grabowski prüft Befunde und Alternativen selbst und bleibt alleiniger Integrator.

Die maschinenlesbare Quellwahrheit für diese Doktrin liegt in `src/grabowski_operator_relay.py`. Runtime, Operator-Kontextgenerator und veröffentlichter Kontext lesen denselben Vertrag.

## Direkter Primärpfad

Für normale Coding-, Architektur-, Migrations-, Debug-, Test-, Dokumentations- und Betriebsaufgaben liefert `grabowski_coding_agent_route` stets:

- `decision=controller`
- `controller=grabowski-primary`
- `primary_role=direct-writer`
- `direct_implementation_required=true`
- `external_primary_writer_forbidden=true`
- `capacity_fallback_to_external_writer=false`

Ein fehlender, veralteter oder katalogfremder Agentenstatus blockiert die direkte Arbeit nicht. Er kann lediglich verhindern, dass ein zusätzlicher externer Reviewer belastbar ausgewählt wird.

Die Operatorverantwortung umfasst Livezustand, Planung, Implementierung, Tests, Integration, Merge, Deployment und Abschluss. Der Router erteilt weiterhin keine automatische Ausführungs-, Merge- oder Deploymentautorität.

## Externe Review-Routen

Auch explizite Review-Aufgaben wie `independent-review`, `critical-review` und `security-review` beginnen beim direkten ChatGPT/Grabowski-Review. Der Router kann danach einen provider- und lineage-unabhängigen externen Zusatzreviewer empfehlen. Ein fehlender oder gesperrter Agentenstatus blockiert den direkten Review nicht. Jeder externe Befund bleibt bis zur direkten Reproduktion oder anderweitigen Prüfung durch den Operator beratend.

Plan-Modus gilt global als Review-Modus: Jede Route mit `plan` als Permission- oder Approval-Modus muss `review_only=true` sein, mindestens eine als unabhängiger Review klassifizierte Aufgabe anbieten und darf keine Kontrastaufgabe enthalten.

Claude Fable 5 besitzt dafür die aktive Route `claude-fable-5-review-high`. Claude Opus 4.8 bleibt ebenfalls plan-only und wird ausschließlich als Reviewer oder Urteilsinstanz geführt.

## Kontrastprogrammierung

Frühere externe Coding-Fähigkeiten heißen nun `contrast_capabilities`. Sie erlauben keinen Primär-Writer. Kontrastprogrammierung ist nur zulässig, wenn sie ausdrücklich angefordert wird und ein abgegrenzter Vergleich echten Erkenntnisgewinn verspricht.

Der Ablauf ist:

1. ChatGPT/Grabowski prüft den Livezustand und erstellt selbst Plan oder Kandidat.
2. Höchstens zwei externe Kandidaten arbeiten isoliert als `contrast` oder `competitor`.
3. Ihre Änderungen bleiben außerhalb des autoritativen Writerpfads.
4. ChatGPT/Grabowski vergleicht, reproduziert und übernimmt nur nach eigener Prüfung einzelne Ideen oder Patches.

`grabowski_agent_execution_route` bleibt deshalb auch bei großen und riskanten Aufgaben auf `execution_mode=direct_operator`. Eine ausdrückliche Kontrastanforderung ergänzt lediglich beratende Kandidaten. Externe parallele Writer-Shards sind nicht zulässig.

## Fable-Routen

Die historische ID `claude-fable-5-high` bleibt als deaktivierter plan-only Kompatibilitätsalias sichtbar.

Die zwischenzeitliche ID `claude-fable-5-writer-high` ist deaktiviert. Sie wird nicht mehr als Writer geroutet und verweist in ihrem `disabled_reason` auf die Direct-first-Doktrin.

Der zulässige mutierende Vergleichspfad heißt `claude-fable-5-contrast-high`. Er verwendet `--safe-mode --permission-mode acceptEdits`, ist aber `contrast_only=true`, besitzt keine Writer-Autorität und darf ausschließlich in einem isolierten Vergleichsraum laufen.

Unabhängige Fable-Reviews laufen über `claude-fable-5-review-high` mit `--permission-mode plan` und `review_only=true`.

## Abgeleitete Rollen

`route_role`, `direct_capable`, `writer_capable`, `contrast_capable` und `review_capable` werden aus Controllerstatus, Task-Klassen und einschränkenden Rollenflags abgeleitet.

- Nur `grabowski-primary` ist direkt- und writer-fähig.
- Externe Nicht-Review-Aufgaben erzeugen ausschließlich Kontrastfähigkeit.
- Review-Routen erzeugen ausschließlich Reviewfähigkeit.
- Gemischte externe Routen können Kontrast und Review anbieten, werden aber nie writer-fähig.
- `writer_only` ist als Katalogfeld stillgelegt und macht den Katalog ungültig.

Permission- und Approval-Modi werden zentral, reihenfolgeunabhängig und für `--flag value` sowie `--flag=value` aus `argv_prefix` abgeleitet. Damit bleibt der Befehlsvertrag die einzige Wahrheit für den konkreten CLI-Modus.

## Qualitäts- und Kostenhierarchie

Modellklassen ordnen nur noch Review- und Kontrastqualität, nicht die Autorenschaft:

- **S:** GPT-5.6 Sol high und Claude Fable 5 als bevorzugte Kontrastrouten; Sol xhigh als teure Revieweskalation.
- **A:** Claude Opus 4.8, Sol medium, Terra high, Sonnet 5 high und Grok 4.5 high.
- **B:** Terra medium, Luna high, Sonnet 5 medium und Gemini 3.1 Pro high.
- **C:** Flash-, GPT-OSS-, ältere Agy-Claude- und lokale oder unklare Fallbacks.

Jules ist ein verwalteter Remote-Harness; die Platzhalteridentität behauptet kein zugrunde liegendes Modell. PAYG-, API-Key- und unbekannte Kostenpfade bleiben gesperrt.

`argv_prefix` bleibt in dieser Version die kanonische Befehlsquelle. Permission- und Approval-Modi werden zentral, reihenfolgeunabhängig und für beide CLI-Schreibweisen (`--flag value` und `--flag=value`) validiert; der abgeleitete Wert erscheint als strukturiertes Feld `permission_mode` in Katalog- und Routingausgaben. Ein eigenständiges autoritatives Katalogfeld wäre eine separate Schemamigration und wird nicht neben dem bestehenden Befehlsvertrag als zweite Wahrheit eingeführt.

## Selbstlernen

Lokale Ergebnisse verändern die Rangfolge externer Review- und Kontrastrouten erst ab fünf vergleichbaren Läufen derselben Route und Aufgabenklasse. Verwendet werden First-Pass-, CI- und Merge-Erfolg, Nacharbeit, Rollbacks, falsche Behauptungen, Scope-Verstöße, Laufzeit und Kontingentverbrauch. Zugangstests zählen nie als Qualitätserfolg.

Selbstlernen kann keine externe Route zum autoritativen Writer machen und die Direct-first-Regel nicht überstimmen.

## Sicherheit und Kosten

Automatische Agentenausführung bleibt deaktiviert. Review- und Kontrastempfehlungen sind beratend. Es gibt genau einen autoritativen mutierenden Writer: ChatGPT/Grabowski.

Statische Kosten-, PAYG-, Reserve- und Parallelitätspolitik stammt ausschließlich aus dem versionierten Katalog. Dynamischer Laufzeitstatus darf nur Verfügbarkeit, Restquote, Cooldown, aktive Sitzungen und Verifikationszeit ergänzen. Ungültige oder zukünftige Werte sperren die betroffene externe Route fail-closed, nicht die direkte Operatorarbeit.

Kontingentpools bilden eine Elternkette. Sperre, Erschöpfung, Cooldown, Reservegrenze, Parallelitätsgrenze oder Kostenunsicherheit eines Elternpools sperrt jede zugehörige externe Review- oder Kontrastroute.

## Automatische Katalogaktualisierung

Der kanonische statische Katalog wird durch `tools/build_coding_agent_catalog_data.py` deterministisch aus `config/coding-agent-catalog.json` erzeugt und als `grabowski_coding_agent_catalog_data` im selben unveränderlichen Runtime-Release wie der Router installiert. Ohne die doppelt ausdrückliche Test- oder Diagnoseüberschreibung `GRABOWSKI_CODING_AGENT_CATALOG=<pfad>` plus `GRABOWSKI_CODING_AGENT_CATALOG_OVERRIDE=1` liest die Runtime keinen Benutzerkatalog. Dadurch wechseln Code und Katalog mit demselben Release-Symlink; ein alter Bestand unter `%h/.config/grabowski/coding-agent-catalog.json` bleibt höchstens Rollback-Artefakt und besitzt keine Routingautorität.

Der dynamische Metadatenstand verfällt nach 3.600 Sekunden fail-closed nur für die Auswahl externer Zusatzreviewer und Kontrastkandidaten. `grabowski-coding-agent-probe.timer` erneuert ihn alle 45 Minuten mit höchstens drei Minuten Jitter. Der Timer startet ausschließlich `agent-route probe`; dieser Pfad liest Versions-, Auth- und Modellinventarmetadaten, führt aber keine Coding-, Review- oder Kontrastarbeit aus. Direkte Implementierung und direkter Review bleiben auch bei fehlender oder veralteter Probe verfügbar.

`agent-route` ist ein dünner, versionierter Wrapper auf das aktuelle Runtime-Modul `grabowski_coding_agent_router_cli`. `tools/install_coding_agent_router_cli.py` ersetzt Wrapper und privaten SHA-256-Pin atomar, verlangt zuvor den eingebetteten Runtime-Katalog und nimmt beide Dateien bei fehlerhaftem Direct-first-Readback zurück. `coding_agent_probe_scheduler.py` öffnet den Wrapper ohne Symlink-Folge, prüft den Pin, entfernt bekannte API-Key-Variablen, begrenzt Laufzeit und Ausgabe und verlangt einen getrennten Status-Readback. Vorherige Historie muss strukturell erhalten bleiben. Ein fehlgeschlagener Probe-Lauf autorisiert nichts.

Die versionierten Installationsquellen sind:

- `tools/coding_agent_probe_scheduler.py`
- `systemd/grabowski-coding-agent-probe.service.example`
- `systemd/grabowski-coding-agent-probe.timer.example`

Die Live-Ziele sind `%h/bin/agent-route`, `%h/.local/libexec/grabowski/coding_agent_probe_scheduler.py` und die Unit unter `%h/.config/systemd/user/`; der Wrapper-Pin liegt privat unter `%h/.config/grabowski/coding-agent-probe-scheduler-router.sha256`. Nur `%h/.local/state/grabowski/coding-agent-router` ist für den Dienst schreibbar. `MemoryMax=512M` und `TasksMax=50` begrenzen einen fehlerhaften Kindprozess. Der sichere Cutover lautet: geprüftes Runtime-Release aktivieren, Wrapper samt Pin installieren, Probe ausführen und Status sowie Direct-first-Empfehlung zurücklesen.
