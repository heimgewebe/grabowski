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

Claude Fable 5 ist pay-only. Die Route `claude-fable-5-review-high` bleibt katalogisiert, wird aber vom normalen kostenfreien Review-Ranking ausgeschlossen und erhält durch ihre bloße Existenz keine Ausführungsautorität. Claude Opus 4.8 bleibt plan-only und kann innerhalb des vorhandenen Claude-Kontingents weiterhin als Reviewer oder Urteilsinstanz gerankt werden.

## Kontrastprogrammierung

Frühere externe Coding-Fähigkeiten heißen nun `contrast_capabilities`. Sie erlauben keinen Primär-Writer. Kontrastprogrammierung ist nur zulässig, wenn sie ausdrücklich angefordert wird und ein abgegrenzter Vergleich echten Erkenntnisgewinn verspricht.

Der Ablauf ist:

1. ChatGPT/Grabowski prüft den Livezustand und erstellt selbst Plan oder Kandidat.
2. Höchstens zwei externe Kandidaten arbeiten isoliert als `contrast` oder `competitor`.
3. Ihre Änderungen bleiben außerhalb des autoritativen Writerpfads.
4. ChatGPT/Grabowski vergleicht, reproduziert und übernimmt nur nach eigener Prüfung einzelne Ideen oder Patches.

`grabowski_agent_execution_route` bleibt deshalb auch bei großen und riskanten Aufgaben auf `execution_mode=direct_operator`. Eine ausdrückliche Kontrastanforderung ergänzt lediglich beratende Kandidaten. Die konkrete Modell-/Harnesswahl stammt dabei nicht mehr aus einer zweiten providerbasierten Routinglogik: Der Coding-Agent-Katalog rankt konkrete `route_id`-Werte und veröffentlicht sie als `external_route_candidates`. Der kostenfreie Frontier-Standard ist `codex-sol-high`; der Selector rankt jedoch alle aktivierten, kontrastfähigen Katalogrouten nach Aufgabenfit, Qualität, Quota, Cooldown und adaptiver Historie. Dadurch können auch geeignete Agy-Routen als kostenfreie Fallbacks gewählt werden. Codex läuft über den vorhandenen `codexr`-Wrapper subscription-only, mit `max_budget_usd=0`, read-only Sandbox und einem expliziten `codex exec --output-schema`-Vertrag für das Candidate-JSON; routegebundene Agy-Candidates laufen mit ihrem exakten Katalog-`argv_prefix` im bestehenden `plan`-/`sandbox`-Vertrag ebenfalls mit `max_budget_usd=0`. Eine pay-only Route wie `claude-fable-5-contrast-high` wird nur bei ausdrücklicher Paid-Autorisierung und nur als explizit katalogisierte Paid-Ausnahme überhaupt in die Auswahl aufgenommen. Externe parallele Writer-Shards sind nicht zulässig.

Ein kanonischer Candidate-Start über `grabowski_agent_competition_start` bindet die gewählte `route_id`, den Katalog-SHA-256, Harness, Modell, Effort, Permission-Modus, Quota-Pools und die Paid-Klassifikation in einen gehashten Route-Vertrag. Neue routegebundene Candidate-Packets, -Manifeste und -Receipts verwenden Schema 3. Historische providergebundene Schema-1/2-Artefakte bleiben lesbar; sie erhalten dadurch keine neue Route-Autorität.

Für Workspace-Routenevidenz bleibt außerdem die historische Policy `workspace-routing-v2.1` als eingefrorener Schema-2-Replaypfad erhalten. Sie dient nur der Lesbarkeit vorhandener Manifeste, Receipts und Shadow-Capture-Belege. Neue Workspace-Erzeugung verlangt ausdrücklich `direct-first-routing-v3.0`; ein historischer `full_workspace`-Beleg kann daher nicht als neue Ausführungsautorität wiederverwendet werden.

## Fable-Routen

Die historische ID `claude-fable-5-high` bleibt als deaktivierter plan-only Kompatibilitätsalias sichtbar.

Die zwischenzeitliche ID `claude-fable-5-writer-high` ist deaktiviert. Sie wird nicht mehr als Writer geroutet und verweist in ihrem `disabled_reason` auf die Direct-first-Doktrin.

Der zulässige mutierende Vergleichspfad heißt `claude-fable-5-contrast-high`. Er verwendet `--safe-mode --permission-mode acceptEdits`, ist aber `contrast_only=true`, besitzt keine Writer-Autorität und darf ausschließlich in einem isolierten Vergleichsraum laufen. Die Route ist `paid_only=true`, wird nie automatisch gewählt und verlangt vor dem Start sowohl `paid_execution_authorized=true` als auch ein positives `max_budget_usd` innerhalb des separat konfigurierten External-Provider-Kostenlimits. Der Candidate-Runner übergibt dieses Limit zusätzlich als Claude-CLI-Hard-Budget.

Unabhängige Fable-Reviews sind weiterhin über `claude-fable-5-review-high` katalogisiert (`--permission-mode plan`, `review_only=true`), aber ebenfalls `paid_only=true` und deshalb vom normalen kostenfreien Reviewer-Ranking ausgeschlossen. Dieser PR führt keinen automatischen Paid-Review-Fallback ein.

Die Zuordnung eines Fable-Routes zum Pool `claude-pro` dient ausschließlich der gemeinsamen Claude-Authentifizierungs-, Quota- und Concurrency-Abstammung. Die routeeigene Klassifikation `paid_only=true` überstimmt für die Ausführung die statische Nullkostenklassifikation dieses gemeinsamen Pools; Kostenautorität entsteht erst aus dem expliziten routegebundenen Budgetvertrag.

## Abgeleitete Rollen

`route_role`, `direct_capable`, `writer_capable`, `contrast_capable` und `review_capable` werden aus Controllerstatus, Task-Klassen und einschränkenden Rollenflags abgeleitet.

- Nur `grabowski-primary` ist direkt- und writer-fähig.
- Externe Nicht-Review-Aufgaben erzeugen ausschließlich Kontrastfähigkeit.
- Review-Routen erzeugen ausschließlich Reviewfähigkeit.
- Externe Routen ohne Rollenflag werden für Nicht-Review-Taskklassen als Kontrastrouten behandelt. Unabhängige Review-Fähigkeit ist fail-closed und verlangt `review_only=true`; eine Route wird nie allein wegen historisch gemischter Taskklassen zum Reviewer.
- `writer_only` ist als Katalogfeld stillgelegt und macht den Katalog ungültig.

Permission- und Approval-Modi werden zentral, reihenfolgeunabhängig und für `--flag value` sowie `--flag=value` aus `argv_prefix` abgeleitet. Damit bleibt der Befehlsvertrag die einzige Wahrheit für den konkreten CLI-Modus.

## Qualitäts- und Kostenhierarchie

Modellklassen ordnen nur noch Review- und Kontrastqualität, nicht die Autorenschaft:

- **S:** GPT-5.6 Sol high als bevorzugte kostenfreie Frontier-Kontrastroute; Claude Fable 5 nur als ausdrücklich autorisierte pay-only Kontrastroute; Sol xhigh als hochwertige Revieweskalation.
- **A:** Claude Opus 4.8, Sol medium, Terra high, Sonnet 5 high und Grok 4.5 high.
- **B:** Terra medium, Luna high, Sonnet 5 medium und Gemini 3.1 Pro high.
- **C:** Flash-, GPT-OSS-, ältere Agy-Claude- und lokale oder unklare Fallbacks.

Jules ist ein verwalteter Remote-Harness; die Platzhalteridentität behauptet kein zugrunde liegendes Modell. API-Key-Fallbacks, unbekannte Kostenpfade und automatische PAYG-Fallbacks bleiben gesperrt. Ein ausdrücklich als `paid_only` katalogisierter Fable-Pfad ist die enge Ausnahme: Er erfordert eine separate Paid-Autorisierung, ein positives per-Aufruf-Budget und ein positives Runtime-Kostenlimit; ohne alle drei Bedingungen blockiert der Start vor dem Provider-Task.

`argv_prefix` bleibt in dieser Version die kanonische Befehlsquelle. Permission- und Approval-Modi werden zentral, reihenfolgeunabhängig und für beide CLI-Schreibweisen (`--flag value` und `--flag=value`) validiert; der abgeleitete Wert erscheint als strukturiertes Feld `permission_mode` in Katalog- und Routingausgaben. Ein eigenständiges autoritatives Katalogfeld wäre eine separate Schemamigration und wird nicht neben dem bestehenden Befehlsvertrag als zweite Wahrheit eingeführt.

## Katalogauflösung ohne stille zweite Wahrheit

`config/coding-agent-catalog.json` ist die redaktionelle Quellwahrheit. Der Runtime-Vertrag deklariert dieselbe Datei als `runtime_asset`; Deployment-Snapshot, Release-ID und Manifest binden sie per Pfad und SHA-256 an das unveränderliche Release. Der Router liest standardmäßig ausschließlich dieses releasegebundene `deployment_catalog`. `tools/build_coding_agent_catalog_data.py` erzeugt zusätzlich eine deterministische, hashgebundene Kopie in `src/grabowski_coding_agent_catalog_data.py`, die Generator- und Konsistenztests unterstützt, aber keine eigene Runtime-Autorität besitzt.

Eine alte Datei unter `%h/.config/grabowski/coding-agent-catalog.json` besitzt keine Routingautorität. Ein abweichender Katalog ist nur für kontrollierte Tests oder Diagnose zulässig, wenn **beide** Variablen gesetzt sind: `GRABOWSKI_CODING_AGENT_CATALOG=<pfad>` und `GRABOWSKI_CODING_AGENT_CATALOG_OVERRIDE=1`. Ein einzelner geerbter Pfadwert wird ignoriert. Status und `grabowski_contract_drift` veröffentlichen den tatsächlich gewählten Ursprung sowie die semantische Validierung; ein ungültiger ausdrücklicher Override setzt die Routing-Readiness fail-closed, ohne auf eine zweite Katalogwahrheit zurückzufallen.

## Selbstlernen

Lokale Ergebnisse verändern die Rangfolge externer Review- und Kontrastrouten erst ab fünf vergleichbaren Läufen derselben Route und Aufgabenklasse. Verwendet werden First-Pass-, CI- und Merge-Erfolg, Nacharbeit, Rollbacks, falsche Behauptungen, Scope-Verstöße, Laufzeit und Kontingentverbrauch. Zugangstests zählen nie als Qualitätserfolg.

Selbstlernen kann keine externe Route zum autoritativen Writer machen und die Direct-first-Regel nicht überstimmen.

## Sicherheit und Kosten

Automatische Agentenausführung bleibt deaktiviert. Review- und Kontrastempfehlungen sind beratend. Es gibt genau einen autoritativen mutierenden Writer: ChatGPT/Grabowski. Ein externer Candidate wird nur durch einen getrennten expliziten Start erzeugt; ein Routingresultat allein startet weder Codex noch Claude.

Statische Kosten-, PAYG-, Reserve- und Parallelitätspolitik stammt ausschließlich aus dem versionierten Katalog. Dynamischer Laufzeitstatus darf nur Verfügbarkeit, Restquote, Cooldown, aktive Sitzungen und Verifikationszeit ergänzen. Ungültige oder zukünftige Werte sperren die betroffene externe Route fail-closed, nicht die direkte Operatorarbeit. `zero_marginal_cost_only=true` bleibt für automatische Auswahl und historische provider-only Starts fail-closed wirksam; `zero_marginal_cost_only_scope` begrenzt diese Alt-Policy ausdrücklich auf `automatic-and-legacy-provider-only-routes`. Die einzige maschinenlesbare Paid-Ausnahme steht in `explicit_paid_route_exceptions` und muss exakt mit den `paid_contrast_routes` übereinstimmen. `paid_only=true` ist zusätzlich eine routeeigene Ausführungssperre: Ohne explizite Paid-Autorisierung wird die Route weder im normalen Ranking berücksichtigt noch als ausführbarer Route-Vertrag aufgelöst. Für kostenfreie Codex-Kontraste bleibt `max_budget_usd=0` obligatorisch; für Fable ist ein positives Budget obligatorisch.

Kontingentpools bilden eine Elternkette. Sperre, Erschöpfung, Cooldown, Reservegrenze, Parallelitätsgrenze oder Kostenunsicherheit eines Elternpools sperrt jede zugehörige externe Review- oder Kontrastroute.

## Automatische Laufzeitstatus-Aktualisierung

Der dynamische Metadatenstand verfällt nach 3.600 Sekunden fail-closed nur für die Auswahl externer Zusatzreviewer und Kontrastkandidaten. `grabowski-coding-agent-probe.timer` erneuert ihn alle 45 Minuten mit höchstens drei Minuten Jitter. Der Timer startet ausschließlich `agent-route probe`; dieser Pfad liest Versions-, Auth- und Modellinventarmetadaten, führt aber keine Coding-, Review- oder Kontrastarbeit aus. Direkte Implementierung und direkter Review bleiben auch bei fehlender oder veralteter Probe verfügbar.

`agent-route` ist ein dünner, versionierter Wrapper auf das aktuelle Runtime-Modul `grabowski_coding_agent_router_cli`. `tools/install_coding_agent_router_cli.py` serialisiert den Cutover unter einem privaten exklusiven Installationslock, ersetzt Wrapper und SHA-256-Pin jeweils atomar, verlangt zuvor den eingebetteten Runtime-Katalog und nimmt beide Dateien bei fehlerhaftem Direct-first-Readback zurück. `coding_agent_probe_scheduler.py` öffnet den Wrapper ohne Symlink-Folge, prüft den Pin, entfernt bekannte API-Key-Variablen, begrenzt Laufzeit und Ausgabe und verlangt einen getrennten Status-Readback. Vorherige Historie muss strukturell erhalten bleiben. Der Probe-Receipt ist mit einem öffentlich domänenseparierten HMAC-SHA256 gebunden; dies dient deterministischer Typ- und Payloadtrennung, nicht Authentizität oder Passwortspeicherung. Ein fehlgeschlagener Probe-Lauf autorisiert nichts.

Die Probe-Unit hängt nicht von einer Benutzerkopie des Katalogs ab. Ihre Startbedingungen prüfen ausschließlich den ausführbaren Metadatenpfad und dessen privaten SHA-256-Pin. Die versionierten Installationsquellen sind:

- `tools/agent-route`
- `tools/install_coding_agent_router_cli.py`
- `tools/coding_agent_probe_scheduler.py`
- `systemd/grabowski-coding-agent-probe.service.example`
- `systemd/grabowski-coding-agent-probe.timer.example`

Die Live-Ziele sind `%h/bin/agent-route`, `%h/.local/libexec/grabowski/coding_agent_probe_scheduler.py` und die Unit unter `%h/.config/systemd/user/`; der Wrapper-Pin liegt privat unter `%h/.config/grabowski/coding-agent-probe-scheduler-router.sha256`. Nur `%h/.local/state/grabowski/coding-agent-router` ist für den Dienst schreibbar. `MemoryMax=512M` und `TasksMax=50` begrenzen einen fehlerhaften Kindprozess. Der sichere Cutover lautet: geprüftes Runtime-Release aktivieren, Wrapper samt Pin installieren, Probe ausführen und Status sowie Direct-first-Empfehlung zurücklesen.
## Kanonische Harness-Erweiterungen vom 24. Juli 2026

- `antigravity` ist die kanonische Google-Harness-Identität; das ausführbare CLI bleibt `agy`. Historische `agy`-Receipts bleiben lesbar, neue Routing-Evidenz verwendet `antigravity`.
- `opencode` ist als mutierender, isolierter Kontrast-Harness aufgenommen. Die initiale Live-Route ist an `opencode/deepseek-v4-flash-free`, JSON-Ereignisse, `--pure` und `--auto` gebunden und wurde mit Kosten `0` live geprüft.
- `openhands` ist als vollständiger mutierender Kontrast-Harness aufgenommen. Headless-Ausführung ist absichtlich an `--always-approve` gebunden. Diese Eigentümerentscheidung ersetzt keine Lease-, Worktree-, Review- oder Integrationsgrenze.
- OpenHands bleibt bis zu einem live attestierten, kostenfreien oder abonnementsgebundenen Modellzugang fail-closed.
- Die Direct-first-Autorität bleibt unverändert: Externe Ergebnisse sind bis zur Operatorprüfung beratend.
