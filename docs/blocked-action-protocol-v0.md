# Blocked Action Protocol v0

## These / Antithese / Synthese

These: ChatGPT bleibt der Operator fuer Grabowski. Direkte Grabowski-Tools bleiben der erste Griff, weil sie naehere Kontrolle, Audit und sofortige Ruecknahme erlauben.

Antithese: Ein blockierter oder zu breiter Toolcall darf nicht durch eine zweite freie Fernbedienung ersetzt werden. Ein Helfer, der beliebige Befehle autonom weiterfuehrt, verschiebt nur das Risiko und verschlechtert die Sichtbarkeit.

Synthese: Wenn ChatGPT ein einzelner Griff verwehrt ist, wird genau dieser Griff als begrenzter Micro-Handoff abgegeben. Danach muss ein Receipt vorliegen, und ChatGPT nimmt die Arbeit wieder auf, bevor der naechste Griff erfolgt.

## Zweck

Dieses Protokoll legt fest, wie mit blockierten ChatGPT/Grabowski-Operationen umzugehen ist, ohne ChatGPT als Operator abzugeben.

Es etabliert keinen neuen Privilegienpfad, keine dauerhafte Agentenautonomie und keinen Ersatz fuer bestehende Grabowski-Policies. Es beschreibt eine Betriebsregel: Der explizit gebundene Controller bleibt autoritativ fuer Planung, Integration, Merge, Deployment und Closeout. Implementierung darf innerhalb einer expliziten, ressourcengebundenen Work-Lane an einen scoped Writer delegiert werden; Modellidentitaet verleiht dabei keine Autoritaet. Reviewer und Observer bleiben read-only. Ein technisch blockierter Einzelgriff kann weiterhin als begrenzter Micro-Handoff ausgefuehrt werden.

## Nutzer-Eskalationsgrenze

Der Nutzer ist Entscheidungsinstanz, nicht Standard-Executor. Bei Plattformblockade muss ChatGPT zuerst interne Relay-Pfade nutzen: engeres Typed Tool, Grabowski Micro-Task, Codex, Claude, Antigravity, OpenCode, OpenHands, lokale KI oder Patch-Relay. Nutzerkontakt ist Entscheidungseskalation, kein Ersatz fuer einen blockierten Griff.

## Nicht-Ziele

- Keine freie Shell als getarnte Schleuse.
- Kein automatischer Merge.
- Kein automatischer Live-Deploy.
- Keine Secret-Offenlegung.
- Kein Daueragent, der selbst Prioritaeten setzt.
- Kein Pull-Relay, das neue Befehle ohne lokale Validierung akzeptiert.

## Grundregel

Jede blockierte Operation wird auf die kleinste pruefbare Handlung reduziert.

Die kleinste Handlung muss beantworten:

1. Was soll exakt passieren?
2. Wer fuehrt nur diesen Griff aus?
3. Was darf nicht passieren?
4. Woran erkennt ChatGPT danach Erfolg, Fehler oder Blockade?
5. Welche Information braucht ChatGPT, um den naechsten Griff selbst zu entscheiden?

## Kontrollschleife und Routing

1. **Typed Grabowski Tool**
   - Erste Wahl fuer Status, Git-Status, Service-Status, Logs, Runtime-Health, Audit und andere schmale Operationen.
   - Beispiel: `grabowski_runtime_health`, `grabowski_git_status`, `grabowski_task_status`.

2. **Grabowski Micro-Task**
   - Erste Wahl fuer kurze Shell-nahe Handgriffe, wenn kein passendes Typed Tool existiert oder ein direktes Tool blockiert.
   - Muss begrenzt sein durch `cwd`, `runtime_seconds`, Memorylimit und optional gueltige `resource_keys`.
   - Danach sind `task_status` und `task_logs` Pflicht.

3. **Receipt before next step**
   - Nach jedem Ersatzgriff wird zuerst Status, Logs, Diff, Testausgabe oder ein anderes Receipt gelesen.
   - Erst danach entscheidet ChatGPT den naechsten Griff.

3a. **Reposkop context signal**
   - Bei Repo-, PR-, Branch-, Pull-, Switch- und Merge-Prep-Arbeit kann `reposkop report <absolute-target> --purpose grabowski-repo-state-context --json` als leichter read-only Kontextgriff genutzt werden, wenn das Zielrepository explizit gewählt wurde.
   - Der Probelauf gilt als bestanden; es wird keine separate `useful_signal`/`changed_decision`/`noise` Trial-Metrik weitergefuehrt.
   - Nur Felder des expliziten Ziels zaehlen. Globale Discovery, Favoriten und Branch-Drift-Simulation sind keine Reposkop-Flaechen.
   - Der Report ist kein Gate, keine Genehmigung und kein Ersatz fuer Git-Status, PR-Checks, Review-Gates oder Action-Readiness.

Danach wird nach Aufgabenklasse geroutet.

4. **ChatGPT Operator**
   - Controller-Standard fuer alle Lanes und jede Aufgabengroesse: Livezustand, Scope, Planung, Delegation, Integration, Merge, Deployment, Closeout und Recovery bleiben controllergebunden.
   - Ein gemeinsamer Operator-Kontext ist der Normalfall; Implementierung kann bei belegter Isolation an einen explizit lane- und ressourcengebundenen scoped Writer delegiert werden.
   - Der Controller bleibt fuer Receipts, Integration und alle controller-only Wirkungen verantwortlich; der scoped Writer darf innerhalb seiner Lane implementieren, testen, committen, pushen und einen Pull Request erstellen oder aktualisieren.

5. **Externe Agentenrollen**
   - Externe Modelle sind standardmaessig aus; Modellidentitaet allein besitzt weder Writer- noch Integrationsautoritaet.
   - Auch bei expliziter Aktivierung erhalten sie keine Kopien dieses ChatGPT-Kontexts, sondern nur den fuer ihre Rolle erforderlichen lane- oder reviewgebundenen Kontext.
   - Zulassige Rollen sind scoped Writer innerhalb einer expliziten Work-Lane sowie unabhaengiger Review, Observer oder ausdruecklich angeforderte isolierte Kontrastprogrammierung.
   - Routingpraeferenz fuer externe Modelle: **Claude -> Codex -> Antigravity -> OpenCode -> OpenHands -> Cline**; diese Reihenfolge verleiht keine Autoritaet.
   - Reviewer, Observer und Kontrastresultate bleiben advisory-only. Ein explizit gebundener scoped Writer darf innerhalb seiner Lane committen und pushen; Merge, Deployment, Bureau-Terminalisierung und Closeout bleiben controllergebunden.

6. **Antigravity, OpenCode, OpenHands / lokale KI**
   - `agy --print` (Antigravity CLI) und lokale Modelle duerfen kurze beratende Denk-, Sortier- oder Kontrastgriffe liefern.
   - Sie sind weder Standardpfad fuer direkte Arbeit noch Ersatz bei grossem Umfang.
   - Jeder Griff endet mit einem begrenzten Receipt; Entscheidungen und Umsetzung bleiben bei ChatGPT/Grabowski.

7. **Unabhaengiger Review**
   - Externe Reviewer pruefen nach einem operatorseitigen Plan, Diff oder Ergebnis Architektur, Sicherheit, Quellen, Failure Paths und Tests.
   - Default: lesen, bewerten, Risiken benennen; Befunde bleiben bis zur direkten Pruefung durch den Operator beratend.

8. **tmux / Antigravity Session**
   - tmux ist Standard fuer vorhandene Sessions, Capture und Resume-Kontexte.
   - Antigravity ist fuer Session/Resume nur dann besser, wenn der Ruecknahmebeleg klarer ist.

9. **Patch file relay**
   - Lokale Patchdateien werden mit `tools/operator_patch_relay.py` geprueft und bei expliziter Entscheidung angewendet.
   - Der Relay schreibt ein JSON-Receipt; manueller Patchdownload durch den Nutzer ist nur der letzte Notausgang.
   - Der Relay merged, pusht und deployt nicht.

10. **Goose / Qwen / Aider**
   - Goose und Qwen sind optionale lokale Agent-Alternativen, nicht der Standardpfad.
   - Aider bleibt ein bounded Patch-Fallback mit deaktiviertem Auto-Commit.

## Executor-Matrix

| Blockierte Klasse | Primaerer Ersatz | Warum | Ruecknahmebeleg |
| --- | --- | --- | --- |
| Status/Health blockiert | engeres Typed Tool oder Micro-Task | geringes Risiko, sofort pruefbar | Status JSON oder Logtail |
| Repo-/Branch-Lage fuer Zielrepo unklar | Reposkop target-bound report | leichtes read-only Lagebild ohne Freigabe | Reposkop report JSON, nur explizites Ziel |
| kurzer Shell-Griff blockiert | Grabowski Micro-Task | bleibt unter Grabowski-Audit | task_id, status, logs |
| komplexer Code-/Repo-Slice | Controller direkt oder lane-gebundener scoped Writer | Autoritaet folgt der Rolle und dem Ressourcenscope, nicht dem Modell; Integration bleibt beim Controller | diff, changed files, Tests |
| lokaler Patch aus Chat/Artefakt | operator_patch_relay.py | prueft und wendet lokal mit Head- und Dirty-Gates an | JSON-Receipt plus Git-Diff |
| Review-/Architekturunsicherheit | Claude Review | bessere Kontrastpruefung | Review mit konkreten Befunden |
| interaktive Sessionfrage | tmux capture, Antigravity bei besserem Resume | Resume-naehe | Capture-Auszug, naechste Eingabe |
| lokale Mikro-Reasoning-Frage | Ollama API mit qwen coder | lokal, billig und begrenzt | kurze Antwort oder Vorschlagsliste |

## Micro-Handoff Contract

Ein Micro-Handoff ist nur gueltig, wenn er diese Felder gedanklich oder maschinenlesbar festlegt:

```json
{
  "step_id": "unique-step-id",
  "operator": "chatgpt-grabowski",
  "executor": "grabowski-task|codex|claude|antigravity|opencode|openhands|local-ai",
  "intent": "one bounded action",
  "allowed_scope": ["repo:/home/alex/repos/example"],
  "forbidden": ["secrets", "live-deploy", "merge", "push unless explicitly requested"],
  "stop_after": "status|logs|diff|tests|review",
  "receipt_required": true
}
```

Der Contract ist bewusst kleiner als ein Projektauftrag. Er beschreibt einen Griff, keinen Arbeitstag.

## Receipt Contract

Nach jedem Micro-Handoff muss ein Receipt vorliegen. Minimal:

```json
{
  "step_id": "unique-step-id",
  "executor": "grabowski-task|codex|claude|antigravity|opencode|openhands|local-ai",
  "state": "completed|failed|blocked|rejected",
  "changed_files": [],
  "exit_code": 0,
  "evidence": "task logs, diff, status output or review text",
  "next_decision_required": "what ChatGPT must decide before continuing"
}
```

Ohne Receipt darf kein Folgeschritt angenommen werden. Der Helfer hat dann nicht gearbeitet, sondern Nebel produziert.

## Wiederaufnahme-Regel

ChatGPT nimmt die Arbeit wieder auf durch mindestens einen dieser Belege:

- `task_status` plus `task_logs`
- Git-Status plus Diff
- Testausgabe
- Service-Status plus Logtail
- PR-Checks
- strukturierter Review-Befund

Danach entscheidet ChatGPT explizit:

- fortsetzen,
- enger schneiden,
- verwerfen,
- testen,
- committen,
- pushen,
- stoppen.

## Stop-Regeln

Sofort stoppen bei:

- Secret-Hinweis oder Redaction-Anzeichen,
- unerklaerten Aenderungen ausserhalb des erlaubten Scopes,
- fehlendem Receipt,
- Dirty Worktree vor Start ohne Bezug zur Aufgabe,
- Testfehlern ohne klare Einordnung,
- Aufforderung zu Merge, Push oder Deploy ohne explizite Freigabe,
- wiederholter Plattformfilter-Blockade derselben Klasse ohne neuen Erkenntnisgewinn.

## Resource-Key-Regel

Wenn `resource_keys` verwendet werden, muessen sie einem erlaubten Typ folgen, z.B.:

- `repo:/home/alex/repos/name`
- `path:/home/alex/repos/name/subpath`
- `service:unit.service`
- `port:18181`
- `display:99`
- `browser-profile:/path`

Freie Fantasietypen sind ungueltig. Ein fehlgeschlagener Resource-Key ist kein Plattformblock, sondern ein Contract-Fehler.

## Agentenwahl

### ChatGPT Operator

ChatGPT/Grabowski ist der Standardcontroller fuer alle Lanes und alle Aufgabengroessen. Der Controller prueft den Livezustand, plant, delegiert optional eine isolierte Writer-Lane, integriert, reviewed kritisch, merged, deployt und schliesst ab. Ein scoped Writer kann intern oder extern ausgefuehrt werden; seine Autoritaet entsteht ausschliesslich aus der expliziten Lane-, Ressourcen- und Controllerbindung.

### Claude

Claude ist eine bevorzugte unabhaengige Review- und Urteilsroute fuer schwierige Invarianten, Sicherheitslogik, Architektur und Quellen. Als Reviewer bleibt Claude advisory-only; als explizit gebundener scoped Writer darf Claude innerhalb der zugewiesenen Work-Lane die Writer-Wirkungen ausfuehren, aber keine Controller-Wirkungen.

### Codex

Codex ist eine Review-, Kontrast- und moegliche scoped-Writer-Route fuer Code- und Repo-Slices. `review` ist der Normalfall; mutierende Nutzung braucht eine explizite Work-Lane und bleibt auf deren Writer-Wirkungen begrenzt. Codex besitzt durch Modellidentitaet keine Integrationsautoritaet.

### Antigravity

Antigravity vereinheitlicht externe Review-, Kontrast- und optionale scoped-Writer-Routen und kann kurze beratende One-Shots liefern. Eine Writerrolle entsteht nur durch explizite Lane-, Ressourcen- und Controllerbindung; ohne diese Bindung bleibt Antigravity advisory-only.

### Cline

Cline ist eine nachrangige Review-, Kontrast- oder scoped-Writer-Route, wenn die bevorzugten Wege nicht geeignet sind. Ohne explizite Writer-Lane bleibt Cline advisory-only; Merge, Deployment und Closeout bleiben controllergebunden.

### Lokale KI / Goose / Ollama

Lokale Modelle duerfen als begrenztes Hilfslicht fuer Review, Klassifikation oder Kontrast dienen. Sie werden nicht zum Daueroperator oder Primaer-Writer.

### Aider

Lokale Patchdateien laufen zuerst ueber `tools/operator_patch_relay.py`. Aider darf hoechstens einen isolierten Kontrastpatch erzeugen; ChatGPT/Grabowski prueft und uebernimmt ihn gegebenenfalls selbst.

## Risikoklassen

- **Scope Drift:** Helfer arbeitet ausserhalb der erlaubten Dateien oder Repos.
- **Autonomie Drift:** Helfer setzt Prioritaeten selbst.
- **Evidence Drift:** Helfer meldet Erfolg ohne pruefbaren Beleg.
- **Platform Drift:** ein Tool funktioniert in einem Turn und wird im naechsten blockiert.
- **Capability Drift:** Status und konkreter Toolcall widersprechen sich.
- **Secret Drift:** Ausgaben enthalten Material, das nicht in den Chat gehoert.

## Nutzenklassen

- **Operationsnaehe:** ChatGPT bleibt im Takt der Arbeit.
- **Auditierbarkeit:** jeder Griff hat Task-ID, Log, Diff oder Review.
- **Sicherheit:** kein breiter Ersatz fuer blockierte Macht.
- **Pragmatik:** vorhandene Grabowski-Tasks werden genutzt, bevor neue Infrastruktur entsteht.
- **Lernfaehigkeit:** Blockaden werden als Friction-Events dokumentiert.

## Praxisablauf v0

1. Lage mit engem Grabowski-Read pruefen.
2. Direktes typed Tool bevorzugen.
3. Bei Blockade: kleinste Handlung formulieren.
4. Executor nach Matrix waehlen.
5. Micro-Handoff starten.
6. Receipt lesen.
7. ChatGPT entscheidet den naechsten Griff.
8. Friction-Event schreiben, wenn ein Block oder Contract-Fehler relevant war.

## Does not establish

Dieses Protokoll etabliert nicht:

- dauerhafte Agentenautonomie,
- neue Privilegien,
- Secret-Zugriff,
- automatischen Merge,
- automatischen Deploy,
- freie Shell als Normalpfad,
- Umgehung von Plattform- oder Host-Sicherheitsgrenzen.

## Kurzform

Grabowski bleibt die Hand. Der Controller traegt die Integrationsautoritaet; Implementierung kann an einen explizit gebundenen scoped Writer delegiert werden. Modellnamen steuern Routingpraeferenzen, nicht Autoritaet; Reviewer und Observer bleiben read-only.
