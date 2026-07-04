# Blocked Action Protocol v0

## These / Antithese / Synthese

These: ChatGPT bleibt der Operator fuer Grabowski. Direkte Grabowski-Tools bleiben der erste Griff, weil sie naehere Kontrolle, Audit und sofortige Ruecknahme erlauben.

Antithese: Ein blockierter oder zu breiter Toolcall darf nicht durch eine zweite freie Fernbedienung ersetzt werden. Ein Helfer, der beliebige Befehle autonom weiterfuehrt, verschiebt nur das Risiko und verschlechtert die Sichtbarkeit.

Synthese: Wenn ChatGPT ein einzelner Griff verwehrt ist, wird genau dieser Griff als begrenzter Micro-Handoff abgegeben. Danach muss ein Receipt vorliegen, und ChatGPT nimmt die Arbeit wieder auf, bevor der naechste Griff erfolgt.

## Zweck

Dieses Protokoll legt fest, wie mit blockierten ChatGPT/Grabowski-Operationen umzugehen ist, ohne ChatGPT als Operator abzugeben.

Es etabliert keinen neuen Privilegienpfad, keine dauerhafte Agentenautonomie und keinen Ersatz fuer bestehende Grabowski-Policies. Es beschreibt eine Betriebsregel: direkt ausfuehren, falls eng genug; sonst einen einzelnen Griff abgeben; danach Ergebnis pruefen und wieder aufnehmen.

## Nutzer-Eskalationsgrenze

Der Nutzer ist Entscheidungsinstanz, nicht Standard-Executor. Bei Plattformblockade muss ChatGPT zuerst interne Relay-Pfade nutzen: engeres Typed Tool, Grabowski Micro-Task, Codex, Claude, agy, lokale KI oder Patch-Relay. Nutzerkontakt ist Entscheidungseskalation, kein Ersatz fuer einen blockierten Griff.

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

3a. **Steuerboard context signal**
   - Bei Repo-, PR-, Branch-, Pull-, Switch- und Merge-Prep-Arbeit kann `steuerboard operator report --branch-warning-threshold 5 --json` als leichter read-only Kontextgriff genutzt werden, wenn die Zielrepo-Lage relevant ist.
   - Der Probelauf gilt als bestanden; es wird keine separate `useful_signal`/`changed_decision`/`noise` Trial-Metrik weitergefuehrt.
   - Nur zielbezogene Felder zaehlen. Globale Branch-Drift ist Kontext, kein Alarm.
   - Der Report ist kein Gate, keine Genehmigung und kein Ersatz fuer Git-Status, PR-Checks, Review-Gates oder Action-Readiness.

Danach wird nach Aufgabenklasse geroutet.

4. **Codex exec/review**
   - Standard fuer komplexe Code- und Repo-Slices.
   - Auftrag endet nach Diff, Test oder Stop-Bericht.
   - Default: kein Commit, kein Push, kein Merge.

5. **agy print / Ollama API**
   - `agy --print` ist Standard fuer schnelle leichte Denk-, Sortier- und Klassifikationsgriffe.
   - Ollama API mit qwen coder ist Standard fuer lokale Mikro-Reasoning- und Shell-Vorschlagsgriffe ohne Cloud.
   - Beide erzeugen kurze Receipts; sie treffen keine Merge-, Push- oder Deploy-Entscheidungen.

6. **Claude Review**
   - Beste Wahl fuer Architektur-, Sicherheits- oder Review-Fragen.
   - Default: lesen, bewerten, Risiken benennen; keine Mutation.

7. **tmux / agy Session**
   - tmux ist Standard fuer vorhandene Sessions, Capture und Resume-Kontexte.
   - agy ist fuer Session/Resume nur dann besser, wenn der Ruecknahmebeleg klarer ist.

8. **Patch file relay**
   - Lokale Patchdateien werden mit `tools/operator_patch_relay.py` geprueft und bei expliziter Entscheidung angewendet.
   - Der Relay schreibt ein JSON-Receipt; manueller Patchdownload durch den Nutzer ist nur der letzte Notausgang.
   - Der Relay merged, pusht und deployt nicht.

9. **Goose / Qwen / Aider**
   - Goose und Qwen sind optionale lokale Agent-Alternativen, nicht der Standardpfad.
   - Aider bleibt ein bounded Patch-Fallback mit deaktiviertem Auto-Commit.

## Executor-Matrix

| Blockierte Klasse | Primaerer Ersatz | Warum | Ruecknahmebeleg |
| --- | --- | --- | --- |
| Status/Health blockiert | engeres Typed Tool oder Micro-Task | geringes Risiko, sofort pruefbar | Status JSON oder Logtail |
| Repo-/Branch-Lage fuer Zielrepo unklar | Steuerboard operator report | leichtes read-only Lagebild ohne Freigabe | operator-report JSON, nur zielrelevante Felder |
| kurzer Shell-Griff blockiert | Grabowski Micro-Task | bleibt unter Grabowski-Audit | task_id, status, logs |
| komplexer Code-/Repo-Slice | Codex exec/review | Standard fuer anspruchsvolle Repo-Arbeit | diff, changed files, Tests |
| lokaler Patch aus Chat/Artefakt | operator_patch_relay.py | prueft und wendet lokal mit Head- und Dirty-Gates an | JSON-Receipt plus Git-Diff |
| Review-/Architekturunsicherheit | Claude Review | bessere Kontrastpruefung | Review mit konkreten Befunden |
| interaktive Sessionfrage | tmux capture, agy bei besserem Resume | Resume-naehe | Capture-Auszug, naechste Eingabe |
| lokale Mikro-Reasoning-Frage | Ollama API mit qwen coder | lokal, billig und begrenzt | kurze Antwort oder Vorschlagsliste |

## Micro-Handoff Contract

Ein Micro-Handoff ist nur gueltig, wenn er diese Felder gedanklich oder maschinenlesbar festlegt:

```json
{
  "step_id": "unique-step-id",
  "operator": "chatgpt-grabowski",
  "executor": "grabowski-task|codex|claude|agy|local-ai",
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
  "executor": "grabowski-task|codex|claude|agy|local-ai",
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

### Codex

Codex ist der primaere Helfer fuer komplexe Code- und Repo-Slices. Der richtige Modus ist `exec` oder `review`: begrenzter Scope, kein Commit, kein Push, Stop nach Diff oder Test.

### Claude

Claude ist Review- und Architekturhelfer. Claude soll schwierige Invarianten, Sicherheitslogik und Alternativen pruefen. Claude ist nicht der Standardgriff fuer schnelle Shell-Aktionen.

### agy

agy ist Standard fuer schnelle leichte One-Shots per `agy --print`. Fuer interaktive Arbeitsraeume und Resume ist agy nur dann besser als tmux, wenn der Ruecknahmebeleg klarer ist.

### Lokale KI / Goose / Ollama

Ollama ist Standard fuer lokale Mikro-Reasoning-Aufgaben ueber die HTTP API, bevorzugt mit qwen coder. Lokale KI darf nicht zum heimlichen Daueroperator werden.

### Aider

Lokale Patchdateien sollen zuerst ueber `tools/operator_patch_relay.py` laufen. Aider bleibt ein Kandidat fuer Patch-Slices. Aider wird gegen Codex anhand von Diff-Qualitaet, Scope-Treue und Testbelegen verglichen, nicht anhand von Versprechen.

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

Grabowski bleibt die Hand. Codex wird das Skalpell fuer Code. Claude wird der zweite Blick. agy bleibt ein moeglicher Arbeitsraum. Lokale KI bleibt Hilfslicht. ChatGPT bleibt Operator.
