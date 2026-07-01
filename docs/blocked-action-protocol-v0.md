# Blocked Action Protocol v0

## These / Antithese / Synthese

These: ChatGPT bleibt der Operator fuer Grabowski. Direkte Grabowski-Tools bleiben der erste Griff, weil sie naehere Kontrolle, Audit und sofortige Ruecknahme erlauben.

Antithese: Ein blockierter oder zu breiter Toolcall darf nicht durch eine zweite freie Fernbedienung ersetzt werden. Ein Helfer, der beliebige Befehle autonom weiterfuehrt, verschiebt nur das Risiko und verschlechtert die Sichtbarkeit.

Synthese: Wenn ChatGPT ein einzelner Griff verwehrt ist, wird genau dieser Griff als begrenzter Micro-Handoff abgegeben. Danach muss ein Receipt vorliegen, und ChatGPT nimmt die Arbeit wieder auf, bevor der naechste Griff erfolgt.

## Zweck

Dieses Protokoll legt fest, wie mit blockierten ChatGPT/Grabowski-Operationen umzugehen ist, ohne ChatGPT als Operator abzugeben.

Es etabliert keinen neuen Privilegienpfad, keine dauerhafte Agentenautonomie und keinen Ersatz fuer bestehende Grabowski-Policies. Es beschreibt eine Betriebsregel: direkt ausfuehren, falls eng genug; sonst einen einzelnen Griff abgeben; danach Ergebnis pruefen und wieder aufnehmen.

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

## Fallback-Leiter

1. **Typed Grabowski Tool**
   - Erste Wahl fuer Status, Git-Status, Service-Status, Logs, Runtime-Health, Audit und andere schmale Operationen.
   - Beispiel: `grabowski_runtime_health`, `grabowski_git_status`, `grabowski_task_status`.

2. **Grabowski Micro-Task**
   - Erste Wahl fuer kurze Shell-nahe Handgriffe, wenn kein passendes Typed Tool existiert oder ein direktes Tool blockiert.
   - Muss begrenzt sein durch `cwd`, `runtime_seconds`, Memorylimit und optional gueltige `resource_keys`.
   - Danach sind `task_status` und `task_logs` Pflicht.

3. **Codex Once**
   - Beste Wahl fuer kleine Repo-Code-Slices.
   - Auftrag endet nach Diff, Test oder Stop-Bericht.
   - Default: kein Commit, kein Push, kein Merge.

4. **Claude Review**
   - Beste Wahl fuer Architektur-, Sicherheits- oder Review-Fragen.
   - Default: lesen, bewerten, Risiken benennen; keine Mutation.

5. **agy / tmux Session**
   - Geeignet fuer interaktive Arbeitsraeume und Resume-Kontexte.
   - Nicht Standard fuer Maschinenreceipts, solange keine klare Resultatdatei oder Loggrenze existiert.

6. **Lokale KI / Goose / Ollama / Aider**
   - Nur fuer niedrigriskante Recherche, einfache Patches oder Vergleichstests.
   - Nicht primaerer Executor ohne vorherigen Beleg besserer Rueckaufnahmequalitaet.

## Executor-Matrix

| Blockierte Klasse | Primaerer Ersatz | Warum | Ruecknahmebeleg |
| --- | --- | --- | --- |
| Status/Health blockiert | engeres Typed Tool oder Micro-Task | geringes Risiko, sofort pruefbar | Status JSON oder Logtail |
| kurzer Shell-Griff blockiert | Grabowski Micro-Task | bleibt unter Grabowski-Audit | task_id, status, logs |
| Dateipatch blockiert | Codex Once | spezialisiert auf Repo-Diffs | diff, changed files, Tests |
| Architekturunsicherheit | Claude Review | bessere Kontrastpruefung | Review mit konkreten Befunden |
| interaktive Sessionfrage | agy oder tmux capture | Resume-naehe | Capture-Auszug, naechste Eingabe |
| einfache lokale Suche | lokale KI oder Micro-Task | billig und begrenzt | Trefferliste mit Pfaden |

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

Codex ist der primaere Helfer fuer Code-Slices. Der richtige Modus ist `once`: begrenzte Dateien, kein Commit, kein Push, Stop nach Diff oder Test.

### Claude

Claude ist Review- und Architekturhelfer. Claude soll schwierige Invarianten, Sicherheitslogik und Alternativen pruefen. Claude ist nicht der Standardgriff fuer schnelle Shell-Aktionen.

### agy

agy ist interessant fuer interaktive Arbeitsraeume und Resume, aber nur dann besser als Grabowski Micro-Tasks, wenn der Ruecknahmebeleg klarer ist.

### Lokale KI / Goose / Ollama

Lokale KI ist optional fuer niedrigriskante Such- und Vergleichsaufgaben. Sie darf nicht zum heimlichen Daueroperator werden.

### Aider

Aider bleibt ein Kandidat fuer Patch-Slices. Aider wird gegen Codex anhand von Diff-Qualitaet, Scope-Treue und Testbelegen verglichen, nicht anhand von Versprechen.

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
