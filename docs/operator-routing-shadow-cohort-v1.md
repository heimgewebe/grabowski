# Operator routing shadow cohort v1

Stand: 2026-07-23

## Zweck

Diese Stufe sammelt prospektiv Routing-Shadow-Fälle aus realer Agent-Workspace-Nutzung. Sie erweitert den in PR #410 eingeführten Capture-Vertrag, ohne Routing-, Policy-, Queue-, Merge-, Deploy-, Runtime- oder ML-Autorität zu erzeugen.

Der entscheidende Zusatz ist ein zweistufiger Eligibility-Vertrag:

1. `operator-routing-shadow-prospective-eligibility.v1` friert Workspace-, Plan- und kanonische Route-Identität ein, solange noch keine Workspace-Task-ID gebunden ist.
2. `operator-routing-shadow-eligibility.v2` bindet diesen unveränderlichen Freeze später an die tatsächlich gestartete Grabowski-Task-ID.
3. `operator-routing-shadow-record.v2` versiegelt danach ausschließlich ein unabhängig geliefertes reviewed Outcome mit Primärevidenz oder eine explizite Abstention.

V1-Eligibility und V1-Records aus PR #410 bleiben unverändert unterstützt.

## Warum ein neuer Eligibility-Vertrag nötig ist

Der V1-Vertrag verlangt bereits beim Freeze eine 24-stellige Grabowski-Task-ID, die im Workspace-Manifest referenziert sein muss. Beim frühesten sicheren Prospektivitätszeitpunkt existiert diese Task-ID noch nicht: `grabowski_agent_workspace_create` schreibt zuerst den Plan, startet die Writer-Task aber erst später.

Ein Freeze erst nach `grabowski_task_start` könnte bei sehr kurzen Aufgaben Outcome-Beobachtung und Eligibility zeitlich nicht strikt trennen. V2 löst diese Lücke, ohne V1 umzudeuten oder eine künstliche Task-ID zu erfinden.

## Triggervergleich

### A. Agent-Workspace-Lifecycle-Hook

**Stärken:** früheste kanonische Route Evidence; echte Prospektivität; eindeutige Workspace-/Plan-Identität.

**Risiko:** Kopplung an einen Runtime-kritischen Pfad.

**Entscheidung:** nur ein sehr kleiner fail-open Freeze-Hook unmittelbar nach dem ersten Manifest-Write und vor Lease, Worktree, Preflight und Task-Start. Der Hook schreibt ausschließlich private Shadow-Artefakte und einen begrenzten Audit-Status. Jeder Capture- oder Auditfehler wird lokal abgefangen und darf die Workspace-Erzeugung nicht blockieren.

### B. Chronik-/Outcome-basierter Collector

**Stärken:** starke Autoritätstrennung für spätere Outcomes; Eventual Consistency ist akzeptabel; reviewed Outcome und Primärevidenz können getrennt angeliefert werden.

**Grenze:** allein kann dieser Weg nicht beweisen, dass Eligibility vor Outcome-Beobachtung feststand.

**Entscheidung:** als getrennte Seal-Seite des Vertrages übernehmen. Der Workspace-Lifecycle erzeugt keine semantischen Labels.

### C. Periodischer read-only Reconciler

**Stärken:** geringe Kopplung an Workspace-Code.

**Grenze:** ein reiner Nachlauf kann nachträgliche Selektion nicht ausschließen und echte Prospektivität nicht zuverlässig herstellen.

**Entscheidung:** nicht als Eligibility-Quelle. Ein späterer Reconciler darf nur bereits prospektiv eingefrorene Receipts binden oder versiegeln und muss dieselben create-only-/identity-bound Regeln verwenden.

## Kohortenvertrag

Aufgenommen werden alle Workspace-Fälle, für die vor Task-Start evidence-complete kanonische Agent-Workspace-Route-Evidence deterministisch validiert werden kann.

- Route-Schema v1 und v2 bleiben explizit unterscheidbar.
- Es werden keine Fälle aus argv, Logs, Prompts oder Narrativen rekonstruiert.
- Ein fehlendes oder unvollständiges Route-Receipt erzeugt keinen gültigen Fall, sondern einen begrenzten Capture-Attempt mit Ablehnungsgrund.
- Abbruch, Infrastrukturfehler oder Lifecycle-Erfolg erzeugen niemals automatisch ein semantisches Erfolgslabel.
- Ist keine unabhängige semantische Bewertung vorhanden, bleibt der Fall `abstained`.
- Reviewed Outcomes benötigen mindestens eine allowlistete Primärevidenzreferenz.
- Derselbe Workspace-/Plan-/Route-Fall behält beim Restart den ersten real geschriebenen Freeze; spätere Wiederholungen werden als Duplikat erkannt.
- Parallele Workspaces erhalten unterschiedliche Case-Identitäten und können nicht über Task- oder Workspace-ID gekreuzt gebunden werden.

Diese Regeln verhindern bewusst keine unausgewogene reale Verteilung. Sie verhindern stattdessen, dass nur erfolgreiche Fälle nachträglich ausgewählt und dadurch künstlich positive Trainingsdaten erzeugt werden.

## Speicher- und Privacy-Grenze

Standardwurzel:

`~/.local/state/grabowski/operator-routing-shadow-cohort`

Unterverzeichnisse:

- `prospective/`: erster prospektiver Freeze pro Workspace-Fall;
- `eligibility/`: spätere Task-Bindung;
- `records/`: versiegelte Outcome-Records;
- `attempts/`: begrenzte Audit-Receipts für Freeze-Versuche.

Verzeichnisse werden owner-private (`0700`) geöffnet oder erzeugt. Records werden create-only mit `0600`, `O_EXCL` und `O_NOFOLLOW` geschrieben. Symlink-Traversal wird abgelehnt.

Nicht gespeichert werden Prompts, Transkripte, private Notizen, Umgebungswerte, unbeschränkte argv oder vollständige Workspace-Manifeste. Gespeichert werden nur allowlistete Routing-Features, Identitäts-Hashes und bounded Primärevidenzreferenzen.

## No-Effect-Vertrag

Jedes Prospective-, Eligibility-, Record- und Attempt-Artefakt trägt denselben unveränderlichen Vertrag:

- `proposal_only = true`
- `routing = false`
- `policy = false`
- `queue = false`
- `merge = false`
- `runtime = false`

`runtime = false` bedeutet: Das Artefakt besitzt keine Runtime-Entscheidungsautorität. Die lokale, fail-open Datenerfassung selbst ist der beabsichtigte Effekt dieser Stufe; sie darf jedoch keine operative Entscheidung oder Ausführung verändern.

## Fehlerverhalten

- Capture-Fehler blockieren Workspace-Erzeugung nicht.
- Unklare Evidenz erzeugt keinen gültigen Eligibility- oder Outcome-Record.
- Rejected/Error-Versuche werden nach Möglichkeit als begrenzte Attempt-Receipts sichtbar gemacht.
- Ein Ausfall auch dieses Audit-Schreibpfads bleibt fail-open und wird nicht als erfolgreicher Capture behauptet.
- Existing-but-identical ist idempotentes Duplikat, kein Update.
- Existing-but-conflicting ist ein Fehler und wird niemals überschrieben.

## Separate Seal-Schnittstelle

`tools/operator_routing_shadow_cohort.py` bindet ein bereits prospektiv eingefrorenes Receipt an ein späteres Workspace-Manifest und eine reale Task-ID und versiegelt ein extern bereitgestelltes Outcome.

Die Schnittstelle leitet kein Outcome aus Lifecycle-Status ab. Das Outcome-Input muss exakt `outcome` und `primary_evidence_refs` enthalten. Reviewed Outcomes ohne Primärevidenz werden abgelehnt; Abstention bleibt Abstention.

## Nicht etabliert

Diese Stufe etabliert ausdrücklich nicht:

- ML-Trainingsreife;
- Repräsentativität der Kohorte;
- ausreichende Fallzahl;
- Klassenbalance;
- Routing-Überlegenheit eines Modells;
- automatische Modellselektion;
- Änderung der Routing-Policy;
- Online-Lernen;
- autonome Policy-Promotion.

Diese Fragen benötigen getrennte Readiness- und Offline-Evaluationsentscheidungen.
