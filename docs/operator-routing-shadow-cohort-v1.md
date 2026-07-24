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

## Integrität und Lineage

### Stabile allowlistete Manifest-Identität

Die kanonische Route-Evidenz bindet keine Hashwerte über das vollständige Manifest. Statt eines `manifest_sha256` über das gesamte Manifest trägt jede Referenz einen `manifest_identity_sha256`, der ausschließlich `workspace_id`, `plan_sha256` und den kanonischen `route_evidence_sha256` bindet. Private Felder (`private_note`, `commands`, Prompts, argv) und mutierende Lifecycle-Felder (`created_at`, `updated_at`, `tasks`, ...) fließen nicht ein. Dadurch ist der Digest zwischen prospektivem Freeze und späterer Task-Bindung identisch und enthält keine privaten Content-Hashes.

### Selbstvalidierende Lineage

Prospective, Eligibility v2 und Record v2 sind vollständig aus ihren eigenen stabilen Feldern nachrechenbar:

- `workspace_case_id` = deterministischer Digest über `workspace_id`, `plan_sha256` und `route_evidence_sha256`.
- `prospective_eligibility_id` wird aus der vollständig rekonstruierten prospektiven Payload verifiziert.
- Eligibility v2 rechnet `eligibility_id` über die vollständige Payload nach und beweist zusätzlich die prospektive Kette.
- Record v2 trägt die stabilen prospektiven Identitätsfelder (`workspace_id`, `plan_sha256`, `workspace_case_id`) in seiner Eligibility-Referenz und rekonstruiert daraus die vollständige Eligibility-v2-Payload; eine gefälschte, in sich konsistente `record_id` mit falscher `eligibility_id` wird abgelehnt.

### V2-Bindung nur an die Writer-Task

Eligibility v2 bindet ausschließlich die routingrelevante Writer-Task-ID. Beliebige referenzierte Test- oder Review-Task-IDs werden abgelehnt. V1 bleibt unverändert.

### Bounded Attempt-Identität

Die Attempt-Identität ist stabil über `workspace_id`, `plan_sha256`, `stage`, `status`, `reason_code` und `prospective_eligibility_id`. Sie bindet bewusst nicht `attempted_at`. Ein idempotenter Retry bewahrt den ersten `attempted_at`, sodass wiederholte identische Rejects oder Duplicates keine unbegrenzte Zahl von Attempt-Dateien erzeugen.

### Kanonische UTC-Z-Zeitstempel

`_parse_timestamp` projiziert äquivalente Offsets auf einen einzigen kanonischen UTC-Z-Instant. Builder normalisieren Eingaben; Validatoren lehnen nichtkanonisch gespeicherte Zeitstempel (auch `+00:00`) ab. Zeitordnung `frozen_at ≤ observed_at ≤ captured_at` wird geprüft.

### Kanonische Primärevidenz

`primary_evidence_refs` verlangt einen allowlisteten Präfix mit nichtleerem, bounded Suffix; ein reiner Präfix wie `github-ci:` wird abgelehnt. Da die Reihenfolge keine Semantik trägt, werden Referenzen deterministisch sortiert, damit identische Evidenzmengen denselben Record ergeben.

## Speicher- und Privacy-Grenze

Standardwurzel:

`~/.local/state/grabowski/operator-routing-shadow-cohort`

Unterverzeichnisse:

- `prospective/`: erster prospektiver Freeze pro Workspace-Fall;
- `eligibility/`: spätere Task-Bindung;
- `records/`: versiegelte Outcome-Records;
- `attempts/`: begrenzte Audit-Receipts für Freeze-Versuche.

Verzeichnisse werden owner-private (`0700`) geöffnet oder erzeugt. Symlink-Traversal wird abgelehnt.

Records werden crash-sicher create-only publiziert: Eine owner-private (`0600`) Temp-Datei im selben Verzeichnis wird vollständig geschrieben und mit `fsync(file)` durabel gemacht, danach wird der finale Name atomar und ohne Überschreiben per no-replace Hard-Link beansprucht, die Temp-Datei entfernt und `fsync(directory)` ausgeführt. Ein Crash vor der finalen Publikation hinterlässt höchstens eine verwaiste Temp-Datei und vergiftet niemals den finalen Slot. Ein bereits belegter Zielname wird als eigener Exception-Typ (`ShadowRecordExistsError`) signalisiert, nicht über Textabgleich.

Nicht gespeichert werden Prompts, Transkripte, private Notizen, Umgebungswerte, unbeschränkte argv oder vollständige Workspace-Manifeste. Es werden keine privaten Content-Hashes gebunden. Gespeichert werden nur allowlistete Routing-Features, stabile Identitäts-Hashes und bounded Primärevidenzreferenzen.

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
- Beim Seal werden Outcome, Evidenz und Zeitordnung vollständig validiert und der Record in-memory gebaut, bevor Eligibility oder Record persistent geschrieben werden. Ein Record-I/O-Fehler hinterlässt höchstens ein gültiges Eligibility-Teilresultat; ein Retry rekonstruiert dieselbe Eligibility als Duplikat und konvergiert sauber zum Record.

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


## Observability-Vertrag v3

Neue prospektive Fälle verwenden `operator-routing-shadow-prospective-eligibility.v2`. Der Freeze bindet `case_provenance.case_origin` (`production`, `test`, `synthetic` oder `quarantined`) per Hash, bevor ein Task-Outcome existiert. Bestehende v1-Prospektiv-Receipts und ihre v2-Eligibility-/Record-Kette bleiben unverändert lesbar; fehlende Provenienz historischer Records bleibt ausdrücklich unbeobachtbar und wird nie nachträglich ergänzt.

Ein v2-Prospektiv-Receipt wird an `operator-routing-shadow-eligibility.v3` gebunden und als `operator-routing-shadow-record.v3` versiegelt. Record v3 hält das semantische Outcome getrennt von `execution_provenance` (`completed`, `execution_aborted`, `infrastructure_failure` oder explizit `unknown`) und kann entweder keine oder zwei bis vier unabhängig pseudonymisierte semantische Bewertungen derselben Outcome-Art binden. Unterschiedliche `reviewer_pseudonym_sha256` machen Review-Abweichungen messbar, ohne Namen, Prompts, Transkripte, private Notizen oder unbeschränkte argv zu speichern. Fehlende Bewertungen und fehlende Ausführungsbeobachtung werden als leere Liste beziehungsweise `unknown` dargestellt, niemals als Übereinstimmung oder Erfolg.

Diese Erweiterung bleibt reine Capture-Beobachtbarkeit. Sie trainiert kein Modell, ändert weder Routing noch Queue- oder Policy-Zustand, trifft keine Laufzeitentscheidung für den beobachteten Task und autorisiert `OPERATOR-ML-READINESS-V1-T002` nicht. Sie macht ausschließlich die Qualitätssignale messbar, die für eine spätere erneute T004-Prüfung erforderlich sind.
