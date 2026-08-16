# Coding-Agent-Routing v4 — Agent Execution Fabric

## 1. Kanonische Regel

Grabowski trennt Ausführungsautorität, Writerwahl und Verification.

Die Autorität folgt nicht dem Modellnamen. Sie folgt der gebundenen Rolle und der Work Lane:

- `controller` plant, integriert, merged, deployt und schließt ab;
- `scoped_writer` darf nur innerhalb einer explizit gebundenen Lane implementieren und testen;
- `reviewer` arbeitet read-only und advisory;
- `observer` liefert nur Evidenz.

Für überlappenden Scope gibt es genau einen autoritativen mutierenden Writer. Disjunkte Work Lanes dürfen parallel laufen.

Die Work Lane ist der Autoritäts- und Wirkungscontainer. Agent Workspace ist die Ausführungs- und Verification-Schicht innerhalb einer Lane. Der lane-backed Modus bindet eine exakte `lane_id` plus erwarteten Lane-Receipt-SHA-256 und verwendet ausschließlich deren Repository-, Branch-, Worktree-, Scope-, Writer-, Lease-, Admission- und Checkout-Lifecycle-Autorität. Der historische advisory-contrast-Modus bleibt als eigener Legacy-Pfad erhalten.

## 2. Maschinenlesbare Quellwahrheit

Die kanonische Routingimplementation liegt in `src/grabowski_coding_agent_router.py`:

- interne Implementierung: `canonical_execution_route`;
- öffentliche Oberfläche: `grabowski_coding_agent_route`.

`grabowski_agent_execution_route` in `src/grabowski_agent_competition.py` ist nur noch ein Kompatibilitätsadapter. Seine historische Workspace-/Kontrastbewertung darf keine eigene Executor-Autorität begründen.

Der Rollen- und Effektvertrag liegt ergänzend in `src/grabowski_operator_relay.py`. Er definiert dieselben vier Rollen und die controller-only Wirkungen. Er ist kein zweiter Router.

## 3. Kanonische Routingachsen

Jede aktuelle Routingentscheidung veröffentlicht unabhängig voneinander:

- `executor`: `controller` oder `scoped_writer`;
- `writer_route`: konkrete Route, zum Beispiel `codex-sol-high`, oder `grabowski-primary` beim Controller;
- `effect_profile`: in dieser Phase `candidate`;
- `verification_policy`: `deterministic`, `independent_review` oder `competition`;
- `risk`: normalisierte Risikoevidenz aus Flags, Neuheit und kritischer Taskklasse;
- `task_class`.

`effect_profile=delivery` ist absichtlich noch nicht freigeschaltet. Commit-/Push-/PR-Wirkungen des delegierten Writers gehören in die spätere Delivery-Phase und dürfen durch P0 nicht vorweggenommen werden.

`verification_policy` ist keine Autoritätsklasse. Insbesondere macht `competition` aus einem Reviewer oder Vergleichskandidaten keinen Writer.

## 4. Controllerintegration versus Executor

Der historische Schlüssel

`decision=controller`

bleibt vorübergehend aus Kompatibilitätsgründen erhalten. Seine Semantik ist ausdrücklich:

`decision_semantics=integration_owner_compatibility`

Er bedeutet: Der Controller bleibt Integrator und Abschlussinstanz.

Er bedeutet nicht: Der Controller muss jede Implementierung selbst schreiben.

Die tatsächliche Ausführungsentscheidung steht ausschließlich in `executor` und `writer_route`.

Damit sind diese Aussagen miteinander vereinbar:

- `decision=controller`;
- `integration_owner=controller`;
- `executor=scoped_writer`;
- `writer_route=codex-sol-high`;
- `controller_integration_required=true`.

## 5. Writerwahl

Für nicht controller-eigene Taskklassen darf der Router einen `scoped_writer` wählen, wenn eine aktuelle, kataloggebundene und ausführbare Route vorhanden ist.

Ist keine belastbare Writerroute verfügbar, fällt die konkrete Ausführung auf den Controller zurück. Das ist ein Verfügbarkeitsfallback, keine Rückkehr zur alten Direct-only-Doktrin.

Die Policy bleibt deshalb:

- `direct_implementation_required=false`;
- `delegated_scoped_writers_allowed=true`;
- `external_primary_writer_forbidden=false`;
- `controller_integration_required=true`.

Controller-eigene Taskklassen, Integrationsarbeit, Merge, Deployment, Recovery und Closeout bleiben beim Controller.

## 6. Work-Lane-Bindung

Eine Routingempfehlung allein erteilt keine Schreibautorität.

Ein delegierter Writer wird erst autoritativ innerhalb seines Scopes, wenn eine Work Lane bindet:

- Source;
- Controller Actor;
- Scoped Writer Actor;
- Repository;
- Base Head;
- Branch;
- Worktree;
- Write Scope;
- Resource Leases;
- Checkout Lifecycle.

Der gewünschte Prepare-only-Pfad ist:

`grabowski_work_acquire`

mit gesetztem `scoped_writer_actor` und `scoped_writer_argv=None`.

Dadurch besitzt die Lane bereits Checkout und Ressourcen, ohne einen zweiten Writer-Lifecycle zu starten.

Diese Prepare-only-Grenze ist verpflichtend: Der Lane-Receipt darf weder einen konfigurierten `scoped_writer_command` noch `writer_job` oder sonstigen `writer_start`-Ausführungszustand enthalten. Andernfalls lehnt der lane-backed Workspace die Erstellung ab, bevor er seinen eigenen Writer startet; innerhalb desselben überlappenden Lane-Scopes darf nie ein zweiter mutierender Writer entstehen.

`grabowski_agent_workspace_create` besitzt deshalb zwei disjunkte Modi:

- ohne Lane-Bindung bleibt der bisherige advisory-contrast-Pfad unverändert und besitzt seine bisherigen Workspace-Ressourcen;
- mit `lane_id` und `expected_lane_receipt_sha256` muss Source, Repository, Base, Branch, Worktree, vollständiger Write Scope, Scoped Writer, jede Live-Lease, die vorhandene Repository-Admission und der aktive Checkout-Lifecycle exakt zur hashgültigen Lane passen.

Der lane-backed Modus ist in dieser Phase ausdrücklich ein Working-Tree-Patch-Modus. Der Writer-Checkout-`HEAD` muss während Erstellung, Revalidierung und Collection unverändert `expected_base_head` bleiben. Ein Commit oder anderer HEAD-Advance wird durch die Live-Lane-Prüfung noch vor der Collection abgewiesen. `Delivery`, `commit_range` und jede Aufweichung dieser HEAD-Bindung liegen außerhalb dieses Vertrags.

Bei der ersten lane-backed Erstellung bindet der Plan außerdem genau eine unveränderliche `runtime_deadline_unix` aus Erstellungszeit plus `runtime_seconds`. Jede Live-Lease der Lane sowie sowohl die quittierte als auch die live beobachtete Checkout-Lifecycle-Retention müssen diese Deadline mindestens erreichen; Gleichheit ist ausreichend. Spätere Lane-Revalidierungen und idempotente Create-Aufrufe verwenden dieselbe gespeicherte Deadline und berechnen sie nicht erneut relativ zu „jetzt“. Der Workspace erhält dadurch weder eine neue State-Ablage noch Renewal-Autorität und verlängert die Lane-Ressourcen nicht selbst.

Der lane-backed Workspace reserviert keine zweite Lease oder Checkout-Generation, führt keine zweite Repository-Admission aus und erzeugt keinen Worktree. Create-Fehler und Workspace-Close erhalten sämtliche Lane-Ressourcen. Seine Close-Receipt weist deshalb `resources_released=false`, `lane_resources_preserved=true` und `workspace_resources_owned=false` aus; dieser Erhalt erfüllt den Workspace-Ausführungsabschluss, ohne einen Lane-Close zu behaupten. Workspace-Cleanup bleibt für diesen Modus gesperrt und verweist auf den separaten Work-Lane-Closeout.

## 7. Verification

Die drei Policies sind:

### deterministic

Deterministische Tests und Prüfungen ohne zusätzlichen unabhängigen LLM-Reviewer.

### independent_review

Deterministische Prüfungen plus unabhängiger read-only Review, wenn Aufgabe oder Risiko dies rechtfertigen.

Explizite Review-Taskklassen wie `independent-review`, `critical-review` und `security-review` erzwingen diese Policy.

### competition

Expliziter Vergleich mehrerer Kandidaten oder Ansätze. Competition bleibt ein Verification-/Vergleichsmodus. Sie ändert weder Lane-Ownership noch Integrationsautorität.

Wenn `need_review=true` gesetzt ist, kann die Anfrage nicht gleichzeitig `verification_policy=competition` erzwingen. Widersprüchliche Fakten werden fail-closed abgewiesen.

## 8. Legacy-Adapter

`grabowski_agent_execution_route` bleibt vorübergehend lesbar, damit bestehende Workspace-Routenevidenz und Shadow-Kalibrierung nicht gebrochen werden.

Der Adapter ruft für die Autoritätsentscheidung `canonical_execution_route` auf und übernimmt daraus mindestens:

- `executor`;
- `writer_route`;
- `effect_profile`;
- `verification_policy`;
- `risk`;
- `integration_owner`;
- `direct_implementation_required`;
- `delegated_scoped_writers_allowed`;
- `external_primary_writer_forbidden`;
- `controller_integration_required`.

Die historischen Felder `execution_mode`, `risk_tier`, `score`, `external_candidates` und `parallel_writer_pilot` bleiben nur für Legacy-Workspace-/Contrast-Replay bestehen.

Der Adapter markiert deshalb:

- `adapter_status=deprecated_compatibility_adapter`;
- `execution_mode_deprecated=true`;
- `execution_mode_scope=legacy_workspace_contrast_shape_only_not_executor_authority`.

Ein Wert wie `execution_mode=direct_operator` darf damit nicht mehr als Aussage über den kanonischen `executor` gelesen werden.

## 9. Review- und Kontrastrouten

Plan-/Review-Routen bleiben read-only. Eine Route mit planartigem Permission-Modus darf nicht stillschweigend Writerautorität erhalten.

Kontrastrouten dürfen mutierende Kandidaten in ihrem isolierten Vergleichspfad erzeugen, wenn der bestehende Competition-Vertrag dies erlaubt. Diese Kandidaten bleiben advisory, bis der Controller sie in einen autoritativen Lane-/Candidate-Pfad übernimmt.

Das ist von einem echten `scoped_writer` zu unterscheiden: Ein lane-gebundener Scoped Writer ist innerhalb seiner Lane autoritativ für die delegierte Implementierung, aber nicht für Integration, Merge, Deployment oder Closeout.

## 10. Kosten und Verfügbarkeit

Modell- und Harnessqualität beeinflusst die konkrete Writer- oder Reviewerroute, nicht die Autorität.

Der Katalog bleibt fail-closed für:

- unbekannte oder verbotene Kostenpfade;
- PAYG-Fallbacks ohne Freigabe;
- erschöpfte oder stale Quota-Evidenz;
- ungültige Route-/Permission-Verträge.

Subscription-gebundene, aktuell attestierte Routen dürfen im vorhandenen Kontingent gerankt werden. Paid-only Routen benötigen weiterhin die bestehende explizite Kostenautorisierung.

Ein fehlerhafter externer Status darf keine falsche Writerroute erzeugen. Wenn keine belastbare Writerroute übrig bleibt, ist `executor=controller` der sichere Fallback.

## 11. P2 Candidate + Verification

P2 ergänzt den bestehenden Workspace-Collect-Pfad additiv um immutable, exakt gebundene Ausführungsevidenz:

- `CandidateManifest.v1` friert den Patch-Modus über Workspace, optionalen Work-Lane-Bezug, Round, Base, Patch-, Untracked-, Scope-, Resulting-Tree- und Writer-Evidence-Digests ein; `candidate_id` ist der SHA-256 des kanonischen Manifest-Bodys.
- `VerificationReceipt.v1` wird aus den bereits bestehenden read-only Role-Receipts abgeleitet und bindet Test beziehungsweise Review an exakt dieselbe `candidate_id`, den konkreten Verifier-Attempt, Command-/Tool-, Toolchain- und Environment-Identität sowie `PASS`, `NEEDS_CHANGE` oder `INDETERMINATE`.
- Ein Candidate-Round bleibt bei rein technischen Verifier-Retries unverändert. Jeder Verifier-Attempt erhält einen eigenen create-only Receipt-Slot; frühere Attempts bleiben immutable erhalten.
- `VerificationSummary.v1` ist eine rein deterministische Projektion über die jeweils ausgewählten finalen Verifier-Receipts. Sie validiert Candidate-Bindungen, dedupliziert und sortiert Findings, erkennt fehlende Pflichtverifier und enthält keine Modellentscheidung. Der Summary ist keine dritte persistierte Autorität.
- Candidate- und Verification-Receipts werden create-only im bestehenden Workspace-Evidenzverzeichnis gespeichert. Ein abweichendes Receipt im selben Candidate-Round/Verifier-Attempt blockiert fail-closed. Es gibt keinen Candidate-StateStore und keine zweite Verifier-Ausführung.
- Die historische `collection` bleibt als Kompatibilitätsprojektion erhalten und verweist zusätzlich auf Candidate und aktuelle Verification.

P2 implementiert ausdrücklich noch nicht:

- Candidate Adoption oder Controller-Custody-Receipt;
- ExecutionPlan oder DAG;
- Revision Rounds;
- automatische Happy-Path-Komposition bis `integration_ready`;
- Delivery-Profil für Writer-Commit/Push/PR;
- Outcome-Learning für Controller-versus-Scoped-Writer.

Diese späteren Funktionen müssen weiterhin auf Lane, Workspace, Candidate und Receipts aufbauen und dürfen keinen zweiten Lifecycle- oder StateStore einführen.

## 12. Invarianten

P0 gilt nur dann als korrekt, wenn für dieselben Routingfacts kein öffentliches Interface gleichzeitig behauptet:

- Delegation sei verboten, und
- lane-gebundene Delegation sei erlaubt.

Die kanonische Autoritätsaussage lautet:

- Controller bleibt Integrator;
- Implementierung kann an genau einen lane-gebundenen Scoped Writer delegiert werden;
- Verification ist eine eigene Achse;
- ein Routingresultat allein erzeugt weder Work Lane noch Writerwirkung;
- Merge, Deployment und finaler Lane-Close bleiben Controllerwirkungen.
