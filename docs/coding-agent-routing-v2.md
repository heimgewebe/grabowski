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

## 12. P3/P4 Adoption + begrenzte Revision

P3 ergänzt den lane-backed Candidate-Pfad um Controller-Adoption: Nur ein vollständig `PASS`-verifizierter Candidate kann nach einem gültig geschlossenen Workspace revisionsgebunden als Controller-Commit übernommen werden. Candidate-, Verification-, Workspace- und Work-Lane-Identität bleiben dabei unverändert referenziert; die Adoption erzeugt weder einen zweiten Lifecycle noch einen neuen StateStore.

P4 ergänzt genau **eine** fachliche Revision und einen kleinen, unveränderlichen Ausführungsplan-Vertrag. Er ist ausdrücklich kein Scheduler und keine neue Control Plane:

- `ExecutionPlan.v1` ist ein reines, kanonisch gehashtes Beschreibungsobjekt. Es bindet Source, die exakte `recommendation_sha256` der bestehenden Route, explizit vom Controller gewählte Topologie, Nodes, typed Edges, Write-Scope, Verification-Policy, Failure-Policy, Budgets und Completion-Policy. Der Plan besitzt keine Lease-, Task-, Workspace-, Queue- oder Merge-Autorität.
- Die Route wählt **keinen Graphen**. `grabowski_coding_agent_route` bleibt bei `executor`, `writer_route`, `effect_profile`, `verification_policy`, `risk` und `task_class`; die Topologie wird separat und explizit gebunden. Eine abweichende Verification-Policy zwischen Route und Plan blockiert. Der Plan trägt die vollständige gehashte Route Decision als immutable Provenienz, nicht nur eine unprüfbare Hash-Behauptung.
- Der interne `acquire_work`-Konstruktor kann optional genau einen validierten `ExecutionPlan.v1` konsumieren. Bei Plan-Nutzung müssen `source_binding` und der normalisierte repository-relative `write_scope` exakt der Work-Lane-Source beziehungsweise den `write_paths` entsprechen; der vollständige Plan geht in die Lane-Identität ein. Ungültige oder driftende Pläne blockieren vor Lease- oder Worktree-Effekten. Planlose Lanes behalten ihre bisherige Identität unverändert. Die öffentliche MCP-Signatur von `grabowski_work_acquire` bleibt in P4 absichtlich unverändert; die externe Plan-Orchestrierung gehört in den P5-Happy-Path und löst deshalb jetzt keinen vorzeitigen Connector-Publication-Zyklus aus.
- Es gibt nur drei Topologien: `direct`, `writer_verify_reduce` und `fork_compare`. Jede Kante muss `from`, `to` und ein benanntes transportiertes Artefakt tragen. Zyklen, unbekannte/disconnected Nodes, fehlende Artefaktverträge, Scope-Escapes, übersprungene Critical-Nodes und unzureichende Verifier-Quoren blockieren deterministisch.
- `fork_compare` ist nur für explizite `competition`-Verification zulässig. Seine Alternativen sind in diesem P4-Vertrag read-only Candidate-Eingänge; konkurrierende mutierende Writer benötigen weiterhin getrennte Work Lanes und erhalten durch den Plan keine Parallel-Schreibautorität.
- Unknown Effects sind im Plan fest auf `reconcile` begrenzt. Das P4-Budget erlaubt höchstens eine fachliche Revision; es gibt keinen unveränderten Blind-Retry.
- Die bestehende Oberfläche `grabowski_agent_workspace_writer_handoff` dient weiterhin dem terminalen Writer-Recovery-Fall. Liegt stattdessen eine vollständige lane-backed Collection mit deterministischem `NEEDS_CHANGE` vor, öffnet dieselbe Oberfläche genau den Übergang `Candidate Round 1 -> Writer Attempt 2 -> Candidate Round 2`. Es gibt keinen caller-wählbaren Modus und kein neues öffentliches Tool.
- `PASS` wird nicht revidiert. `INDETERMINATE`, fehlende Pflichtverifier, Base-Drift, Scope-Verletzungen, offene Start-Intents oder eine bereits verbrauchte Revision blockieren fail-closed. Der P4-Pilot verlangt außerdem first-attempt Verification in Round 1; Verifier-Retry plus fachliche Revision wird erst nach separater Evidenz verallgemeinert.
- Vor dem zweiten Writer wird zusätzlich ein `RevisionRequest.v1` create-only eingefroren. Er bindet Candidate-ID, `VerificationSummary.v1`, Collection-Result, den bereits deterministisch reduzierten Findings-Digest samt Findings, Round `1 -> 2`, den bestehenden Workspace-Write-Scope und das Budget `revision_index=1/max_revisions=1`. Er ist eine Anweisungsevidenz, kein neuer Lifecycle.
- Vor dem zweiten Writer wird die vollständige Round-1-Collection create-only als `collection-round-0001.json` archiviert. Candidate- und Verification-Receipts von Round 1 bleiben unverändert. Round 2 erhält eigene Patch- und Role-Receipt-Pfade. Frühere Evidenz wird weder überschrieben noch als aktueller Candidate umetikettiert.
- Writer Attempt 2 trägt `actor=candidate_revision` und bindet `revision_candidate_id`, Round-1-`result_sha256`, den exakten Dirty-Preimage-Digest sowie ID, Full-Receipt-Digest und Pfad des immutable `RevisionRequest.v1`. Manipulation oder Verlust dieses Requests blockiert sowohl Start-Reconcile als auch spätere effektive Writer-Auswertung fail-closed. Der Writer darf auf einem dirty Worktree nur starten, wenn sein live berechneter Digest exakt dieser gebundenen Candidate-Preimage entspricht; der normale Initial-Writer verlangt weiterhin einen clean Base-Checkout.
- Vor dem Task-Start wird ein revisionsgebundener Start-Intent persistiert. Bei verlorenem oder unklarem Start-Outcome darf nicht blind wiederholt werden; der bestehende Reconcile-Pfad sucht genau den an Host, CWD, argv, Candidate und Preimage gebundenen Task.
- Nach erfolgreichem Start wird `candidate_round=2`, die aktuelle Collection/Frozen-Writer-Projektion wird für die neue Runde geleert und Tests/Review werden frisch gestartet. Die Round-1-Evidenz bleibt über ihr immutable Archiv adressierbar.
- Adoption akzeptiert ausschließlich den Candidate der aktuellen Collection. Ein alter Round-1-Candidate kann deshalb nach einer Round-2-Collection nicht als aktuelles Ergebnis adoptiert werden.
- `grabowski_agent_workspace_status` exponiert die begrenzte Candidate-Revision separat. Bei vollständig verifiziertem `NEEDS_CHANGE` lautet die nächste Aktion `writer_handoff_for_candidate_revision`, nicht `close_with_abandon_failed_roles`.

P4 implementiert ausdrücklich **nicht**:

- mehr als eine fachliche Revision;
- einen universellen DAG, Scheduler oder Candidate-StateStore; `ExecutionPlan.v1` beschreibt nur einen begrenzten azyklischen Datenfluss und führt selbst nichts aus;
- automatische Multi-Writer-Konkurrenz;
- P5-Delivery oder Outcome-Learning.

## 13. P5 controller-owned `integration_ready`

P5 beginnt bewusst nicht mit einer universellen Orchestrierung, sondern mit einer begrenzten Controller-Komposition auf den bereits vorhandenen P1-P4-Receipts. `grabowski_execution_coordinator.py` ist der interne, zustandslose P5a-Core für `status -> collect -> gegebenenfalls genau eine gebundene Candidate-Revision -> close`. Er besitzt keinen eigenen StateStore, publiziert kein MCP-Tool und führt weder Adoption noch GitHub-Publikation aus. Als Runtime-Supporting-Source wird er zusammen mit der äußeren Komposition deployt, nicht als zweite Control Plane.

- Der Grip `agent-execution-happy-path` ist die äußere P5-Komposition hinter der bestehenden Grip-Oberfläche. Der Caller liefert nur Workspace-ID sowie PR-Basis/-Metadaten. Der Grip liest das bereits gebundene Writer-argv aus dem unveränderlichen Workspace-Manifest, ruft den internen Coordinator mit einem kleinen festen Poll-Budget ohne Sleep auf und akzeptiert dessen `closed`/`verified_candidate_closed` nur nach erneuter exakter PASS-Candidate-Prüfung. `pending` bleibt ein normaler Zwischenzustand; `blocked`, `revision_required`, `reconcile_required` und unbekannte Coordinator-Ergebnisse stoppen vor jeder Integrationswirkung.
- Erst nach geschlossenem, lane-backed und vollständig `PASS`-verifiziertem Candidate ruft `agent-execution-happy-path` den bestehenden Grip `candidate-integration-ready` mit serverseitig abgeleiteter Candidate-ID und Collection-Digest auf. Repository, Work-Branch, Commit, Candidate-Identität und Revision-Command können nicht vom Caller überschrieben werden. Dadurch entsteht keine dritte Lifecycle- oder Integrationswahrheit.
- Der Grip `candidate-integration-ready` ist eine Operation hinter der bestehenden Grip-Oberfläche und **kein neuer öffentlicher MCP-Toolname**. Er akzeptiert Workspace-ID, exakte Candidate-/Collection-Digests sowie PR-Basis und PR-Metadaten; Repository, Work-Branch und Integrations-Commit werden ausschließlich aus der unveränderlichen Workspace-/Lane-/Adoption-Evidenz abgeleitet. Der Caller kann diese Git-Ziele nicht überschreiben.
- Zuerst wird ausschließlich der aktuelle `PASS`-Candidate über den bestehenden P3-Adoption-Pfad in Controller-Custody übernommen. Ein unklarer Adoptionseffekt beendet den Lauf mit `reconcile_required`; es gibt keinen Blind-Retry.
- Nach erfolgreicher Adoption wird die Source Work Lane mit frischer Task-, Prozess-, Lease- und Git-Liveness revisionsgebunden als `candidate_adopted` terminalisiert. Damit endet Writer-Autorität vor PR/CI/Merge. Die bereits vorhandenen Lane-Leases dürfen danach nur noch kurz als Koordinationsschutz für die unmittelbar folgende Controller-Publikation gehalten werden.
- Die Publikation erfindet keine neuen Git-/GitHub-Schreibpfade: Sie verwendet `branch-publish` und `pr-create-or-update` mit dem exakten Adoption-Commit. Ein bereits exakt publizierter Remote-Head wird nach Readback nicht erneut gepusht. Ein bereits exakt offener, nicht-draftiger PR wird ebenfalls nur gelesen und wiederverwendet.
- Nach exaktem PR-Readback werden die unveränderten Source-Lane-Leases über den bestehenden auditierten, snapshot-gebundenen Resource-Release freigegeben. Scheitert nur diese Hygiene, bleibt `integration_ready=true`, aber `cleanup_complete=false` und der Receipt fordert gezielten Lease-Readback statt die Publikationswirkung zu wiederholen.
- `integration_ready` ist eine **abgeleitete Projektion** aus CandidateAdoptionReceipt, terminaler Source-Lane-Evidenz, exaktem Remote-Head, exaktem ready PR und Lease-Cleanup. Es entsteht kein zusätzlicher Candidate-, Lane- oder Delivery-StateStore.
- Push-/PR-Unklarheit hält die Koordinationsleases und liefert eine benannte Reconcile-Aktion. Ein exakter Remote-Readback nach einem früheren Push erlaubt die Fortsetzung beim fehlenden PR, ohne denselben Push erneut auszulösen.

Der P5-Happy-Path ist damit als begrenzte Kette `Workspace Coordinator -> geschlossener PASS-Candidate -> Candidate Adoption -> integration_ready` komponiert. Er implementiert ausdrücklich noch nicht:

- Merge oder Deployment; beides bleibt eine spätere Controllerwirkung nach CI/Review;
- einen universellen Scheduler, eine Queue oder einen zweiten StateStore;
- automatische Multi-Writer-Konkurrenz;
- Writer-Commit/Push/PR-Autorität; diese war in P5 noch nicht aktiv und wird erst durch das nachfolgende P6-Profil explizit freigeschaltet;
- Outcome-Learning; das bleibt P7.

## 14. P6 explizites Delivery-Profil

P6 erweitert ausschließlich die bestehende kanonische Route und den vorhandenen Grip `agent-execution-happy-path`. Es gibt kein neues öffentliches MCP-Tool und keinen zweiten Merge-, Deployment- oder Lifecycle-Pfad. `effect_profile=candidate` bleibt Default und behält den P1-P5-Pfad über `candidate-integration-ready`; Delivery wird nur durch `effect_profile=delivery` in Source-Mode opt-in aktiviert. Resume-Mode akzeptiert keinen caller-gelieferten Profilwechsel, sondern liest das Profil aus dem lane-gebundenen `ExecutionPlan.v1`.

- Delivery ist nur bei `executor=scoped_writer` und `verification_policy=independent_review` zulässig; `deterministic` und `competition` werden für Delivery vor jeder Writerwirkung fail-closed abgewiesen. Route und `ExecutionPlan.v1` binden Profil, Writerroute, Source, Write-Scope und Plan-ID unveränderlich. Controller-Routen sowie Lane-, Route-, Plan-, Branch-, Base- oder Scope-Drift blockieren vor Commit oder Publikation.
- Der Writer-Effekt beginnt erst nach einem gültig geschlossenen, lane-backed Workspace mit erfolgreichem Close-Receipt, integer aktuellem Candidate-Round, integrity-valid aktueller Collection und vollständigem `PASS` aus Tests und Review. Candidate-, Verification- und Collection-Evidenz wird aus den create-only Workspace-Receipts erneut validiert; ein alter Candidate einer früheren Round ist nicht lieferbar.
- `CandidateDeliveryManifest.v1` ist ein kleiner create-only Manifest-Vertrag für genau einen `commit_range`. Er bindet Candidate-ID und Candidate-Manifest-Digest, Verification-Summary- und exakten Collection-Result-Digest, Workspace-, Lane-, Lane-Receipt-, Route- und Plan-Identität, Write-Scope, Base-/Head-Commit, Candidate-abgeleiteten und Commit-Git-Tree, Writer-/Base-Branch sowie `origin`/Remote-Ref. Deterministische Commit-, Push- und PR-Aktions-IDs binden außerdem PR-Head-SHA, Draft-State, Titel und Body. Exakter Replay wird wiederverwendet; ein abweichender Inhalt im selben Receipt-Slot ist ein Identitätskonflikt.
- Der Commit wird auf dem bereits serverseitig bestimmten Writer-Branch als genau ein Single-Parent-Commit über dem Candidate-Base erstellt. Vor Ref-CAS wird der Candidate-Patch in einem isolierten Index zum exakten Git-Tree abgeleitet; nach CAS folgt unmittelbarer Branch-/Parent-/Tree-/Clean-Readback. Vor jeder Publikation muss `commit^{tree}` exakt dem Candidate-abgeleiteten Tree entsprechen, und das immutable Delivery-Manifest muss create-only persistiert und wieder gelesen worden sein.
- Push und PR verwenden weiterhin `branch-publish` und `pr-create-or-update`. Ein autoritativ gelesener exakter Remote-Head wird nicht erneut gepusht. Ein exakter offener PR wird nur wiederverwendet, wenn Base, Head-Branch, Head-SHA, Draft, Titel und Body übereinstimmen; Metadaten-Drift darf über die bestehende Update-Semantik korrigiert und danach exakt gelesen werden. Mehrere offene PRs, anderer Remote-Head oder struktureller PR-Drift blockieren fail-closed.
- Nach einem unklaren oder fehlgeschlagenen Push-/PR-Aufruf erfolgt immer autoritativer Remote-/PR-Readback. Beweist er den exakten Effekt, wird dieser wiederverwendet. Andernfalls lautet der Zustand `outcome_unknown`, `reconcile_required=true`; die Source-Lane-Leases bleiben erhalten und die benannte Readback-Aktion ist vor jedem Retry Pflicht.
- Der interne Writer-Delivery-Helfer darf committen, pushen und einen PR erstellen/aktualisieren. Er terminalisiert keine Source Lane, gibt keine Leases frei, merged nicht und deployt nicht. Erst die äußere Controller-Komposition darf nach erneut exaktem Task-, Prozess-, Lease-, Git-, Remote- und PR-Readback den bestehenden `pr_opened`/`pr_updated`-Closeout persistieren und die unveränderten Lane-Leases snapshot-gebunden freigeben.
- Merge und Deployment bleiben controller-only. Eine spätere CI-Korrektur eröffnet eine neue Work Lane; die geschlossene und terminalisierte Source Lane wird niemals wiederbelebt.

Damit lautet der P6-Happy-Path `Workspace Coordinator -> geschlossener exakter PASS-Candidate -> Candidate-Tree-Commit -> immutable Delivery-Manifest -> exakter Branch/PR -> Controller-Closeout`. Weder das Manifest noch der Effekt führen Merge, Deployment, Source-Terminalisierung durch den Writer oder automatische Lane-Wiederbelebung ein.

## 15. Invarianten

P0 gilt nur dann als korrekt, wenn für dieselben Routingfacts kein öffentliches Interface gleichzeitig behauptet:

- Delegation sei verboten, und
- lane-gebundene Delegation sei erlaubt.

Die kanonische Autoritätsaussage lautet:

- Controller bleibt Integrator;
- Implementierung kann an genau einen lane-gebundenen Scoped Writer delegiert werden;
- Verification ist eine eigene Achse;
- ein Routingresultat allein erzeugt weder Work Lane noch Writerwirkung;
- Merge, Deployment und finaler Lane-Close bleiben Controllerwirkungen.
