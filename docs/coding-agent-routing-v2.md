# Coding-Agent-Routing v4 — Agent Execution Fabric

## 1. Kanonische Regel

Grabowski trennt Ausführungsautorität, Writerwahl und Verification.

Die Autorität folgt nicht dem Modellnamen. Sie folgt der gebundenen Rolle und der Work Lane:

- `controller` plant, integriert, merged, deployt und schließt ab;
- `scoped_writer` darf nur innerhalb einer explizit gebundenen Lane implementieren und testen;
- `reviewer` arbeitet read-only und advisory;
- `observer` liefert nur Evidenz.

Für überlappenden Scope gibt es genau einen autoritativen mutierenden Writer. Disjunkte Work Lanes dürfen parallel laufen.

Die Work Lane ist der Autoritäts- und Wirkungscontainer. Agent Workspace ist die Ausführungs- und Verification-Schicht innerhalb einer Lane. Solange lane-backed Workspaces noch nicht produktiv sind, darf der Legacy-Workspace diese Ownership nicht als zweite Wahrheit duplizieren.

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

Bis der lane-backed Agent Workspace implementiert ist, darf `grabowski_agent_workspace_create` nicht als Ersatz für diese Lane-Ownership verwendet werden, weil der Legacy-Pfad eigene Ressourcen und Checkout-Lifecycle reserviert.

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

## 11. Noch nicht durch P0 implementiert

P0 behauptet ausdrücklich noch nicht:

- lane-backed Agent Workspace;
- getrennten Execution-Close/Lane-Close;
- offiziellen Candidate-Receipt;
- Candidate-Digest-Bindung für Test, Review und Integration;
- Revision Rounds;
- automatische Happy-Path-Komposition bis `integration_ready`;
- Delivery-Profil für Writer-Commit/Push/PR;
- Outcome-Learning für Controller-versus-Scoped-Writer.

Diese Funktionen müssen auf bestehenden Lane-, Workspace-, Task- und Governor-Komponenten aufbauen und dürfen keinen zweiten Lifecycle- oder StateStore einführen.

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
