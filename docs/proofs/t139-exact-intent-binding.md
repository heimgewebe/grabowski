# T139: Verifikationen exakt an das Ziel binden

## Befund

`consume_verified` wählte bei fehlender exakter Übereinstimmung eine
*ungebundene* Verifikation aus:

```python
exact = [r for r in verified_receipts if _receipt_mutation_intent(r) == requested_intent]
unbound = [r for r in verified_receipts if _receipt_mutation_intent(r) is None]
if exact:
    verified = exact[0]
elif unbound:
    verified = unbound[0]      # <- jede Mutation, jedes Ziel
```

Damit autorisierte ein beliebiger Handshake ohne Zielangabe jede beliebige
Mutation. Das ist exakt der Live-Operatorbefund aus PR #185, für den T139
registriert wurde: `mutation_intent_bound: false`,
`observed_pool_mode: bounded-shared-token-pool`,
`observed_client_scope_kind: shared_unlabeled`.

## Entscheidung

Die ungebundene Auswahl entfällt ersatzlos. Eine Verifikation autorisiert nur
noch genau das Paar aus Werkzeugname und kanonischem Argument-Digest, an das
sie gebunden wurde.

Ungebundene Belege sind danach nicht mehr bloß wirkungslos, sondern gar nicht
mehr vorhanden: `begin()` und `acknowledge()` weisen sie fail-closed ab, und
`_current_receipts()` filtert gespeicherte Altbestände sofort heraus. Für den
Aufrufer erscheint ein solcher Zustand daher als geschlossenes Gate ohne
verwendbaren Receipt — nicht als eigener Projektionszustand.

Der zentrale Gate-Ablauf fängt jetzt `TransportRoundtripRequired` statt nur
`TransportMutationIntentMismatch`. Dadurch erhält der Aufrufer auch beim
allerersten Aufruf eines Scopes sofort eine exakte Challenge zum Bestätigen,
statt einer generischen Meldung ohne Handlungsweg.

## Verhältnis zu #609 und #610

Die zurückgenommene Variante band Autorität an die MCP-Sitzung. Genau daran
scheiterte der ChatGPT-Connector, der pro Aufruf eine andere Sitzung
präsentiert; #610 nahm sie deshalb vollständig zurück.

Diese Lösung bindet **nicht** an die Sitzung. Der Scope bleibt
`client_declared_meta` beziehungsweise `shared_unlabeled`, also über Aufrufe
hinweg stabil. Gebunden wird stattdessen an den exakten Zieldigest. Damit
erfüllt sie den in #609 geforderten Weg 2 — eine sitzungsübergreifende,
kurzlebige, einmalige Berechtigung, die an Werkzeug, kanonischen
Argument-Hash, Runtime-Identität und Ablaufzeit gebunden ist — ohne den
globalen unbeschrifteten Pool wiederherzustellen: Es gibt weiterhin einen
Pool, aber kein Eintrag darin ist unbeschriftet autorisierend.

## `shared_unlabeled` ist eine Partition, keine Identität

Die exakte Intent-Bindung beseitigt ungebundene Autorität. Sie erzeugt aber
**keine** Aufruferidentität. `shared_unlabeled` bleibt eine gemeinsame
Speicherpartition: Zwei unbeschriftete Aufrufer mit demselben exakten Intent
sind konstruktionsbedingt ununterscheidbar, und die Verifikation des einen
lässt den identischen Aufruf des anderen zu.

Das wird nicht mehr impliziert, sondern ausgesprochen. `status` und
`consume_verified` führen es in `does_not_establish`:

- `caller identity: shared_unlabeled is a shared storage partition, not an identity`
- `that two unlabeled callers of the same exact intent are distinguishable`

Was der Vertrag für diesen Fall trotzdem garantiert, und was jetzt in
`SharedPartitionEffectBoundaryTests` belegt ist:

| Zusage | Mechanismus |
|---|---|
| at-most-once-Zulassung | Auswahl, Entfernung und Zustandsschreibung liegen im selben `flock`-Abschnitt |
| eindeutige Consumption-Receipts | jeder Receipt trägt `verification_receipt_sha256`; eine Verifikation ist einmalig |
| fail-closed bei Ambiguität | Zulassung wird **vor** dem Effekt verbraucht |

## Verbrauch vor Wirkung

Der zentrale Gate-Ablauf ruft `consume_verified` vor `original(...)` auf. Das
ist die entscheidende Reihenfolge: Scheitert der Effekt danach, oder geht die
Antwort verloren, existiert **kein** unverbrauchter Nachweis mehr. Der
Aufrufer kann nicht stillschweigend erneut zuschlagen, sondern braucht einen
neuen, explizit zielgebundenen Handshake — plus Zielzustands-Readback, weil
ein verlorener Effekt und ein fehlgeschlagener Effekt am Gate
ununterscheidbar sind.

Diese Grenze ist ausdrücklich in `does_not_establish` der Consumption
formuliert und durch `test_a_failed_effect_leaves_no_reusable_proof` belegt:
Der Effekt wird nach der Zulassung zum Scheitern gebracht, und der
anschließende identische Aufruf scheitert fail-closed.

## Verworfen: bearer-gebundener atomarer Execute/Ack-Pfad

Ein atomarer Pfad, der Bestätigung und Zielaufruf in einer Anfrage
zusammenzieht, wurde geprüft und **nicht** umgesetzt. Beide möglichen
Bauformen durchbrechen genau die Gates, die sie schützen sollen:

**Bearer-Parameter an jedem mutierenden Werkzeug.** Dieser Stand registriert
84 mutierende Werkzeuge (73 `MUTATING`, 4 `CREATE`, 3 `REMOVE`, 2 `REPLACE`,
1 `SECRET_REVEAL`, 1 `DEPLOY_MUTATING`). Ein zusätzlicher Parameter änderte
jede dieser Signaturen. Der Connector-Snapshot bindet nicht nur Namen,
sondern Schemata (`observed_schemas`, `observed_schema_coverage_count`); jede
bestehende Bindung würde ungültig. Der Nutzen wäre null, denn der Token käme
weiterhin vom Aufrufer und belegte weiterhin keine Identität.

**Generisches `execute(token, tool, arguments)`.** Es müsste das Ziel
entweder über `manager.call_tool` aufrufen — dann läuft das Gate erneut und
verlangt eine zweite Verifikation, was nur durch eine Ausnahme auflösbar wäre
— oder die Zielfunktion direkt aufrufen und damit `gated_call_tool`
vollständig umgehen: keine Deployment-Admission-Buchführung, keine
`readOnlyHint`-Pflicht, keine Serving-Process-Prüfung, kein Transport-Gate.
Heute existiert genau eine Ausnahme, `grip_run(name=transport-roundtrip)`,
und sie ist auf eine Handshake-Oberfläche begrenzt. Ein Executor, der jedes
beliebige Werkzeug benennen darf, machte aus dieser eng begrenzten Ausnahme
eine universelle.

**Dauerhafte Grenze.** Im trusted-owner-Modell ist der Angreifer nicht ein
fremder Aufrufer, sondern eine Zielverwechslung: eine Autorisierung, die für
etwas anderes gilt als das, was ausgeführt wird. Exakte Intent-Bindung
schließt genau das, und Verbrauch vor Wirkung schließt die Wiederverwendung.
Was offen bleibt — Unterscheidbarkeit zweier identischer Absichten desselben
Vertrauensbereichs — ist ohne echte, vom Server verifizierbare
Aufruferidentität nicht lösbar; das ist Weg 1 aus #609 und liegt außerhalb
dieses Transportvertrags.

## Geschlossene Nebenpfade

Die exakte Bindung allein genügte nicht. Fünf Stellen bestätigten die Zusage,
umgingen sie aber:

**`require_verified()` ersatzlos entfernt.** Es prüfte nur `mutation_gate_open`
und belegte damit *irgendeinen* gebundenen Intent, nicht den angefragten. Als
öffentliche Abstraktion war es eine Einladung, genau die Zielverwechslung
wieder einzuführen. Es gab keinen Produktivaufrufer. An der Fundstelle steht
jetzt die Begründung, damit es niemand gutgläubig neu anlegt. Zulassung hat
genau einen Eingang: `consume_verified()` mit exaktem Werkzeug und
Argument-Digest.

**Ungebundene Handshakes sind unmöglich statt nur wirkungslos.** `begin()` ohne
Intent und `acknowledge()` einer ungebundenen Challenge scheitern mit der neuen
typisierten `TransportMutationIntentRequired`. Ohne das hätten 32 ungebundene
Einträge `MAX_SHARED_VERIFIED_RECEIPTS` füllen und exakte Handshakes
blockieren können — eine Denial-of-Service-Fläche ohne jede Autorität.

**Altbestand wird auf Sicht verworfen, nicht bei TTL.** `_current_receipts()`
filtert ungebundene Einträge. Das wirkt in `_prune_state` *und* in der
Projektion, also auch im nicht-prunenden `status`.

**Der Replay-Pfad in `acknowledge()` liest ungepruntes State** und hätte eine
ungebundene Altverifikation zurückgegeben statt sie zu verwerfen. Er lehnt
jetzt vor dem Replay ab.

**Der Produktivaufrufer war gebrochen.** `_observe_and_bind_snapshot` startete
einen ungebundenen `begin` und baute die Deklaration erst danach. Nach dem
Hardening wäre er hart gescheitert. Jetzt entstehen `declaration` und die
vollständigen `bind_arguments` vor dem Handshake; `begin` bindet auf
`grip_run` mit genau diesen Argumenten, und der Bind führt dasselbe Objekt
aus. Der Test vergleicht `target_arguments` per Identität mit dem
ausgeführten Aufruf, nicht feldweise.

## Verbliebener Guard, bewusst behalten

Nach diesen Sperren ist der geschlossene Zweig in `_verified_projection()`
nicht mehr erreichbar. Er bleibt trotzdem stehen, als **zweite Linie** und
nicht als Kompatibilitätsrest: Die Funktion ist der einzige Ort, an dem „darf
das Gate öffnen" entschieden wird, und sie leitet die Antwort bei jedem Aufruf
neu aus dem Beleg ab. Kosten: ein Vergleich. Abgedeckter Fehlerfall: ein Gate,
das für einen ungebundenen Beleg öffnet.

Was dagegen entfernt wurde, war echte tote Doppelung: Die zweite Aufrufstelle
filterte `verified_current` erneut nach gebundenen Belegen, obwohl
`_current_receipts()` das bereits garantiert. Damit war dort sowohl der Filter
als auch sein `else`-Zweig unerreichbar. Ein zweiter Filter an derselben
Invariante ist kein Schutz, sondern eine Stelle, die später auseinanderdriftet.

## Grip-Vertrag

Der veröffentlichte Vertrag versprach weiterhin die alte Semantik. Er steht
jetzt auf Version 1.1 mit der zusätzlichen Acceptance-ID `exact-target-bound`;
Summary und Recovery-Text nennen `target_tool_name` und `target_arguments`
für `action=begin` sowie den exakten Receipt für `action=ack`.

Bedingte Pflichtfelder lassen sich nicht als statische `required_parameters`
ausdrücken — `target_tool_name` dort einzutragen hätte `ack` gezwungen,
Begin-Felder mitzuführen. Sie stehen deshalb in `GRIP_CONDITIONAL_PRECONDITIONS`
und fließen in die veröffentlichten `preconditions`; `required_parameters`
bleibt `("action",)`, und ein Test hält das fest.

Der Runner-Preflight verlangt für `begin` beide Felder statt „beide oder
keines". Der Receipt trägt einen `exact-target-bound`-Check mit
`tool:digest`, sodass die Bindung im Beleg sichtbar ist und nicht nur im
Verhalten.

## Sicherheitsgrenze

- Ein fremder Aufruf mit abweichendem Ziel scheitert fail-closed und
  **verbraucht die fremde Verifikation nicht**; die vorgesehene Mutation kann
  danach unverändert fortfahren.
- Gleiche Argumente unter anderem Werkzeugnamen werden abgewiesen.
- Zwei parallele Aufrufer desselben exakten Ziels erhalten genau eine
  Zulassung; der Verlierer scheitert fail-closed.
- Die Fehlermeldung nennt Aufruferscope, angefragtes Werkzeug, angefragten
  Argument-Digest sowie die Anzahl gebundener und ungebundener Verifikationen.
  Das mehrdeutige `bound to a different mutation` ohne Identitätsbezug
  entfällt.
- Read-only-Werkzeuge bleiben unberührt.

Bestehende ungebundene Zustände auf der Platte brauchen keinen
Migrationsschritt, laufen aber auch **nicht** über ihre Ablaufzeit aus:
`_current_receipts()` macht sie sofort unsichtbar — auch weit innerhalb ihrer
TTL und auch im nicht-prunenden `status` — und der nächste schreibende Prune
entfernt sie dauerhaft aus der Datei.

## Verifikation

`make validate` vollständig. Die Transport-Suite enthält neu eine eigene
Klasse, die belegt, dass eine ungebundene Verifikation das Gate nicht öffnet,
keine Mutation autorisiert, dass die Fehlermeldung Identität und exaktes Ziel
nennt, dass eine Verifikation für ein Ziel kein anderes zulässt ohne sich
dabei zu verbrauchen, und dass gleiche Argumente unter anderem Werkzeug
abgewiesen werden.

## Restrisiko

Die Bindung schützt gegen Zielverwechslung, nicht gegen kompromittierten Code
mit derselben UID. Zwei Aufrufer, die exakt dieselbe Mutation beabsichtigen,
sind für das Gate ununterscheidbar — das ist gewollt, denn es ist dieselbe
Mutation, und Einmalverbrauch lässt sie nur einmal zu.

Der Livebeweis über den echten ChatGPT-Connector steht aus; er kann nur aus
einer Sitzung geführt werden, die den deployten Stand bedient.
