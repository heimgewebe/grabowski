# Bureau Operator Intake Adapter v1

## Zweck

Der Adapter stellt den in Bureau definierten Operator-Intake-Vertrag als schmale Grabowski-Werkzeuge bereit. Bureau bleibt alleinige Quelle für Acceptance-, Kandidaten-, Bewertungs-, Proposal- und Publikationssemantik. Grabowski besitzt nur Transport, private Artefakte, Laufzeitbindung, Leases, Audit und begrenzten Ambiguitäts-Readback.

## Werkzeuge

| Werkzeug | Wirkung |
|---|---|
| `grabowski_bureau_acceptance_authenticate` | Authentifiziert genau ein run-/criterion-/digest-/reviewer-gebundenes manuelles Acceptance-Item über Bureaus kanonischen StateStore-Journalvertrag. |
| `grabowski_bureau_candidate_record` | Hängt einen quellgebundenen Kandidaten oder eine append-only Korrektur idempotent an das Bureau Live Register an. |
| `grabowski_bureau_candidate_assess` | Bewertet einen Kandidaten read-only gegen aktuelle Registry- und Live-Register-Wahrheit. |
| `grabowski_bureau_task_propose` | Erzeugt ein digestgebundenes privates Proposal-Artefakt; Registry und Queue bleiben unverändert. |
| `grabowski_bureau_task_review` | Prüft exakt den angegebenen Proposal-Digest und erzeugt `reviewed_plan`-Approval-Evidenz; Reviewzeitpunkt kommt ausschließlich aus Bureau. |
| `grabowski_bureau_task_publish_preview` | Validiert ein Proposal und liefert die exakt benötigten Publikationsressourcen ohne Wirkung. |
| `grabowski_bureau_task_publish` | Erwirbt die vom Preview bestimmten Kurzleasen, publiziert den TaskSpec und projiziert die exakte Lease-Konvergenz. |

## Acceptance-Authentifizierung

`grabowski_bureau_acceptance_authenticate` besitzt keine eigene Acceptance-Domänenlogik. Grabowski validiert nur die vier Transportfelder `run_id`, `criterion_id`, `expected_evidence_sha256` und `reviewer`, ruft den immutable Bureau-Launcher mit `acceptance-authenticate` und explizitem State-Root auf und behandelt Mutationsambiguität als rungebundene Readback-Pflicht. Current-run revision, Evidence-Digest, Observation-Scope, Reviewer-Trennung, Journal-Idempotenz und Authentifizierungswahrheit bleiben ausschließlich bei Bureau.

## Kandidaten-Refinement

`grabowski_bureau_candidate_record` transportiert optional `supersedes_event_id` unverändert im digestgebundenen Request. Typprüfung, Aktualität, Kandidatenzugehörigkeit und Supersession-Zulässigkeit entscheidet ausschließlich der append-only Bureau-Live-Register-Vertrag; der Adapter bewahrt dessen wirkungsfreie Fehler- und Readback-Semantik ohne eigene Domänenentscheidung.

## Vertrauensgrenzen

- Der Adapter importiert keine Bureau-Domänenlogik.
- Jeder Bureau-Aufruf läuft über den kanonisch gebundenen Runtime-Vertrag.
- Paketdateien und der geladene `bureau.cli`-Pfad werden vor und nach dem Aufruf geprüft.
- Private Requests, Pläne, Bindings und Receipts liegen unter dem Grabowski-State-Verzeichnis mit Verzeichnisrechten `0700` und Dateirechten `0600`.
- Eingaben und Ausgaben sind größenbegrenzt.
- GitHub-Merge, Deployment und Queue-Übergang sind nicht Bestandteil des Adapters.

## Idempotenz

Kandidaten verwenden den Bureau-Idempotenzschlüssel. Proposal-Verzeichnisse werden aus dem kanonischen Request-Hash abgeleitet. Ein vorhandener Plan wird nicht blind wiederverwendet, sondern erneut gegen aktuelle Registry-Wahrheit geprüft. Reviews binden Reviewer und exakten Proposal-Digest; der Adapter akzeptiert bewusst keinen aufrufergesteuerten Reviewzeitpunkt und überlässt dessen Erzeugung ausschließlich Bureau. Ein vorhandenes Publikations-Receipt wird vor jeder neuen Lease-Akquise über Bureaus Receipt-Replay gelesen.

## Publikationsvertrag

Das Preview bestimmt die exakten Publikationsressourcen: für StateStore-Publikation
den Koordinations-State-Root, für historische Git-Publikation Registry-Gate und
Task-Datei. Der Owner und die Lease-Metadaten sind an Publikationstask, Operation
und Proposal-SHA gebunden; die Laufzeit beträgt 90 bis 300 Sekunden.

Bei StateStore-Publikation ist Bureau die Freigabeautorität: Es gibt die
ursprünglich beobachteten Lease-Zeilen exakt und atomar frei. Der Adapter
verifiziert das eingebettete Release-Receipt gegen diese Bindung und den
aktuellen Ressourcen-Readback. Bei nachgewiesener Konvergenz meldet er
`leases_released=true`, ohne erneut freizugeben. Dasselbe gilt beim Receipt-Replay.
Eine fehlende oder driftende Bindung oder eine noch belegte Ressource wird als
`cleanup_incomplete` mit `resource_leases` in `required_readback` ausgewiesen,
nicht durch einen zweiten Release bereinigt. Bei eindeutig wirkungslosem
Abbruch darf der Adapter nur seine exakt unveränderten Akquise-Snapshots
freigeben; bei Ambiguität bleiben sie erhalten.

Historische Git-Publikationen behalten ihren bisherigen Release-Pfad.

## Fehler- und Ambiguitätsvertrag

Read-only-Timeouts sind ohne Wirkungsbehauptung wiederholbar. Bei mutierenden Timeouts, Laufzeitdrift, ungültiger oder übergroßer Ausgabe gilt:

- `effect_started=true`;
- `ambiguity=true`;
- `retryable=false`;
- ein konkreter `required_readback` wird zurückgegeben.

Publikations-Readback umfasst Receipt, Remote-Branch, Pull Request und Resource-Leases. Eine Mutation wird nicht automatisch erneut ausgeführt. Existiert ein Receipt, ist genau ein idempotenter Receipt-Replay zulässig.

## Nichtbehauptungen

Der Adapter belegt nicht:

- Mergefähigkeit oder Mergefreigabe;
- CI-Erfolg;
- Deployment;
- Task-Terminalität;
- Queue- oder Dispatch-Autorität;
- vollständige T017-Abnahme ohne integrierten Bureau-Core und Fresh-Session-Beweis.
