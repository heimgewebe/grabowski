# Bureau Operator Intake Adapter v1

## Zweck

Der Adapter stellt den in Bureau definierten Operator-Intake-Vertrag als schmale Grabowski-Werkzeuge bereit. Bureau bleibt alleinige Quelle für Kandidaten-, Bewertungs-, Proposal- und Publikationssemantik. Grabowski besitzt nur Transport, private Artefakte, Laufzeitbindung, Leases, Audit und begrenzten Ambiguitäts-Readback.

## Werkzeuge

| Werkzeug | Wirkung |
|---|---|
| `grabowski_bureau_candidate_record` | Hängt einen quellgebundenen Kandidaten idempotent an das Bureau Live Register an. |
| `grabowski_bureau_candidate_assess` | Bewertet einen Kandidaten read-only gegen aktuelle Registry- und Live-Register-Wahrheit. |
| `grabowski_bureau_task_propose` | Erzeugt ein digestgebundenes privates Proposal-Artefakt; Registry und Queue bleiben unverändert. |
| `grabowski_bureau_task_review` | Prüft exakt den angegebenen Proposal-Digest und erzeugt `reviewed_plan`-Approval-Evidenz; Reviewzeitpunkt kommt ausschließlich aus Bureau. |
| `grabowski_bureau_task_publish_preview` | Validiert ein Proposal und liefert die exakt benötigten Publikationsressourcen ohne Wirkung. |
| `grabowski_bureau_task_publish` | Erwirbt zwei exakte Kurzleasen, publiziert Branch und Pull Request und gibt Leases nur nach eindeutigem Ausgang frei. |

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

Vor einer Publikation muss Bureau `status=ready` und exakt zwei Ressourcen liefern:

1. den kanonischen Registry-Publikations-Gate-Pfad;
2. die exakte Task-Datei.

Grabowski erwirbt beide Ressourcen unter einem proposalgebundenen Owner für 90 bis 300 Sekunden. Die Lease-Metadaten binden Publikationstask, Operation und Proposal-SHA. Ein klarer Ausgang löst die Freigabe aus. Bei unklarem Ausgang bleiben die Kurzleasen bis zum Ablauf erhalten, sofern kein gültiges Receipt einen eindeutigen Replay ermöglicht.

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
