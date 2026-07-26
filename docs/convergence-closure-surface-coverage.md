# Konvergenz-Abdeckung der Operator-Abschlussflächen

Stand: 2026-07-26

Geprüfter Grabowski-Commit: `d2097c909bd60be7f947b5c50cc9fa6d56ba907c`

Geprüfter Protokoll-Commit: `fae4c26faa22d62d148d39e1995fe5492211cb43`

## Fragestellung

Dieser Audit prüft, welche mutierenden Grabowski-Oberflächen einen semantischen Abschluss herstellen oder dafür verwendet werden können und ob sie einen hash- und revisionsgebundenen `terminally_closed`-Receipt des Konvergenzregelkreises technisch erzwingen.

Der Audit unterscheidet bewusst:

- **semantischen Abschluss**: Eine Änderung gilt als systemisch abgeschlossen;
- **Prozessabschluss**: Ein Prozess oder Task ist terminal;
- **Effekt**: Merge, Deployment oder Veröffentlichung hat stattgefunden;
- **Hygiene**: Leases, Worktrees oder Archive werden bereinigt.

Nur der semantische Abschluss benötigt zwingend die Wirkungsevidenz des Konvergenzregelkreises. Ein mechanischer Effekt oder Cleanup darf diese Evidenz weder ersetzen noch selbst erfinden.

## Bestehender Consumer

`convergence-assess` ist ein read-only Grip. Er bindet Requestbytes, Protokollcommit, sauberen Checkout, Evaluatoridentität sowie Status und Exit-Code. Nur `terminally_closed` ergibt `allow_closure`.

Der Consumer funktioniert, ist aber derzeit kein zentraler technischer Vorgänger aller mutierenden Abschlussflächen. Die Operator-Instruktion fordert seinen Aufruf für Deployment-, Runtime-, Security-, Daten- und irreversible Arbeit; die nachfolgenden Mutationen validieren diesen Receipt jedoch nicht durchgängig selbst.

## Abdeckungsmatrix

| Oberfläche | Wirkung | Aktueller Konvergenzstatus | Urteil |
|---|---|---|---|
| `convergence-assess` | bewertet ein gebundenes Belegpaket | vollständiger Consumer, keine Mutation | **belegt** |
| `operator-obligation-close` mit `outcome=completed` | erklärt eine Operatorverpflichtung für abgeschlossen | kein verpflichtender Konvergenz-Receipt-Parameter | **semantische Lücke** |
| `task-closeout-archive` | archiviert und projiziert einen terminalen Task | bindet Task- und Lifecycle-Receipts, aber keinen Konvergenz-Receipt | **bedingte semantische Lücke** |
| `grabowski_agent_workspace_close` | schließt einen Workspace und gibt Ressourcen frei | bindet Writer-, Test- und Review-Ergebnis, aber keinen Konvergenz-Receipt | **bedingte semantische Lücke** |
| `grabowski_agent_workspace_cleanup` | archiviert und entfernt einen bereits geschlossenen Writer-Checkout | besitzt Recovery- und Workspace-Evidenz, bewertet aber nicht selbst die Systemwirkung | **Upstream-Bindung nötig** |
| `grabowski_checkout_cleanup` | entfernt einen archivierten Linked Checkout | Hygieneoperation mit Dry-Run und Recovery-Refs | **kein eigener Assessment-Fall** |
| `bureau-pickup-release` | gibt unveränderte Leases eines terminalen Bureau-Laufs frei | rein mechanischer Release nach Bureau-Readback | **außerhalb des Scopes** |
| `task-attention-decision` | klassifiziert einen terminalen Taskausgang | darf keinen systemischen Abschluss behaupten | **außerhalb des Scopes** |
| `grabowski_runtime_deploy_schedule` | startet einen Deployment-Effekt | erzeugt erst Evidenz für eine spätere Verifikation | **vor dem Abschluss** |
| Branch-, PR-, Merge- und Publish-Oberflächen | erzeugen Versionskontroll- oder Veröffentlichungseffekte | Wirkung noch nicht verifiziert | **vor dem Abschluss** |
| Task-Reconcile und Prozess-Terminalisierung | aktualisieren Prozesszustand | Prozessende ist kein Systemabschluss | **außerhalb des Scopes** |

## Konkrete Umgehungspfade

### 1. Operatorverpflichtung

`operator-obligation-close` kann eine Verpflichtung mit `completed` schließen, ohne selbst einen `convergence-assess`-Receipt zu validieren. Bei R2-/R3-, Deployment-, Runtime-, Security-, Daten- oder irreversibler Arbeit ist damit ein Abschluss trotz fehlender oder blockierender Wirkungsevidenz technisch möglich.

### 2. Task-Archivierung

`task-closeout-archive` prüft den terminalen Task und dessen Lifecycle-Evidenz. Ein erfolgreich beendeter Prozess beweist jedoch nicht, dass Deployment, Laufzeit und Produktwirkung korrekt sind. Wird die Archivierung als fachlicher Abschluss interpretiert, fehlt die Konvergenzbindung.

### 3. Workspace-Abschluss

`grabowski_agent_workspace_close` bindet Writer-Head, Diff, Tests und Review. Für reine Codeerzeugung ist das ausreichend als Workspace-Abschluss. Wird derselbe Receipt jedoch als systemischer Abschluss einer R2-/R3-Änderung verwendet, fehlen Deployment-, Live-, Recovery- und Cleanup-Belege.

## Erforderliche Härtung

Ein zentrales, fail-closed Closeout-Gate sollte für jede semantische Abschlussmutation eine explizite Klassifikation verlangen:

1. `convergence_required=true` mit einem gültigen, unveränderten `terminally_closed`-Receipt, der an Ziel, Assessment-Request und konkrete Abschlussmutation gebunden ist; oder
2. `convergence_required=false` mit einer kanonischen, testbaren Begründung wie `process_only`, `effect_only`, `lease_release_only` oder `cleanup_after_bound_closure`.

Für high-risk Abschlussklassen darf eine fehlende Klassifikation nicht implizit als `false` gelten.

## Negative Abnahmekriterien

Die Härtung ist erst vollständig, wenn Tests beweisen:

- `operator-obligation-close(completed)` blockiert ohne erforderlichen Konvergenz-Receipt;
- ein nichtterminales Assessment blockiert dieselbe Mutation;
- Receipt-, Request-, Protokoll- oder Ziel-Drift blockiert;
- `task-closeout-archive` und Workspace-Closeout können einen Prozessabschluss nicht als Systemabschluss hochstufen;
- rein mechanische Releases und Cleanup-Operationen bleiben ohne unnötige Doppelbewertung möglich, verlangen aber bei high-risk Artefakten einen gebundenen Upstream-Closeout;
- v1-Verbraucher und nachweislich niedrig riskante, rein dokumentarische Pfade bleiben kompatibel.

## Nichtbehauptungen

Dieser Audit ist eine revisionsgebundene Code- und Vertragsprüfung. Er beweist nicht:

- dass jeder externe Client die Operator-Instruktionen ignoriert;
- dass jeder abgeschlossene historische Vorgang fehlerhaft war;
- dass Cleanup- oder Lease-Release-Oberflächen selbst Konvergenzevidenz erzeugen sollten;
- dass der Konvergenzregelkreis Task-, Merge-, Deployment- oder Runtime-Autorität erhält.
