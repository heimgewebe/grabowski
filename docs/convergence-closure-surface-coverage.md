# Konvergenz-Abdeckung der Operator-Abschlussflächen

Stand: 2026-09-23

Geprüfter Grabowski-`main`: `2dec93336884852660e5b7d0ca1ca9ce756752d2`

Geprüfte Produktionsruntime: `d1e1d3dd8df3504b2e8913c49f00b9a020429840`

Geprüfter Protokoll-Commit: `c2f75946aa0f3f37646f3c93f1c176c683f341cc`

Die für diesen Vertrag relevanten Implementierungs- und Testdateien `grabowski_convergence.py`, `grabowski_operator_obligation.py`, `grabowski_grips.py`, `test_convergence.py` und `test_grips.py` sind zwischen der geprüften Produktionsruntime und dem genannten `main` unverändert.

## Fragestellung

Dieser Audit trennt vier unterschiedliche Dinge:

- **systemischen Abschluss**: Eine Wirkung darf als systemisch abgeschlossen gelten;
- **Prozessabschluss**: Ein Prozess, Task oder Workspace ist terminal;
- **Effekt**: Merge, Deployment oder Veröffentlichung hat stattgefunden;
- **Hygiene**: Leases, Worktrees oder Archive werden bereinigt.

Nur ein systemischer Abschluss benötigt zwingend terminale Konvergenzevidenz. Prozessende, Effekt und Cleanup dürfen diese Evidenz weder ersetzen noch selbst erfinden.

## Consumer

`convergence-assess` ist ein read-only Grip. Er bindet die Requestbytes an `expected_request_sha256` und das Protokoll an `expected_protocol_head`.

Für den erwarteten Protokollcommit verwendet Grabowski bevorzugt ein verifiziertes immutable Runtime-Bundle. Ist für diesen Commit kein Bundle vorhanden, wird ausschließlich ein sauberer Checkout mit exakt passendem HEAD und gebundenem Evaluator akzeptiert. Identitätsdrift während der Auswertung scheitert fail-closed.

Nur `assessment.status=terminally_closed` ergibt:

```text
closure_allowed = true
decision = allow_closure
```

Fachlich nichtterminale Zustände wie `evidence_missing`, `conflicting_evidence`, `source_stale` oder `blocked` ergeben einen gültigen, aber blockierenden Consumer-Receipt.

## Systemischer Operator-Abschluss

Die im Audit vom 26.07.2026 dokumentierte semantische Lücke von `operator-obligation-close` besteht im aktuellen Vertrag nicht mehr.

Für `outcome=completed` ist heute eine explizite `closure_classification` Pflicht.

### Systemischer Abschluss

```text
convergence_required = true
reason = systemic
```

verlangt einen exakt gebundenen, bestandenen `convergence-assess`-Receipt mit einer v2-Ausgabe `status=terminally_closed`. Gebunden und geprüft werden unter anderem Request-Hash, Protokoll-Head, Assessment-ID, Profilidentität, Output-Hash und die konkrete `closure_id=operator-obligation:<obligation_id>`.

Unmittelbar vor dem create-only Close führt Grabowski das gebundene Assessment erneut live aus. Die frische Ausgabe muss weiterhin Closure erlauben und exakt zur gebundenen Consumer-Ausgabe passen. Nichtterminaler Zustand oder Drift blockieren den systemischen Close.

### Prozessabschluss

```text
convergence_required = false
reason = process_only
```

ist weiterhin zulässig, enthält aber keinen Konvergenz-Receipt und behauptet ausdrücklich keine systemische Konvergenz.

## Abdeckungsmatrix

| Oberfläche | Wirkung | Aktueller Konvergenzstatus |
|---|---|---|
| `convergence-assess` | bewertet ein hash- und revisionsgebundenes Belegpaket | **Consumer belegt** |
| `operator-obligation-close` / `completed` / `systemic` | persistiert einen systemischen Operator-Abschluss | **terminales v2-Assessment technisch erzwungen und live revalidiert** |
| `operator-obligation-close` / `completed` / `process_only` | persistiert nur acceptance-gebundenen Prozessabschluss | **explizit nichtsystemisch** |
| `task-closeout-archive` | archiviert und projiziert einen terminalen Task | **Prozess/Hygiene; kein eigener Systemabschluss** |
| `grabowski_agent_workspace_close` | schließt einen Workspace | **Workspace-/Prozessabschluss; kein eigener Systemabschluss** |
| `grabowski_agent_workspace_cleanup`, Checkout-Cleanup | räumt bereits klassifizierten Zustand auf | **Hygiene; kein eigener Assessment-Fall** |
| Lease-Release-Flächen | geben gebundene Ressourcen frei | **Hygiene; kein eigener Assessment-Fall** |
| `grabowski_git`, `branch-publish`, `pr-base-converge`, `pr-create-or-update`, `grabowski_bureau_task_publish` | erzeugen Branch-, PR- oder Publikationseffekte | **Effekt, nicht selbst Systemabschluss** |
| `grabowski_text_artifact_publish` | publiziert unveränderliche Textevidenz | **Evidenzfläche, nicht selbst Systemabschluss** |
| `pr-check-readiness`, `grabowski_bureau_task_publish_preview`, `grabowski_github_pr_view` | beobachten Readiness oder Publikationszustand | **read-only, kein Systemabschluss** |
| Deploy-Flächen | erzeugen Deployment-Effekte | **Evidenz für spätere Verifikation, nicht selbst Systemabschluss** |

Eine Prozess- oder Hygieneoberfläche soll nicht allein deshalb ein eigenes Konvergenzgate erhalten. Entscheidend ist, ob sie selbst systemische Konvergenz behauptet.

## Historischer Proof

`docs/proofs/convergence-closure-surface-coverage-v1.json` bleibt als revisionsgebundener Beleg des Audits vom 26.07.2026 erhalten. Seine Klassifikation `operator-obligation-close = semantic_gap` beschreibt den dort gebundenen alten Grabowski-Commit und ist **keine aktuelle Klassifikation** des heutigen Codes.

## Produktionsbeleg vom 23.09.2026

Gegen die tatsächlich deployte Grabowski-Runtime und den echten Protokollcheckout `c2f75946...` wurden beide Richtungen ausgeführt:

1. Ein vollständiger v2-R2-Request ergab `terminally_closed / allow_closure`. Ein daran exakt gebundener `operator-obligation-close` wurde als `completion_scope=systemic` create-only persistiert.
2. Derselbe reale Protokollpfad mit gezielt fehlender Closure-Evidenz ergab `evidence_missing / block_closure`. Der anschließende systemische `operator-obligation-close` blockierte und erzeugte kein Close-Record.

Damit ist für diese Abschlussfläche sowohl der positive als auch der fail-closed negative Runtimepfad belegt.

## Regressionssicherung

Die Unit-/Integrationstests prüfen zusätzlich unter anderem:

- fehlende oder ungültige Completion-Klassifikation;
- nichtterminales Assessment;
- Request-, Protokoll- und Output-Drift;
- Live-Revalidierung direkt vor dem Close;
- explizite Trennung von `systemic` und `process_only`.

Der vorhandene Cross-Repo-Test `test_real_regelkreis_conformance_and_evaluation` bleibt der kanonische Vertragstest gegen den echten Regelkreis. Die Validate-CI stellt dafür den Protokollcommit `c2f75946...` als gepinnten Geschwister-Checkout samt Evaluator bereit, statt einen zweiten Testpfad einzuführen.

## Nichtbehauptungen

Dieser Nachweis bedeutet nicht:

- dass jede Prozess-, Effekt- oder Cleanup-Fläche ein eigenes Konvergenzgate benötigt;
- dass `convergence-assess` Task-, Merge-, Deployment-, Bureau- oder Runtime-Autorität erhält;
- dass ein Prozessabschluss automatisch ein Systemabschluss ist;
- dass ein erfolgreicher Effekt ohne nachfolgende Verifikation systemisch abgeschlossen ist.