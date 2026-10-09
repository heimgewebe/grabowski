# Konvergenzregelkreis-Consumer

Stand: 2026-09-23

Grabowski stellt mit `grip_run(name="convergence-assess")` einen read-only Consumer des öffentlichen Konvergenzprotokolls bereit.

## Zweck

Der Grip bewertet einen bereits erzeugten Assessment-Request vor einem systemischen Abschluss. Er besitzt keine Task-, Deployment-, Bureau- oder Runtime-Wahrheit und führt selbst keine Mutation aus.

## Bindungen

Der Aufruf benötigt:

- `request_path`: absolute lokale JSON-Datei;
- `expected_request_sha256`: SHA-256 der unveränderten Requestbytes;
- `expected_protocol_head`: exakter Commit des Protokolls.

Vor und nach der Auswertung bindet Grabowski die Request- und Protokollidentität fail-closed.

Für den erwarteten Protokollcommit gilt genau ein Evaluationspfad:

1. Ist ein gültiges immutable Runtime-Bundle für diesen Commit vorhanden, werden Wheel, eingebettete Verträge und Resilienzprofil hashgebunden daraus ausgewertet.
2. Andernfalls muss der verifizierte Protokollcheckout exakt auf `expected_protocol_head` stehen, sauber sein und einen gebundenen regulären Evaluator bereitstellen.

Ändert sich die verwendete Bundle- oder Checkout-/Evaluatoridentität während der Auswertung, scheitert der Consumer geschlossen.

Nur:

```text
assessment.status = terminally_closed
```

ergibt:

```text
closure_allowed = true
decision = allow_closure
```

Nichtterminale fachliche Ergebnisse liefern einen gültigen, aber blockierenden Consumer-Receipt.

## Beispiel

```json
{
  "name": "convergence-assess",
  "parameters": {
    "request_path": "/absolute/path/to/assessment-request.json",
    "expected_request_sha256": "<64 lowercase hex>",
    "expected_protocol_head": "c2f75946aa0f3f37646f3c93f1c176c683f341cc"
  }
}
```

Der Receipt bindet die ausgewertete Assessment-Ausgabe. Er ersetzt weder Bureau-Abschluss noch Chronikpersistenz noch die Primärquellen der behaupteten Wirkung.

## Durchsetzung bei Operator-Obligations

`operator-obligation-close` unterscheidet heute explizit zwischen Prozess- und Systemabschluss.

Ein systemisches `completed` verlangt:

```text
convergence_required = true
reason = systemic
+ bestandener convergence-assess-Receipt
+ v2 assessment
+ status = terminally_closed
```

Die Bindung umfasst den konkreten Obligation-Abschluss. Direkt vor der Persistenz führt Grabowski das Assessment mit Request-Pfad, Request-Hash und Protokoll-Head erneut live aus. Nur wenn die frische Ausgabe weiterhin `allow_closure` liefert und exakt zur gebundenen Ausgabe passt, darf der create-only Close erfolgen.

Ein nichtterminaler, ungültiger oder gedrifteter Receipt blockiert den systemischen Close.

Ein explizites:

```text
convergence_required = false
reason = process_only
```

behauptet dagegen keine systemische Konvergenz und benötigt deshalb keinen Consumer-Receipt.

## Scope-Grenze

Diese technische Erzwingung gilt für den systemischen `operator-obligation-close`. Daraus folgt nicht, dass jede Task-, Workspace-, Archiv-, Lease- oder Cleanup-Fläche ebenfalls ein eigenes Konvergenzgate erhalten soll.

Die relevante Unterscheidung bleibt:

```text
Prozessabschluss
Effekt
Cleanup
systemischer Abschluss
```

Nur der letzte Fall benötigt zwingend systemische Konvergenzevidenz.

## Cross-Repo-Regressionsbeleg

`test_real_regelkreis_conformance_and_evaluation` prüft den echten Regelkreis sowohl positiv als auch mit gezielt fehlender Closure-Evidenz. Die normale Validate-CI stellt dafür den Protokollcommit `c2f75946aa0f3f37646f3c93f1c176c683f341cc` als gepinnten Geschwister-Checkout mit Evaluator bereit. Dadurch läuft der bestehende Testpfad auch in CI, statt wegen fehlendem lokalem Checkout übersprungen zu werden.
