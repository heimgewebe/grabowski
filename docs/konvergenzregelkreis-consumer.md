# Konvergenzregelkreis-Consumer

Grabowski stellt mit `grip_run(name="convergence-assess")` einen read-only Consumer des öffentlichen Konvergenzprotokolls bereit.

## Zweck

Der Grip bewertet einen bereits erzeugten Assessment-Request vor dem Abschluss von Deployment-, Runtime-, Security-, Daten- oder irreversibler Arbeit. Er besitzt keine Task-, Deployment- oder Runtime-Wahrheit und führt keine Mutation aus.

## Bindungen

Der Aufruf benötigt:

- `request_path`: absolute lokale JSON-Datei;
- `expected_request_sha256`: SHA-256 der unveränderten Requestbytes;
- `expected_protocol_head`: exakter Commit des Protokollrepositories.

Vor der Auswertung prüft Grabowski:

1. reguläre, nicht per Symlink adressierte Requestdatei innerhalb des Größenlimits;
2. bytegenauen Request-Hash;
3. exakten Protokollcommit;
4. sauberen Protokollcheckout;
5. regulären Evaluator;
6. Konsistenz von Status, Schema und Exit-Code.

Nur `terminally_closed` ergibt `closure_allowed=true`. Alle anderen fachlichen Zustände liefern einen gültigen, aber blockierenden Receipt. Eingabe-, Identitäts- und Ausführungsfehler scheitern geschlossen.

## Beispiel

```json
{
  "name": "convergence-assess",
  "parameters": {
    "request_path": "/absolute/path/to/assessment-request.json",
    "expected_request_sha256": "<64 lowercase hex>",
    "expected_protocol_head": "83ed435bf9eb490e81a6ff2103b6c1397440d40b"
  }
}
```

Der Assessment-Receipt muss anschließend in den Abschlussbelegen referenziert werden. Er ersetzt weder Bureau-Abschluss noch Chronikpersistenz.
