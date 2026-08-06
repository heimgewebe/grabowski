# Transport-Roundtrip v3: atomare Zielausführung

## Zweck

Der Transport-Roundtrip schützt mutierende MCP-Aufrufe vor Fremdverbrauch, Wiederholung und Zielverwechslung. Eine Verifikation darf genau ein kanonisch gebundenes Werkzeug mit genau einem Argumentdigest zulassen.

`shared_unlabeled` ist nur eine gemeinsame Speicherpartition und keine Aufruferidentität. Deshalb darf dort eine bestätigte Verifikation nicht zwischen Bestätigung und späterem Zielaufruf frei im Pool liegen.

## Öffentlicher Ablauf

### Stabil identifizierter Client

1. `grip_run(name="transport-roundtrip", action="begin", target_tool_name=..., target_arguments=...)`
2. `action="ack"` mit dem exakten Challenge-Hash
3. exakt ein unveränderter Zielaufruf

Dieser Kompatibilitätspfad bleibt nur für `client_declared_meta` erhalten. Zielwerkzeug, kanonischer Argumentdigest, Runtimebindung, Ablaufzeit und Einmalverbrauch bleiben geprüft.

### Gemeinsamer unbeschrifteter Client

1. `action="begin"` mit exaktem Zielwerkzeug und exakten Argumenten
2. `action="execute"` mit demselben Ziel, denselben Argumenten und dem zurückgegebenen Challenge-Hash

`execute` reserviert die Challenge, bindet eine daraus abgeleitete Ausführungsfähigkeit an den aktuellen In-Prozess-Kontext, lässt den normalen zentralen Mutations-Gate die Reservierung verbrauchen und dispatcht das Ziel in derselben MCP-Anfrage. Ein separater bestätigter Token wird nicht an den gemeinsamen Pool ausgegeben.

## Zustands- und Sicherheitsvertrag

- Zustandsformat: `STATE_SCHEMA_VERSION = 3`.
- Bestehende v2-Verifikationen im gemeinsamen Pool sind übertragbar und werden bei der Migration verworfen. Sie können keine neue Mutation autorisieren.
- Frische, exakt gebundene Pending-Challenges bleiben diagnostizierbar; jede neue gemeinsame `begin`-Anfrage erhält eine eigene Challenge.
- Die Ausführungsfähigkeit wird nur als SHA-256-Bindung der Challenge persistiert. Der Zielaufruf erhält die Challenge nicht als Produktargument.
- Direkter Verbrauch einer reservierten gemeinsamen Verifikation außerhalb ihres Ausführungskontexts scheitert mit `TransportAtomicExecutionRequired`, `TransportExecutionCapabilityRequired` oder `TransportExecutionCapabilityMismatch`.
- Verschachtelte atomare Transportausführungen und rekursive `transport-roundtrip`-Ziele werden abgewiesen.
- Read-only-Werkzeuge benötigen und verbrauchen weiterhin keine Mutationsverifikation.

## Fehler- und Recovery-Semantik

- Scheitert der Dispatch vor dem Verbrauch, wird die unverbrauchte Reservierung entfernt.
- Wurde die Reservierung verbraucht, gilt der Effekt als potenziell erfolgt. Eine Ausnahme oder ein MCP-Ergebnis mit `isError=true` wird als `target_failed` ausgewiesen; die Verifikation bleibt verbraucht.
- Ein verlorener oder mehrdeutiger Zielausgang gewährt keine Retry-Autorität. Vor einem neuen Versuch ist der Zielzustand zu lesen.
- Werkzeug-, Argument-, Runtime-, Ablauf- und Capability-Abweichungen scheitern vor Produktwirkung.

## Grenzen

Der Vertrag authentifiziert keinen Menschen und schützt nicht gegen kompromittierten Code desselben Betriebssystembenutzers, der private Zustandsdateien lesen kann. Er ersetzt keine Lease-, Review-, Merge-, Deployment- oder Recovery-Autorität. Die atomare Route beweist die Admission und den beobachteten Zielausgang, nicht die fachliche Richtigkeit des Zielsystems.

## Verifikation

Die verbindlichen Tests liegen in:

- `tests/test_transport_roundtrip.py`
- `tests/test_transport_gate_integration.py`
- `tests/test_transport_roundtrip_intent_replacement.py`
- `tests/test_operator_v2_runtime.py`

Der revisionsgebundene Laufnachweis wird unter `docs/proofs/transport-roundtrip-v3-t139-20260804.md` veröffentlicht.
