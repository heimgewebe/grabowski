# Transport-Roundtrip v3 – T139-Nachweis

## Bindung

- Bureau-Task: `GRABOWSKI-OPERATOR-SURFACE-V1-T139`
- koordinierter Lauf: `BUR-RUN-20260806T043411Z-6bf5bd0a99`
- Ausgangscommit: `2e22fb481da08ae3e4adff1760a3674195333561`
- Ausgangsquelle `src/grabowski_transport_roundtrip.py`: `4b9521777e47870ffb787796a62eff92d2909984ccd942102fb5a8d5673a18c5`
- Kandidatenquelle `src/grabowski_transport_roundtrip.py`: `13f1e9e3d8fe624e5c995675f579b01af01e922fec5cb0a891428bc2957c39c9`
- Zustandsvertrag: Schema v2 → Schema v3

Dieser Nachweis bindet den im selben Commit enthaltenen Kandidaten. Der spätere Merge-, Deployment- und Live-Readback wird zusätzlich im PR- und Bureau-Closeout belegt.

## Fehlerbild vor der Reparatur

`shared_unlabeled` war eine gemeinsame Speicherpartition und keine Aufruferidentität. Nach `begin → ack` lag ein exakt zielgebundener, aber frei aus dem gemeinsamen Pool konsumierbarer Einmaltoken vor. Ein anderer gleichartig unbeschrifteter Aufrufer konnte ihn vor dem beabsichtigten Aufrufer verbrauchen.

Deterministischer Vorher-/Nachher-Lauf mit je 32 Versuchen:

| Messwert | Basis v2 | Kandidat v3 |
|---|---:|---:|
| fremder Verbrauch erfolgreich | 32/32 | 0/32 |
| beabsichtigter Besitzer erfolgreich | 0/32 nach Fremdverbrauch | 32/32 |
| Replay erfolgreich | 0/32 | 0/32 |

Basisfehler nach dem ersten Verbrauch: 64 × `TransportRoundtripRequired`.

Kandidatenfehler:

- 32 × `TransportAtomicExecutionRequired` für den fremden direkten Verbrauch,
- 32 × `TransportRoundtripRequired` für den Replay nach erfolgreichem Besitzerverbrauch.

Messjob:

- Unit: `grabowski-job-2932aed23848`
- Finalisierungsreceipt: `7fb2442b765bcc742f0ba57c7bd2b890b14a7b9e70e5178aff536430f48665f9`
- Payload-SHA-256: `2d2b5e2e2b49a1d98e140fc265425f72ee926edd397fa15e0643c946e866cd3d`

## Reparaturvertrag

Für `shared_unlabeled` gilt nun:

1. `begin` erzeugt eine frische, exakt an Werkzeug, Argumentdigest, Runtime und Ablaufzeit gebundene Challenge.
2. `execute` reserviert diese Challenge und leitet daraus eine Ausführungsfähigkeit ab.
3. Die Fähigkeit ist nur im aktuellen In-Prozess-Ausführungskontext verfügbar; die Challenge wird nicht als Produktargument weitergereicht.
4. Der bestehende zentrale Mutations-Gate ruft weiterhin `consume_verified()` auf und verbraucht die Reservierung genau einmal.
5. Der Ziel-Dispatch erfolgt in derselben MCP-Anfrage über den registrierten Tool-Manager.
6. Verschachtelte oder rekursive atomare Ausführungen scheitern vor Produktwirkung.

Stabil identifizierte `client_declared_meta`-Clients behalten den kompatiblen Ablauf `begin → ack → exakt ein Ziel`.

Ein Legacy-Client, der unter `shared_unlabeled` weiterhin `ack` versucht, erhält fail-closed die Anforderung zur atomaren `execute`-Route. Es entsteht kein übertragbarer bestätigter Pooltoken.

## Konkurrenz- und Einmalnachweis

Ein zusätzlicher Zwei-Prozess-Test verwendet nur **eine** reservierte Shared-Challenge:

- Prozess A versucht den direkten Verbrauch ohne Ausführungsfähigkeit,
- Prozess B besitzt den exakten Challenge-Kontext,
- genau Prozess B konsumiert,
- der Verifikationspool ist danach leer,
- ein Replay mit derselben Challenge scheitert.

Ergebnis: 2/2 Tests bestanden in 0,06 Sekunden.

Testjob:

- Unit: `grabowski-job-94f201d94096`
- Finalisierungsreceipt: `116a1f07d277290298dc1f7fcc9f65fe1d2bcaa132652dfe373c106f6c344a05`
- Payload-SHA-256: `1c82825a286e139292038a67f9e6ce46da620712d5cdf1a6999c946a192a1ea8`

## Validierung

Der erste fokussierte Lauf vor dem zusätzlichen Zwei-Prozess-Test umfasste die Transport-, Gate-, Grip- und Operatorverträge:

- 509 Tests bestanden,
- 243 Subtests bestanden,
- Laufzeit 66,07 Sekunden,
- Finalisierungsreceipt: `42d75c4f5c590d705c923a659483bdd0b0e420579a5a1dde59cedaf57faac12d`,
- Payload-SHA-256: `a488044190f07ee53baaafffd9dbd105d0474fdf9bfbcdf807f052af707f6cf0`.

Die abschließende erweiterte Matrix enthält zusätzlich den neuen Konkurrenztest, Operator-v2-Runtime, Consumer-Surface und Tool-Surface-Budget:

```text
env PYTHONPATH=src python3 -m pytest -q \
  tests/test_transport_roundtrip.py \
  tests/test_transport_gate_integration.py \
  tests/test_transport_roundtrip_intent_replacement.py \
  tests/test_grips.py \
  tests/test_operator_contract.py \
  tests/test_operator_v2_runtime.py \
  tests/test_consumer_surface.py \
  tests/test_tool_surface_budget.py
```

Ergebnis:

- 637 Tests bestanden,
- 269 Subtests bestanden,
- Laufzeit 71,21 Sekunden,
- Finalisierungsreceipt: `1905e0dab79aba5403f4622f33a4d10f2ea2fb2b06ccefbb7d9ca8242d265553`,
- Payload-SHA-256: `d8ad7df4086d40b5341a92538853a6fcdda1dd61208bf569b55937a4fdba04b9`.

Die vollständige Repositoryabnahme lief anschließend über `make validate`:

- 4.800 Tests bestanden,
- 12 Tests übersprungen,
- vollständiger Python-Unittest-Vertrag grün,
- Operator-Kontext generatorisch aktuell,
- Zugriffspolitik, Tool-Surface-Budget, Runtime- und Deploy-Tooling-Locks grün,
- Secret-Scan grün,
- Finalisierungsreceipt: `4d18517630f81362ae93562ee454b36998e00b61c2edf3822a210d191747b19e`,
- Payload-SHA-256: `c973360901d9087f0ef80f8991fde3358c01d7acddb93447b17e592674cf3712`.

Ein vorheriger direkter Pytest-Aufruf ohne `PYTHONPATH=src` scheiterte ausschließlich während der Modulsammlung. Er gilt nicht als Produktbefund und wurde mit der kanonischen Repository-Importumgebung ersetzt.

## Abgedeckte Negativ- und Recoveryfälle

- falsches Werkzeug oder falscher Argumentdigest,
- falsche Runtimebindung,
- abgelaufene Challenge,
- fremder direkter Shared-Verbrauch,
- fehlende oder falsche Ausführungsfähigkeit,
- Replay nach erfolgreichem Verbrauch,
- parallele unabhängige Shared-Handshakes,
- genau eine reservierte Challenge mit konkurrierendem Fremd- und Besitzerprozess,
- verschachtelte oder rekursive atomare Ausführung,
- Dispatchfehler vor Verbrauch mit Entfernung der ungenutzten Reservierung,
- Zielausnahme oder `isError=true` nach Verbrauch ohne automatische Retry-Autorität,
- Migration alter Shared-v2-Verifikationen ohne Übernahme ihrer Mutationsautorität.

## Grenzen

Der Vertrag authentifiziert keinen Menschen. Er schützt nicht gegen kompromittierten Code desselben Betriebssystembenutzers mit Zugriff auf private Zustandsdateien. Er ersetzt keine Task-, Lease-, Review-, Merge-, Deployment- oder Recovery-Autorität. Ein erfolgreich zugelassener Zielaufruf beweist nicht die fachliche Richtigkeit des Zielsystems; bei mehrdeutigem Ausgang ist vor einem neuen Versuch der Zielzustand zu lesen.
