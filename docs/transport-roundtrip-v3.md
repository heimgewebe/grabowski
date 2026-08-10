# Transport-Roundtrip v3: atomare Zielausführung

## Zweck

Der Transport-Roundtrip schützt mutierende MCP-Aufrufe vor Fremdverbrauch, Wiederholung und Zielverwechslung. Eine Verifikation darf genau ein kanonisch gebundenes Werkzeug mit genau einem Argumentdigest zulassen.

`shared_unlabeled` ist nur eine gemeinsame Speicherpartition und keine Aufruferidentität. Deshalb darf dort eine bestätigte Verifikation nicht zwischen Bestätigung und späterem Zielaufruf frei im Pool liegen.

## Öffentlicher Ablauf

### Servervalidierter Connector

1. Der lokale Tunnel hängt seinen geheimen `X-Grabowski-Connector-Capability`-Header an jede MCP-Anfrage.
2. `grip_run(name="transport-roundtrip", action="begin", target_tool_name=..., target_arguments=...)`
3. `action="ack"` mit dem exakten Challenge-Hash
4. exakt ein unveränderter Zielaufruf

Der Ack-Pfad ist nur für einen stabilen, servervalidierten `connector_capability`-Scope vorgesehen. Client-deklarierte Metadaten wie `_meta.client_id` sind keine Autorität. Zielwerkzeug, kanonischer Argumentdigest, Runtimebindung, Ablaufzeit und Einmalverbrauch bleiben geprüft.

### Gemeinsamer unbeschrifteter Client

1. `action="begin"` mit exaktem Zielwerkzeug und exakten Argumenten
2. `action="execute"` mit demselben Ziel, denselben Argumenten und dem zurückgegebenen Challenge-Hash

`execute` reserviert die Challenge, bindet eine daraus abgeleitete Ausführungsfähigkeit an den aktuellen In-Prozess-Kontext, lässt den normalen zentralen Mutations-Gate die Reservierung verbrauchen und dispatcht das Ziel in derselben MCP-Anfrage. Ein separater bestätigter Token wird nicht an den gemeinsamen Pool ausgegeben.

## Zustands- und Sicherheitsvertrag

- Zustandsformat: `STATE_SCHEMA_VERSION = 4`.
- Bestehende v2- und v3-Verifikationen werden bei der Migration verworfen. Insbesondere kann kein vor T142 erzeugter objekt-, Meta- oder Shared-Scope eine Schema-v4-Mutation autorisieren.
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

## T142: stabile Connector-Capability

Für HTTP-Tunnel kann `tunnel-client` mit `mcp.extra-headers` einen statischen, lokal konfigurierten Header aus einer `file:/...`-Quelle an **jede** downstream MCP-Anfrage anhängen. Grabowski nutzt `X-Grabowski-Connector-Capability` als Protokollanker:

- jede Connector-Instanz besitzt ein eigenes zufälliges Token in `~/.local/state/grabowski/transport-connectors/<id>.token`;
- Token-Dateien und Identitätswurzel müssen dem Grabowski-Benutzer gehören, dürfen keine Symlinks sein und sind für Gruppe/Andere unzugänglich;
- der rohe Tokenwert erscheint nie im Transportzustand oder Receipt; die Scope-ID ist ein SHA-256-Digest aus Connector-ID, Token und einer zufälligen Server-Instanz-ID;
- zwei Tunnel mit verschiedenen Token erhalten verschiedene `connector_capability`-Scopes;
- ein Server-Neustart ändert die Instanz-ID und macht alte Connector-Scopes unverwendbar;
- `_meta.client_id`, Python-Objektidentität und `mcp-session-id` sind keine Autorität; OpenAI kann pro Tool-Aufruf weiterhin eine neue MCP-Session erzeugen;
- ein unbekannter Capability-Header scheitert immer fail-closed.

Der Rollout ist absichtlich zweiphasig. Solange der sichere Marker `require-identity` fehlt, bleiben headerlose Aufrufe nur im bisherigen `shared_unlabeled`-Atomic-Pfad, damit die Capability ohne Connector-Ausfall ausgerollt werden kann. Nach Provisionierung und Live-Nachweis beider Tunnel wird der Marker mit Inhalt `required-v1` gesetzt. Ab dann scheitert jede Mutation **vor dem Handshake**, wenn kein gültiger Connector-Capability-Header vorhanden ist. Read-only-Werkzeuge bleiben davon unabhängig.

Dieser Vertrag authentifiziert die lokal konfigurierte Tunnelinstanz, nicht die menschliche Person hinter dem entfernten Client. Er schützt nicht gegen kompromittierten Code desselben Betriebssystembenutzers, der die 0600-Token-Dateien lesen kann.
