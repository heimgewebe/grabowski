# Transport-Roundtrip v3: atomare Zielausführung

## Zweck

Der Transport-Roundtrip schützt mutierende MCP-Aufrufe vor Fremdverbrauch, Wiederholung und Zielverwechslung. Eine Verifikation darf genau ein kanonisch gebundenes Werkzeug mit genau einem Argumentdigest zulassen.

`shared_unlabeled` ist nur eine gemeinsame Speicherpartition und keine Aufruferidentität. Deshalb darf dort eine bestätigte Verifikation nicht zwischen Bestätigung und späterem Zielaufruf frei im Pool liegen.

## Öffentlicher Ablauf

### Signierter Owner-Pfad (Normalfall)

1. `tunnel-client` leitet MCP an den lokalen `grabowski-transport-ingress` weiter.
2. Der Ingress entfernt alle vom entfernten Client gelieferten `X-Grabowski-*`-Header.
3. Für einen `tools/call` erzeugt er eine stabile Request-ID aus MCP-Session, JSON-RPC-ID und exaktem HTTP-Body-Digest.
4. Er bindet Request-ID, Timestamp, Audience, Werkzeug, kanonischen Argumentdigest, Body-Digest und den Digest der aktuell deployten Runtime mit HMAC an die lokal eingeschriebene Connector-Capability.
5. Der Operator prüft Capability, MAC, signierte Runtimebindung, Frische und Einmalverbrauch und führt die Mutation im selben MCP-Aufruf aus.

Damit benötigt der normale Owner-Pfad genau **einen** Agentenaufruf. Die Request-ID ist Idempotenz- und Replayanker, keine ChatGPT-Threadidentität. Eine bereits konsumierte Request-ID wird nicht erneut ausgeführt; nach Antwortverlust ist der Zielzustand zu reconciliieren.

Der langlebige Replay-Filter trennt identische Bodies innerhalb eines stabilen Connector-Scopes zusätzlich nach der bereits signierten MCP-Session. Für **neu unter diesem Vertrag konsumierte** Requests werden gleiche legitime `tools/call`-Bodies in späteren, von der Plattform neu erzeugten MCP-Sessions deshalb nicht dauerhaft miteinander verklebt. Innerhalb derselben Session bleibt der Body auch über Capability-Tokenrotation hinweg einmalig. Historische v1-Body-Bits aus der Zeit vor der sessiongebundenen Replay-Identität bleiben dagegen bewusst fail-closed und werden im monotonen Filter nicht nachträglich gelöscht; ein bereits vor dem Upgrade markierter Body kann daher weiterhin sessionübergreifend blockieren. Eine sichere Auflösung dieses Altzustands benötigt eine explizite, belegte Session-/Intent-Terminalisierung und ist nicht Teil dieses Vertragswechsels. `mcp-session-id` ist weiterhin **keine Autorität**: Ausführungsautorität entsteht ausschließlich aus eingeschriebener Connector-Capability, gültiger Signatur, Runtimebindung und Frische. Fehlt eine Session-ID, bleibt aus Kompatibilitäts- und Fail-closed-Gründen die historische Body-weite Replay-Identität erhalten.

### Domain-Reentry für intrinsisch idempotente Post-Merge-Synchronisation

Der Durable-Replay-Filter bleibt für mutierende Werkzeuge grundsätzlich fail-closed. Eine eng begrenzte Ausnahme gilt ausschließlich für `grip_run(name="post-merge-sync-apply", profile="operator", allow_mutation=true)`: Wenn der aktuelle Aufruf eine gültige signierte Connector-Capability, MAC, Frische und Runtimebindung besitzt, aber wegen bereits vorhandener Replay-Evidenz als `TransportAssertionReplay` klassifiziert wird, darf der Operator denselben exakt gebundenen Grip bis zu seiner eigenen Reconciliation eintreten lassen. Das erzeugt **keine** allgemeine Retry-Autorität und behauptet keinen neuen Transport-Einmalverbrauch.

Der Reentry ist zusätzlich an den aktuellen Grip-Vertrag gebunden: geschützter kanonischer Checkout, saubere exakte Preimage, Remote-Head-Bindung, Fast-Forward-Prüfung, exklusive Worktree/Common-Dir/Branch-Serialisierung, Branch-CAS, verifizierter Post-State und fail-closed `outcome_unknown` müssen weiterhin Bestandteil der Acceptance-Gates sein. Die Domain liest Checkout und Remote vor jeder Wirkung frisch. Ein bereits abgeschlossener vorheriger Effekt konvergiert damit auf `already_synced`; Dirty-, Drift-, Lease-, CAS- oder mehrdeutige Teilzustände blockieren weiterhin mit `retry_authorized=false`.

Für die zentrale Effect-Admission wird dieser Reentry nicht als neuer Transport-Receipt ausgegeben. Stattdessen bleibt er an den Digest der bereits signierten Runtime gebunden, sodass die vorhandene Writer-Fence- und Audit-Admission weiter greift. Andere Grips, andere Argumentdigests und generische Replay-Fälle bleiben unverändert gesperrt.

### Roundtrip-Fallback

Wenn eine Anfrage nicht über den signierten Ingress kommt, bleibt der Roundtrip während der Migration fail-closed erhalten. Für `shared_unlabeled` gilt genau dieser Normalablauf:

1. Der Client ruft das exakte mutierende Ziel einmal normal auf; der Aufruf erzeugt vor jeder Produktwirkung eine Challenge. Der Server darf Werkzeug und Argumente zusätzlich kurzzeitig im Prozess halten, aber diese Retention ist keine Cross-call-Garantie.
2. Der Client ruft `grip_run(name="transport-roundtrip", action="execute", challenge_receipt_sha256=..., target_tool_name=..., target_arguments=...)` mit demselben exakten Zielwerkzeug und den unveränderten Zielargumenten auf.
3. `execute` prüft das erneut übergebene Ziel gegen die dauerhaft in der Challenge gebundene Werkzeug-/Argumentdigest-Identität, reserviert und verbraucht die Challenge und dispatcht das Ziel im selben In-Prozess-Kontext. Vorhandene passende Retention darf zusätzlich als Same-Process-Konsistenzprüfung verwendet werden, ist für den kanonischen Cross-call-Pfad aber nicht erforderlich.

Challenge-only `action=execute` bleibt nur eine opportunistische Same-Process-Optimierung, solange das exakte Target noch im selben Prozess gehalten wird. Clients dürfen sich darauf über getrennte Connector-Calls, Prozesswechsel, Deploys, Restarts oder Retention-Eviction hinweg nicht verlassen. Fehlt diese Retention bei einem Challenge-only-Versuch, gilt der Vorgang nur dann als wirkungsfrei, wenn die noch pending Challenge atomar storniert werden konnte; andernfalls bleibt der Ausgang mehrdeutig und verlangt zielspezifischen Readback. Ein stabiler, servervalidierter Connector-Scope kann weiterhin `begin`/`ack` verwenden. Client-deklarierte Metadaten wie `_meta.client_id` bleiben ohne Autorität, und ein separater bestätigter Token wird nie an den gemeinsamen Pool ausgegeben.

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

- `tests/test_transport_one_call.py`
- `tests/test_transport_roundtrip.py`
- `tests/test_transport_gate_integration.py`
- `tests/test_transport_roundtrip_intent_replacement.py`
- `tests/test_operator_v2_runtime.py`

Der revisionsgebundene Laufnachweis wird unter `docs/proofs/transport-roundtrip-v3-t139-20260804.md` veröffentlicht.

## T142-Grundlage: stabile Connector-Capability

Für HTTP-Tunnel kann `tunnel-client` mit `mcp.extra-headers` einen statischen, lokal konfigurierten Header aus einer `file:/...`-Quelle an **jede** downstream MCP-Anfrage anhängen. Der signierte Normalpfad verwendet dort ausschließlich `X-Grabowski-Ingress-Auth`. Der Loopback-Ingress entfernt alle extern gelieferten `X-Grabowski-*`-Header und setzt anschließend selbst `X-Grabowski-Connector-Capability` sowie die signierte One-Call-Evidenz für den Operator. Ein direkt gesetzter Capability-Header bleibt nur für eingeschriebene lokale Kompatibilitäts-Connectoren vorgesehen.

Die Capability bleibt der Protokollanker:

- jede Connector-Instanz besitzt ein eigenes zufälliges Token in `~/.local/state/grabowski/transport-connectors/<id>.token`;
- Token-Dateien und Identitätswurzel müssen dem Grabowski-Benutzer gehören, dürfen keine Symlinks sein und sind für Gruppe/Andere unzugänglich;
- der rohe Tokenwert erscheint nie im Transportzustand oder Receipt; die Scope-ID ist ein domänengebundener SHA-256-Digest ausschließlich der stabilen Connector-ID;
- zwei verschiedene Connector-IDs erhalten auch bei Tokenwechseln getrennte `connector_capability`-Scopes;
- ein Server-Neustart oder die Rotation des Capability-Tokens erhält den Scope derselben Connector-ID und damit die dauerhafte Einmalverbrauchsgrenze;
- `_meta.client_id`, Python-Objektidentität und `mcp-session-id` sind keine Autorität; OpenAI kann pro Tool-Aufruf weiterhin eine neue MCP-Session erzeugen;
- ein unbekannter Capability-Header scheitert immer fail-closed.

Der Rollout ist absichtlich zweiphasig. Solange der sichere Marker `require-identity` fehlt, bleiben headerlose Aufrufe nur im bisherigen `shared_unlabeled`-Atomic-Pfad, damit Ingress und Capability ohne Connector-Ausfall ausgerollt werden können. Nach Provisionierung und Live-Nachweis beider Tunnel wird der Marker mit Inhalt `required-v1` gesetzt. Ab dann scheitert jede Mutation **vor dem Handshake**, wenn der Operator keinen gültigen Connector-Capability-Header beobachtet; im signierten Normalpfad darf dieser Header nur vom lokalen Ingress stammen. Read-only-Werkzeuge bleiben davon unabhängig.

Dieser Vertrag authentifiziert die lokal konfigurierte Tunnelinstanz, nicht die menschliche Person hinter dem entfernten Client. Er schützt nicht gegen kompromittierten Code desselben Betriebssystembenutzers, der die 0600-Token-Dateien lesen kann.