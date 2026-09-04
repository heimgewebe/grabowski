# Maulwurf X: Grok als begrenzter Grabowski-Client

## Ziel

`Maulwurf X` ist **kein zweiter Grabowski**. Grok benutzt dieselbe kanonische
Grabowski-Runtime, erhält aber einen eigenen Principal, getrennte Secrets und
eine serverseitig erzwungene Least-Privilege-Toolpolicy.

```text
Grok
  -> stable HTTPS tunnel
  -> grabowski-external-connector-maulwurf-x (127.0.0.1:18184)
       external credential only
       tool projection
  -> grabowski-transport-ingress-maulwurf-x (127.0.0.1:18183)
       internal maulwurf-x connector capability
       signed one-call transport
  -> canonical/green Grabowski operator
```

Der bestehende OpenAI-Tunnel und `primary.token` bleiben unverändert. Das
externe Grok-Credential darf nie identisch mit der internen Grabowski-Capability
sein und wird nie an den Operator weitergereicht.

## Trust-Grenzen

### 1. External Connector Gateway

Das Gateway ist nur eine Providergrenze. Es:

- akzeptiert genau ein externes Credential über `Authorization: Bearer ...` oder
  `X-API-Key`;
- entfernt beide externen Auth-Header und alle vom Client gelieferten
  `X-Grabowski-*`-Header;
- setzt ausschließlich das interne `X-Grabowski-Ingress-Auth` für den sekundären
  signed ingress;
- projiziert bei `tools/list` nur die für `maulwurf-x` erlaubten Tools;
- verweigert nicht erlaubte `tools/call` bereits vor dem Upstream;
- bindet ausschließlich an Loopback.

Die Gateway-Filterung ist **nicht** die Autoritätsgrenze. Ein Fehler dort darf
keine zusätzlichen Operatorrechte erzeugen.

### 2. Signed transport ingress

Die zweite Ingress-Instanz verwendet ein eigenes
`transport-connectors/maulwurf-x.token`. Sie benutzt denselben
`operator-routing-selector.json` wie der primäre Ingress und folgt damit dem
kanonischen blue/green-Cutover statt eine zweite Runtime-Wahrheit zu erzeugen.

### 3. Autoritative Toolpolicy im Operator

Der Operator löst die signierte Connector-Capability zu einer serverseitig
enrollten Connector-ID auf. Ist `require-tool-policy` aktiv, muss jeder
enrollte Principal eine eigene `<connector-id>.tools.json` besitzen.

Für `maulwurf-x` gilt zusätzlich `read_only_only: true`. Selbst ein versehentlich
in die Allowlist aufgenommenes Tool wird verweigert, wenn seine aktuelle
MCP-Annotation nicht **explizit** `readOnlyHint=true` ist.

Dadurch bestehen zwei unabhängige Schranken:

1. **Projection Gate:** Grok sieht nur die Allowlist.
2. **Authority Gate:** Grabowski führt nur die Allowlist aus und prüft zusätzlich
   die Read-only-Semantik.

## Policy-Contract

Beispiel:

```json
{
  "schema_version": 1,
  "connector_id": "maulwurf-x",
  "mode": "allowlist",
  "read_only_only": true,
  "allowed_tools": ["grabowski_status"]
}
```

`mode=unrestricted` ist für bestehende vertrauenswürdige Principals als
Migrationsmodus vorgesehen; `allowed_tools` muss dann leer sein.

Die Repository-Vorlage für Maulwurf X liegt unter
`config/maulwurf-x-tools.json`. Ein Test bindet ihre Einträge an den publizierten
Runtime-Toolvertrag und an den Capability-Katalog mit `read_only=true`.

## Fail-closed-Aktivierung

Die Aktivierung muss in dieser Reihenfolge erfolgen:

1. Runtime mit Connector-Policy-Code und Gateway-Artefakten deployen.
2. Für alle bereits enrollten Connectoren explizite Policies schreiben:
   - `primary.tools.json`: zunächst `mode=unrestricted`, `read_only_only=false`;
   - `johannes.tools.json`: zunächst `mode=unrestricted`, `read_only_only=false`;
   - `maulwurf-x.tools.json`: aus `config/maulwurf-x-tools.json`.
3. Ein neues internes `maulwurf-x.token` erzeugen; Modus `0600`.
4. Ein davon verschiedenes externes Credential unter
   `~/.local/state/grabowski/external-connectors/maulwurf-x.token` erzeugen;
   Elternverzeichnis `0700`, Datei `0600`.
5. **Erst danach** `transport-connectors/require-tool-policy` mit exakt
   `required-v1` und Modus `0600` anlegen.
6. `grabowski-transport-ingress-maulwurf-x.service` **enable + start** und lokal prüfen.
7. `grabowski-external-connector-maulwurf-x.service` **enable + start** und lokal prüfen.
8. Erst nach lokalem Negativ-/Positivtest einen stabilen HTTPS-Tunnel auf
   `127.0.0.1:18184` schalten.
9. Grok-Connector unter dem Namen **Maulwurf X** anlegen.

Der Marker wird absichtlich zuletzt gesetzt. Fehlt danach für irgendeinen
enrollten Principal die Policy oder ist sie ungültig, verweigert der Operator
dessen Calls statt auf globale `trusted-owner`-Rechte zurückzufallen.

Die Install-Targets bilden eine optionale, erst durch `enable` aktivierte
Startkette: der primäre signed ingress zieht den Maulwurf-X-Ingress, dieser das
Gateway. `PartOf` propagiert Stop/Restart nach unten. Damit bleiben normale
Grabowski-Deployments restartfest, ohne dass ein nicht provisionierter Maulwurf X
den primären Connector als Pflichtabhängigkeit belastet.

## Abnahme

Positive Beweise:

- Gateway ohne Secret-Ausgabe gesund;
- signed ingress gesund und an denselben Runtime-Routing-Selector gebunden;
- `tools/list` enthält exakt die Maulwurf-X-Allowlist;
- `grabowski_runtime_health` funktioniert über Maulwurf X;
- Operator löst den Principal als `maulwurf-x` auf;
- Neustart beider Services erhält die Funktion;
- primärer ChatGPT-Connector bleibt unverändert funktionsfähig.

Negative Beweise:

- kein externes Credential -> `401`;
- falsches externes Credential -> `401`;
- gleiches externes und internes Secret -> Gateway startet nicht;
- fremde `X-Grabowski-*`-Header -> werden verworfen;
- nicht allowgelistetes Tool -> Gateway verweigert;
- manuell am Gateway vorbei an den signed ingress gesendetes, nicht erlaubtes
  Tool -> Operator verweigert;
- allowgelistetes Tool ohne explizites `readOnlyHint=true` -> Operator verweigert;
- fehlende Principal-Policy bei aktivem Marker -> fail closed.

## Öffentlicher Tunnel und Grok-Auth

Der vorhandene `tunnel-client-grabowski` ist OpenAI-spezifisch und wird für
Maulwurf X nicht wiederverwendet. Der Produktionspfad benötigt einen eigenen,
providerneutralen, stabilen HTTPS-Endpunkt vor Port 18184.

Auf dem Heim-PC ist Tailscale bereits vorhanden; `cloudflared` ist nicht
installiert. Für den ersten produktiven Cutover ist deshalb ein **Tailscale
Funnel auf HTTPS-Port 8443** der bevorzugte Pfad. Er benötigt keine
Router-Portfreigabe und zeigt ausschließlich auf `http://127.0.0.1:18184`.
Der Funnel wird erst nach den lokalen Positiv- und Negativtests aktiviert.

Das Gateway unterstützt als schmalen ersten Vertrag Bearer-Header und
`X-API-Key`. Die konkrete Grok-App-Authentisierungs-UX wird erst gegen die reale
Grok-Oberfläche abgenommen. Vollständiges OAuth wird **nicht vorsorglich**
gebaut. Falls Grok im realen Connector zwingend OAuth verlangt, ist das ein
separater Adapter-Folgeschritt an der äußeren Gateway-Grenze; interne
Grabowski-Identität und Toolpolicy bleiben unverändert.

## Rollback

Der Rollback ist schichtweise und beschädigt den primären Connector nicht:

1. öffentlichen Maulwurf-X-Tunnel stoppen;
2. Gateway-Service stoppen/deaktivieren;
3. sekundären signed-ingress-Service stoppen/deaktivieren;
4. `maulwurf-x`-Secrets und Policy nur nach gesondertem Audit entfernen;
5. `require-tool-policy` nur dann entfernen, wenn ausdrücklich auf den
   Legacy-Modus zurückgerollt werden soll.

Ein Maulwurf-X-Ausfall darf weder `primary.token`, den OpenAI-Tunnel noch den
kanonischen Grabowski-Routing-Selector verändern.
