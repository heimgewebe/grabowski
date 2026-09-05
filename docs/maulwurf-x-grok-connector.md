# Maulwurf X: Grok als begrenzter Grabowski-Client

## Ziel

`Maulwurf X` ist **kein zweiter Grabowski**. Grok benutzt dieselbe kanonische
Grabowski-Runtime, erhält aber einen eigenen Principal, getrennte Secrets und
eine serverseitig erzwungene Least-Privilege-Toolpolicy.

```text
Grok / Grok Custom Connector
  -> public HTTPS
  -> wg-prod-1 Tailscale Funnel :10000
  -> 127.0.0.1:18091 public bridge
       transparent TCP only; no credentials or MCP policy
  -> TLS to heim-pc.tail6dbb90.ts.net:10000
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

### 4. Public Bridge auf wg-prod-1

Der Bridge-Layer ist absichtlich **keine** weitere Security-Authority. Er kennt
weder HTTP-Header noch MCP-Methoden, Toolnamen oder Credentials. Er transportiert
nur Bytes von seinem Loopback-Listener zu einem TLS-verifizierten heim-pc-Funnel.
Insbesondere liegen auf wg-prod-1 keine Maulwurf-X-Tokenbytes.

Die kanonischen Artefakte sind:

- `tools/grabowski_maulwurf_x_public_bridge.py`;
- `systemd/maulwurf-x-public-bridge.service.example`;
- `tools/install_maulwurf_x_public_bridge.py`.

Der Bridge-Prozess löst `heim-pc.tail6dbb90.ts.net` normal auf und pinnt keine
Tailnet-IP. TLS wird mit dem System-Truststore und genau diesem Servernamen
verifiziert. Verbindungen haben einen begrenzten Connect-Timeout, einen
verbindungsweiten Idle-Timeout, eine Half-Close-Frist, begrenzte Stream-Puffer
und eine globale Parallelitätsgrenze. Der systemd-Dienst begrenzt zusätzlich
Dateideskriptoren, Tasks und Speicher.

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

### Initiale Produktionsoberfläche

Der erste produktive Cutover ist absichtlich **Status-Plane-only**. Allgemeine
Inhaltsleser wie `grabowski_git_show`, `grabowski_git_diff`, `grabowski_context`
oder freie RepoGround-Abfragen sind nicht freigegeben, obwohl sie technisch
read-only sind. Ohne argumentgebundene Repo-/Pfadregeln könnten solche Werkzeuge
einem externen Modell mehr lokale oder private Inhalte zeigen als für den
Connector nötig. Erweiterungen der Oberfläche erfolgen deshalb erst als eigener,
reviewter Policy-Schritt mit engeren Argumentgrenzen statt durch bloßes Ergänzen
von Toolnamen.

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
8. Erst nach lokalem Negativ-/Positivtest den öffentlichen HTTPS-Pfad auf
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

## Öffentlicher HTTPS-Pfad

### Bevorzugte Architektur

Wenn der direkte Funnel auf heim-pc von **öffentlichen Tailscale-Funnel-
Ingress-Nodes** zuverlässig TLS und MCP transportiert, ist der kürzere Pfad
bevorzugt:

```text
Internet -> heim-pc Funnel :10000 -> 127.0.0.1:18184
```

Er erzeugt weniger Komponenten und damit weniger Betriebsfläche.

### Kanonischer Fallback

Wenn der direkte heim-pc-Funnel extern TLS-EOF-Fehler zeigt, obwohl er innerhalb
des Tailnets funktioniert, wird der belegbar funktionierende wg-prod-1-Pfad
verwendet:

```text
Internet
  -> https://wg-prod-1.tail6dbb90.ts.net:10000/mcp
  -> Tailscale Funnel :10000
  -> http://127.0.0.1:18091
  -> maulwurf-x-public-bridge.service
  -> TLS https://heim-pc.tail6dbb90.ts.net:10000
  -> heim-pc Funnel :10000
  -> http://127.0.0.1:18184/mcp
```

Port `8443` auf wg-prod-1 gehört einem anderen Funnel und wird von diesem Vertrag
**nicht** verändert. Auch der Installer verändert keinerlei Tailscale
Serve-/Funnel-Konfiguration. Die Funnel-Konfiguration wird separat und immer nach
frischem vollständigem `tailscale serve status` verwaltet.

### Installation auf wg-prod-1

Die drei versionierten Artefakte werden commitgebunden auf wg-prod-1 in einen
temporären, nicht geheimen Staging-Pfad übertragen. Dort wird ausgeführt:

```text
python3 tools/install_maulwurf_x_public_bridge.py --source-root <staging-root> --activate
```

Der Installer schreibt deterministisch nach:

- `~/.local/libexec/grabowski/grabowski_maulwurf_x_public_bridge.py`;
- `~/.config/systemd/user/maulwurf-x-public-bridge.service`.

Er ist idempotent, benötigt kein `sudo`, erzeugt keine Credentials, führt keine
Secret-Transformation aus und gibt nur Pfade, Hashes und systemd-Readback aus.
Für Logout-Festigkeit muss für den Benutzer bereits systemd-Linger aktiviert
sein; Linger ist eine Hostvoraussetzung und wird nicht vom Installer verändert.

## Grok-Auth

Der vorhandene `tunnel-client-grabowski` ist OpenAI-spezifisch und wird für
Maulwurf X nicht wiederverwendet. Das Gateway unterstützt als schmalen Vertrag
Bearer-Header und `X-API-Key`. An Grok geht ausschließlich das **externe**
Maulwurf-X-Credential. Das interne
`transport-connectors/maulwurf-x.token` verlässt heim-pc nie.

Die konkrete Authentisierungsart wird gegen die jeweils aktuelle Grok-Connector-
Oberfläche abgenommen. OAuth wird **nicht vorsorglich** gebaut. Falls die reale
Grok-App ausschließlich OAuth akzeptiert, ist das ein separater Adapter-Slice an
der äußeren Gateway-Grenze; interne Grabowski-Identität und Toolpolicy bleiben
unverändert.

## Restart- und Recovery-Abnahme

Vor Consumer-Cutover werden mindestens folgende Punkte frisch geprüft:

1. `maulwurf-x-public-bridge.service` ist loaded, enabled, active und ohne
   unerklärte Restarts;
2. Service-Restart führt wieder zu genau einem Listener auf `127.0.0.1:18091`;
3. systemd-Linger für den Benutzer ist aktiv;
4. keine manuell gestartete oder verwaiste Bridge-Instanz existiert;
5. wg-prod-1 Funnel `:10000` zeigt auf `http://127.0.0.1:18091`, während
   bestehende andere Funnel unverändert bleiben;
6. heim-pc Gateway und signed ingress laufen auf `18184` bzw. `18183`;
7. öffentliches `/mcp` ohne Credential liefert `401` bei gültiger TLS-Prüfung;
8. authentifiziertes MCP `initialize` und `tools/list` funktionieren;
9. `tools/list` enthält exakt die Maulwurf-X-Allowlist;
10. ein nicht erlaubtes Tool bleibt serverseitig verweigert;
11. nach Restart des Maulwurf-X-Gateways ist derselbe öffentliche E2E-Pfad
    wieder funktionsfähig.

Ein Host-Reboot wird nur ausgeführt, wenn dadurch keine fremde aktive Arbeit
gefährdet wird. Andernfalls bleibt der reale Reboot-Nachweis eine explizit
registrierte Restobligation; Service-Restart, Linger und Boot-Enable werden
bereits vorher geprüft.

## Abnahme

Positive Beweise:

- Gateway ohne Secret-Ausgabe gesund;
- signed ingress gesund und an denselben Runtime-Routing-Selector gebunden;
- `tools/list` enthält exakt die Maulwurf-X-Allowlist;
- `grabowski_runtime_health` funktioniert über Maulwurf X;
- Operator löst den Principal als `maulwurf-x` auf;
- Neustart aller Maulwurf-X-Dienste erhält die Funktion;
- primärer ChatGPT-Connector bleibt unverändert funktionsfähig;
- finaler Grok-Custom-Connector beobachtet den zu diesem Zeitpunkt real
  deployten Grabowski-Head.

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

## Rollback

Der Rollback ist schichtweise und beschädigt den primären Connector nicht:

1. öffentlichen Maulwurf-X-Funnel auf dem betroffenen Host deaktivieren bzw. auf
   den zuvor frisch gelesenen Zustand zurücksetzen;
2. `maulwurf-x-public-bridge.service` auf wg-prod-1 stoppen/deaktivieren;
3. Gateway-Service auf heim-pc stoppen/deaktivieren;
4. sekundären signed-ingress-Service stoppen/deaktivieren;
5. `maulwurf-x`-Secrets und Policy nur nach gesondertem Audit entfernen;
6. `require-tool-policy` nur dann entfernen, wenn ausdrücklich auf den
   Legacy-Modus zurückgerollt werden soll.

Ein Maulwurf-X-Ausfall darf weder `primary.token`, den OpenAI-Tunnel noch den
kanonischen Grabowski-Routing-Selector verändern.
