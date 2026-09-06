# maulwurf x: Grok als begrenzter Grabowski-Client

## Ziel

`maulwurf x` ist **kein zweiter Grabowski**. Grok benutzt dieselbe kanonische
Grabowski-Runtime, erhält aber einen eigenen Principal, getrennte Secrets und
eine serverseitig erzwungene Least-Privilege-Toolpolicy.

Der kanonische Produktionspfad ist genau:

```text
Grok / Grok Custom Connector
  -> https://wg-prod-1.tail6dbb90.ts.net:10000/mcp
  -> wg-prod-1 Tailscale Funnel :10000
  -> http://127.0.0.1:18091
  -> maulwurf-x-public-bridge.service
       transparent TCP only; no HTTP rewrite, credentials or MCP policy
  -> TLS to heim-pc.tail6dbb90.ts.net:10000
  -> heim-pc Funnel :10000
  -> http://127.0.0.1:18184/mcp
  -> grabowski-external-connector-maulwurf-x
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
- projiziert bei `tools/list` nur die für `maulwurf-x` erlaubten internen Tools
  plus den explizit freigegebenen gateway-lokalen Proposal-Sink;
- verweigert nicht erlaubte `tools/call` bereits vor dem Upstream;
- verarbeitet `maulwurfx_propose_finding` lokal als privaten, create-only,
  inhaltsadressierten Finding-Record und leitet diesen Call nie an den Operator weiter;
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

Für `maulwurf-x` gilt zusätzlich `read_only_only: true`. Das betrifft die an den
Operator weitergereichten internen Tools: Selbst ein versehentlich in deren Allowlist
aufgenommenes Tool wird verweigert, wenn seine aktuelle MCP-Annotation nicht
**explizit** `readOnlyHint=true` ist. Der gateway-lokale
`maulwurfx_propose_finding` ist davon getrennt: Er erzeugt ausschließlich einen
privaten Proposal-Record und besitzt keine Operator-, Bureau-, Repo-, Deploy- oder
Ausführungsautorität.

Dadurch bestehen drei getrennte Schranken:

1. **Projection Gate:** Grok sieht nur die freigegebene Oberfläche.
2. **Authority Gate:** Grabowski führt nur die internen Allowlist-Tools aus und prüft
   zusätzlich deren Read-only-Semantik.
3. **Proposal Sink:** Der einzige Schreibpfad endet gateway-lokal in einem
   create-only Finding-Record; eine spätere Prüfung oder Übernahme ist ein eigener
   Autoritätsschritt.

### 4. Public Bridge auf wg-prod-1

Der Bridge-Layer ist absichtlich **keine** weitere Security-Authority. Er kennt
weder HTTP-Header noch MCP-Methoden, Toolnamen oder Credentials. Er transportiert
nur Bytes von seinem Loopback-Listener zu einem TLS-verifizierten heim-pc-Funnel.
Insbesondere liegen auf wg-prod-1 keine Maulwurf-X-Tokenbytes.

Der Loopback-Listenvertrag ist nicht nur ein Default: die Bridge verweigert
jeden `--listen-host` außer `127.0.0.1` und `::1`. Damit kann die CLI den
Funnel-vorgelagerten Trust-Contract nicht still auf `0.0.0.0` aufweiten.

Die kanonischen Artefakte sind:

- `tools/grabowski_maulwurf_x_public_bridge.py`;
- `systemd/maulwurf-x-public-bridge.service.example`;
- `tools/install_maulwurf_x_public_bridge.py`.

Der Bridge-Prozess löst `heim-pc.tail6dbb90.ts.net` normal auf und pinnt keine
Tailnet-IP. TLS wird mit dem System-Truststore und genau diesem Servernamen
verifiziert. Verbindungen haben einen begrenzten Connect-Timeout, einen
verbindungsweiten Idle-Timeout, eine Half-Close-**Idle**-Frist, begrenzte
Stream-Puffer und eine globale Parallelitätsgrenze. Die Half-Close-Frist ist
keine maximale Antwortdauer: solange die verbleibende Richtung Bytes liefert,
wird sie durch Aktivität verlängert. Erst eine nach dem ersten EOF stillstehende
Gegenrichtung wird beendet.

Bei ausgelasteter Parallelitätsgrenze wird die gerade akzeptierte TCP-Verbindung
ohne Userspace-Warteschlange geschlossen. Die Bridge erzeugt dabei bewusst keine
HTTP-Antwort. Das ist Teil des transparenten Byte-Relay-Vertrags.

HTTP wird nirgends in der Bridge geparst oder umgeschrieben. Insbesondere müssen
`Host: wg-prod-1.tail6dbb90.ts.net:10000` und der externe Auth-Header bytegleich
bis zum heim-pc-Gateway gelangen. Ob der öffentliche `Host` entlang des realen
Funnel-Pfads akzeptiert wird, ist deshalb ein expliziter E2E-Abnahmepunkt und
kein impliziter Rewrite.

Der systemd-Dienst begrenzt zusätzlich Dateideskriptoren, Tasks und Speicher.
`ProtectHome=read-only` wird mit `PYTHONDONTWRITEBYTECODE=1` kombiniert, damit
CPython im geschützten Installationspfad keine `__pycache__`-Schreibversuche
benötigt.

## Policy-Contract

Beispiel:

```json
{
  "schema_version": 2,
  "connector_id": "maulwurf-x",
  "mode": "allowlist",
  "read_only_only": true,
  "allowed_tools": ["grabowski_status"],
  "gateway_tools": ["maulwurfx_propose_finding"]
}
```

Schema v1 bleibt für bestehende transport-only Policies lesbar. Schema v2 ergänzt
`gateway_tools`; dort sind nur serverseitig fest definierte Gateway-Tools zulässig.
`mode=unrestricted` ist für bestehende vertrauenswürdige Principals als
Migrationsmodus vorgesehen; `allowed_tools` muss dann leer sein und Gateway-Tools
sind in diesem Modus nicht zulässig.

Die Repository-Vorlage für `maulwurf x` liegt unter
`config/maulwurf-x-tools.json`. Ein Test bindet ihre Einträge an den publizierten
Runtime-Toolvertrag und an den Capability-Katalog mit `read_only=true`.

### Produktionsoberfläche

Die produktive Oberfläche bleibt absichtlich **Status-Plane plus genau ein
Proposal-Sink**. Allgemeine Inhaltsleser wie `grabowski_git_show`,
`grabowski_git_diff`, `grabowski_context` oder freie RepoGround-Abfragen sind nicht
freigegeben, obwohl sie technisch read-only sind. Ohne argumentgebundene
Repo-/Pfadregeln könnten solche Werkzeuge einem externen Modell mehr lokale oder
private Inhalte zeigen als für den Connector nötig.

`maulwurfx_propose_finding` ist die einzige Ausnahme vom reinen Lesen. Der Call
wird nicht an Grabowski/Bureau weitergereicht. Das Gateway normalisiert und
begrenzt die Felder, bindet den Record an die aktuell vollständig deployte
`release_id`/`repo_head`-Identität und bildet daraus eine inhaltsadressierte ID.
Der Store ist privat (`0700`, Records und Lock `0600`), hart auf 256 Records
begrenzt und serialisiert konkurrierende Writer. Wiederholte identische Calls
liefern denselben Finding-Identifier und erzeugen keine zweite Datei. Der Receipt
behauptet ausdrücklich weder Finding-Korrektheit noch Bureau-Readiness, Claim,
Repo-Mutation, Deployment oder Ausführung.

Eine spätere Übernahme eines Findings in Bureau bleibt ein separater, reviewter
Intake-Schritt. Erweiterungen der Lese- oder Schreiboberfläche erfolgen ebenfalls
nur als eigener Policy-Schritt mit engeren Argumentgrenzen statt durch bloßes
Ergänzen von Toolnamen.

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
5. Den Finding-Store als leeres Verzeichnis
   `~/.local/state/grabowski/external-connectors/maulwurf-x-findings` mit Modus
   `0700` vorprovisionieren. Die Gateway-Unit verlangt dieses Verzeichnis und
   macht innerhalb von `ProtectHome=read-only` ausschließlich diesen Pfad
   schreibbar; das externe Credential bleibt damit nicht beschreibbar.
6. **Erst danach** `transport-connectors/require-tool-policy` mit exakt
   `required-v1` und Modus `0600` anlegen.
7. `grabowski-transport-ingress-maulwurf-x.service` **enable + start** und lokal prüfen.
8. `grabowski-external-connector-maulwurf-x.service` **enable + start** und lokal prüfen.
9. Auf wg-prod-1 die commitgebundene Public Bridge installieren/aktivieren und
   verifizieren, dass Funnel `:10000` weiterhin ausschließlich auf
   `http://127.0.0.1:18091` zeigt. Port `8443` bleibt unberührt.
10. Den öffentlichen Pfad mit dem realen öffentlichen Hostnamen positiv und
    negativ abnehmen.
11. Erst danach den Grok-Connector unter dem sichtbaren Namen **maulwurf x** anlegen.

### Upgrade von laufendem Policy-v1 auf Proposal-v2

Bei einer bereits laufenden `maulwurf-x`-Installation gilt eine andere,
ausfallarme Reihenfolge: **zuerst** den Finding-Store `0700` vorprovisionieren,
dann Code und Unit deployen, während die produktive Policy noch auf Schema v1
bleibt. Die neue Runtime akzeptiert v1 weiter und kann deshalb gefahrlos neu
starten. **Erst nach erfolgreichem Runtime-Readback** wird
`maulwurf-x.tools.json` CAS-gebunden auf Schema v2 umgestellt und nur das Gateway
neu gestartet. Damit kann weder die alte Gateway-Version mit einer unbekannten
v2-Policy kollidieren noch die neue Unit an ihrem verpflichtenden Finding-Verzeichnis
scheitern.

Der Marker wird absichtlich zuletzt gesetzt. Fehlt danach für irgendeinen
enrollten Principal die Policy oder ist sie ungültig, verweigert der Operator
dessen Calls statt auf globale `trusted-owner`-Rechte zurückzufallen.

Die Install-Targets bilden eine optionale, erst durch `enable` aktivierte
Startkette: der primäre signed ingress zieht den Maulwurf-X-Ingress, dieser das
Gateway. `PartOf` propagiert Stop/Restart nach unten. Damit bleiben normale
Grabowski-Deployments restartfest, ohne dass ein nicht provisioniertes `maulwurf x`
den primären Connector als Pflichtabhängigkeit belastet.

## Öffentlicher HTTPS-Pfad

### Kanonischer Produktionspfad

Für den aktuellen Produktionsvertrag gilt ausschließlich der am Anfang dieses
Dokuments gezeigte wg-prod-1-Pfad. Der kürzere direkte heim-pc-Funnel wurde
bewusst **nicht** kanonisiert, weil am realen öffentlichen Rand TLS-EOF-Fehler
beobachtet wurden. Eine spätere Vereinfachung auf direkten heim-pc-Ingress ist
ein eigener, neu zu beweisender Cutover und keine alternative Laufzeitwahrheit
dieses Vertrags.

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
Secret-Transformation aus und verändert Tailscale nicht. Vor `--activate` liest
er systemd-Linger aus und verweigert die Aktivierung fail-closed, wenn Linger
nicht aktiv ist. Nach Restart prüft er `LoadState`, `ActiveState`, `SubState`,
`UnitFileState`, `Result`, `MainPID` und insbesondere den exakten `FragmentPath`
der gerade installierten Unit. Die Unit selbst muss einen exakt gebundenen
`ExecStart` auf die installierte Bridge enthalten. Aktivierungsfehler werden als
secret-freie Operatorfehler klassifiziert statt stderr unkontrolliert in den
Ergebnisvertrag zu übernehmen.

## Grok-Auth

Der vorhandene `tunnel-client-grabowski` ist OpenAI-spezifisch und wird für
`maulwurf x` nicht wiederverwendet. Das Gateway unterstützt als schmalen Vertrag
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
2. der installierte `FragmentPath` und die Hashes von Bridge/Unit entsprechen
   exakt den gemergten Repository-Artefakten;
3. Service-Restart führt wieder zu genau einem Listener auf `127.0.0.1:18091`;
4. systemd-Linger für den Benutzer ist aktiv;
5. keine manuell gestartete oder verwaiste Bridge-Instanz existiert;
6. Namensauflösung von `heim-pc.tail6dbb90.ts.net` funktioniert unter den echten
   Address-Family-Beschränkungen der wg-prod-1-Unit. `AF_UNIX` wird nur ergänzt,
   falls dieser reale Test es verlangt;
7. wg-prod-1 Funnel `:10000` zeigt auf `http://127.0.0.1:18091`, während
   bestehende andere Funnel unverändert bleiben;
8. heim-pc Gateway und signed ingress laufen auf `18184` bzw. `18183`;
9. ein Request mit dem realen öffentlichen Host
   `wg-prod-1.tail6dbb90.ts.net:10000` erreicht den E2E-Pfad; die Bridge verändert
   `Host` und Auth-Header nicht;
10. öffentliches `/mcp` ohne Credential liefert `401` bei gültiger TLS-Prüfung;
11. authentifiziertes MCP `initialize` und `tools/list` funktionieren;
12. `tools/list` enthält exakt die interne Read-only-Allowlist plus
    `maulwurfx_propose_finding`;
13. ein nicht erlaubtes Tool bleibt serverseitig verweigert;
14. ein Finding-Call erzeugt genau einen privaten, runtime-gebundenen Proposal-Record
    und ein identischer Wiederholungs-Call bleibt idempotent;
15. nach Restart des Maulwurf-X-Gateways ist derselbe öffentliche E2E-Pfad
    wieder funktionsfähig.

Ein Service-Restart beweist Wiederanlauf, **nicht** Sitzungsfortsetzung: aktive
TCP-/MCP-Verbindungen dürfen beim Restart abgeschnitten werden und müssen vom
Consumer neu aufgebaut werden. Graceful Session-Drain ist kein Bestandteil
dieses Bridge-Vertrags.

Ein Host-Reboot wird nur ausgeführt, wenn dadurch keine fremde aktive Arbeit
gefährdet wird. Andernfalls bleibt der reale Reboot-Nachweis eine explizit
registrierte Restobligation. Linger plus `WantedBy=default.target` plus echter
Service-Restart sind dann nur ein schwächeres Surrogat und werden nicht als
Reboot-Beweis bezeichnet.

## Abnahme

Positive Beweise:

- Gateway ohne Secret-Ausgabe gesund;
- signed ingress gesund und an denselben Runtime-Routing-Selector gebunden;
- `tools/list` enthält exakt die interne Read-only-Allowlist plus den einen
  Proposal-Sink `maulwurfx_propose_finding`;
- `grabowski_runtime_health` funktioniert über `maulwurf x`;
- ein Finding-Call liefert einen runtime-gebundenen create-only Receipt, ohne eine
  Bureau-Aufgabe oder sonstige Ausführung auszulösen;
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
- allowgelistetes internes Tool ohne explizites `readOnlyHint=true` -> Operator verweigert;
- Proposal mit Zusatzfeldern, ungültigen Kategorien, nicht-endlicher Unsicherheit
  oder falschem Principal -> Gateway verweigert;
- Proposal-Store mit unsicherer Datei-/Lock-Identität oder überschrittenem Limit ->
  Gateway verweigert fail closed;
- fehlende Principal-Policy bei aktivem Marker -> fail closed.

## Rollback

Der Rollback ist schichtweise und beschädigt den primären Connector nicht:

1. öffentlichen Maulwurf-X-Funnel auf wg-prod-1 deaktivieren bzw. auf den zuvor
   frisch gelesenen Zustand zurücksetzen;
2. `maulwurf-x-public-bridge.service` auf wg-prod-1 stoppen/deaktivieren;
3. Gateway-Service auf heim-pc stoppen/deaktivieren;
4. sekundären signed-ingress-Service stoppen/deaktivieren;
5. `maulwurf-x`-Secrets und Policy nur nach gesondertem Audit entfernen;
6. `require-tool-policy` nur dann entfernen, wenn ausdrücklich auf den
   Legacy-Modus zurückgerollt werden soll.

Ein Maulwurf-X-Ausfall darf weder `primary.token`, den OpenAI-Tunnel noch den
kanonischen Grabowski-Routing-Selector verändern.