# Browser Control Plane v1

## Zweck

Die Browser-Control-Plane hält die dauerhafte Browserautorität in Grabowski und trennt sie von einem einzelnen Browser, Transportprotokoll oder Vendor-MCP. Sie ergänzt den bestehenden Browser-Worker-Lifecycle, ersetzt ihn aber nicht.

Autoritativ bleiben:

- Grabowski für Intent und Effektklasse;
- die Grabowski-Worker-Registry für Session- und Outcome-Zustand;
- der Grabowski-Ressourcenstore für Port- und Profil-Leases;
- die Grabowski-Auditkette für begrenzte, nicht geheime Evidenz;
- `grabowski_browser_worker_status` für terminalisierenden Readback.

Die Control-Plane ist eine deterministische Projektion der bereits persistierten Worker-Felder. Sie führt **keine zweite Zustandsdatenbank** und keine zweite Lifecycle-Wahrheit ein.

## Adaptergrenze

`browser_start()` validiert nach der bestehenden Executable-Allowlist zusätzlich, dass für das aufgelöste Executable ein implementierter Browseradapter existiert. Erst danach darf ein Profil oder Worker-State angelegt werden.

Aktuelle Adapterrollen:

| Browserfamilie | Adapter | Protokoll | Rolle |
| --- | --- | --- | --- |
| Google Chrome Stable | `chrome-cdp` | CDP | `canonical-operator` |
| Google Chrome Stable | `chrome-webdriver-bidi` | WebDriver BiDi | `qualified-pre-effect-fallback` |
| Brave | `chromium-cdp` | CDP | `fallback-test` |
| Chromium | `chromium-cdp` | CDP | `fallback-test` |
| Chrome for Testing | `chrome-cdp` | CDP | `reproducible-test` |

Chrome Stable über `chrome-cdp` ist weiterhin die kanonische allgemeine Operatorwahl. `chrome-webdriver-bidi` ist **kein zweiter Default und kein freier Routerkandidat**, sondern ausschließlich ein startup-only Standby: Innerhalb desselben noch privaten Startvorgangs muss CDP vor Rückgabe eines Worker-Endpunkts als nicht ready beobachtet, der Primärversuch terminalisiert sowie Portfreigabe und Endpunkt-Abwesenheit bestätigt werden. Brave bleibt ausdrücklich zulässig, wird aber nicht zur kanonischen Agentenbasis erklärt. Chrome for Testing ist eine reproduzierbare Testoption und kein Zwang für allgemeines Browsing.

Ein Executable ohne implementierten Browseradapter wird vor Profilerzeugung und Workerstart abgewiesen. Eine bloße Aufnahme in `GRABOWSKI_BROWSER_EXECUTABLES` erzeugt also keine neue Protokollunterstützung. Der BiDi-Standby ist zusätzlich auf Chrome Stable, einen vollständig privaten startup-only CDP-Primärversuch, ephemere Profile und ein explizit gebundenes lokales `chromedriver`-Executable beschränkt. Ein bestehender Worker wechselt niemals das Backend: Snapshot, Elementhandles und Adapter bleiben für die gesamte Workerlebensdauer fest gebunden.

## Kanonischer Operatorpfad

Für normale Agenten-Browserarbeit gilt ab jetzt als Default, sofern kein konkretes Task-Erfordernis dagegen spricht:

1. `grabowski_context(...)` lesen und den runtimegebundenen `browser_operator_contract` beachten.
2. Chrome Stable über `grabowski_browser_worker_start` normal als CDP-Primärworker starten. Grabowski besitzt Worker-, Profil- und Lease-Lifecycle.
3. Einen Chrome/BiDi-Standby nur **beim selben Startvorgang** armieren, indem zusätzlich `chromedriver_executable` angegeben wird. Grabowski startet weiterhin zuerst Chrome/CDP und gibt diesen Worker zurück, sobald sein CDP-Endpunkt intern ready ist. Nur wenn CDP vor Rückgabe irgendeines Worker-Endpunkts nicht ready wird, terminalisiert Grabowski diesen privaten Primärversuch und startet einen neuen BiDi-Worker auf demselben Port. Ein späterer Backendwechsel existiert nicht.
4. Standardmäßig ein separates ephemeres Profil verwenden; persistente Profile nur als explizite Auth-/Trust-Scopes. Der qualifizierte BiDi-Standby akzeptiert ausschließlich ein ephemeres Profil.
5. Den von Grabowski erzeugten CDP- bzw. WebDriver/BiDi-Endpunkt ausschließlich über `127.0.0.1` benutzen. ChromeDriver muss HTTP und BiDi-WebSocket auf demselben workergeleasten Port bereitstellen; Portdrift wird verworfen.
6. Semantisch abgedeckte Navigation und Aktionen über `grabowski_browser_worker_semantic` ausführen; nicht abgedeckte Browserfunktionen dürfen beim kanonischen Primärworker weiterhin den loopback-only CDP-Transport verwenden. Der BiDi-Standby erhält keine zusätzliche Raw-Transport-Surface. Vendor-MCPs sind nur optionale Adapter/Diagnostik und übernehmen keine Lifecycle-Autorität.
7. Outcome durch eine frische autoritative Browserbeobachtung prüfen. Insbesondere begründet weder ein CDP- noch ein BiDi-Command-ACK allein einen Navigationserfolg.
8. Den eigenen Worker terminalisieren und anschließend Profilentfernung sowie Port-/Profil-Leasefreigabe lesen.
9. Menschliche Browserprofile und den Desktop-Default nicht verändern; Brave bleibt menschlicher Default/Fallback.

Dieser Pfad bleibt im versionierten Runtime-Entrypoint-Contract als allgemeiner Default verankert. Der veröffentlichte Schema-2-Vertrag beschreibt ein partiell abdeckendes `semantic_gateway` mit `observe`/`act` für `read_state`, `navigate`, `scroll_into_view` und jetzt auch `activate`. Die interne Link-Aktivierung wurde zuvor getrennt implementiert und live deployt; diese Slice veröffentlicht ausschließlich den bereits gehärteten Intent im kanonischen Runtime-Contract. Der kanonische Runtime-Validator bleibt absichtlich rückwärtskompatibel und akzeptiert weiterhin sowohl die frühere Dreierliste als auch die aktuelle Viererliste, damit immutable ältere Releases cold-reentry-sicher lesbar bleiben. `activate` ist keine generische Klick-Autorität: Es akzeptiert ausschließlich ein opak snapshot-gebundenes Element mit der öffentlichen semantischen Rolle `link`. Bereits die Observation bindet einen privaten SHA-256 des adapterintern aufgelösten HTTP(S)-Linkziels in Snapshot und Elementhandle; CDP gewinnt diese Bindung aus DOM-Metadaten, der BiDi-Standby aus seinem isolierten DOM-Realm. Unmittelbar vor der Wirkung liest der jeweilige Adapter denselben intern gebundenen `<a>`-Knoten samt Ziel erneut und führt die Navigation erst bei Digestgleichheit aus. Die Abdeckung bleibt partiell, weil Console, Network, Screenshot und weitere Browserfunktionen nicht Teil dieses Vertrags sind. Navigation ist öffentlich backend-neutral. Der kanonische Chrome-Primäradapter setzt sie intern mit CDP `Page.navigate` um; ein explizit qualifizierter Chrome/BiDi-Standby setzt denselben Intent innerhalb seines **eigenen** Workers über WebDriver BiDi um. Es gibt keinen Backendwechsel innerhalb eines vorhandenen Snapshots und keinen Fallback nach `outcome_unknown`. Wegen dieser Netznavigation ist die Capability mindestens `risk_class=high` und veröffentlicht den Effekt `browser-network-navigation`. Das ist keine neue Netzwerkautorität: Der Browserworker besitzt bereits normale Browser-Netzreichweite; insbesondere private oder Loopback-Ziele werden durch den semantischen Pfad weder neu autorisiert noch pauschal verboten, sondern erben ausschließlich die bereits bestehende Browserautorität.

Ein zusätzlicher Praxistest am 12. August 2026 hat den kompletten Pfad erneut bestätigt: ein frischer Chrome-Stable-Worker öffnete `https://example.com/` direkt über CDP; `Page.loadEventFired` trat ein und `Runtime.evaluate` las `title=Example Domain`, `h1=Example Domain`, `readyState=complete` zurück. Danach wurden ephemeres Profil sowie Port-/Profil-Leases vollständig entfernt.

## Endpoint- und Transportvertrag

Der kanonische Browserworker bindet seinen Transport ausschließlich an Loopback. Für CDP gilt weiterhin:

- `--remote-debugging-address=127.0.0.1`
- serverseitig gewählter `--remote-debugging-port=<port>`
- serverseitig gewähltes `--user-data-dir=<profil>`

Für den qualifizierten Chrome/BiDi-Standby gilt stattdessen:

- ChromeDriver-HTTP ausschließlich auf `127.0.0.1:<worker-port>`;
- die sessiongebundene BiDi-WebSocket-URL muss auf **denselben** numerischen Loopback-Port und exakt dieselbe Session-ID zeigen;
- Chrome läuft mit einem frischen ephemeren `user-data-dir`;
- Session-ID und WebSocket-URL bleiben in einer privaten `0600`-Workerdatei und erscheinen weder in Public Worker Projection noch Audit.

Caller dürfen Profil- oder Debuggingbindungen weiterhin nicht über `args` überschreiben. Die semantische Projektion weist beide Transportformen als `loopback_only=true` aus. Das ist keine Erlaubnis, CDP, WebDriver HTTP oder BiDi über Tailscale, LAN, Funnel oder Internet zu exponieren.

## Profil- und Sessionvertrag

### Ephemere Profile

Ohne `persistent_profile` erzeugt Grabowski ein workergebundenes Profil unter seinem privaten Worker-State. Es ist Standard und wird bei erfolgreicher terminaler Reconciliation entfernt.

Die Control-Plane kennzeichnet es als:

- `mode=ephemeral`
- `scope_kind=worker-ephemeral`

### Persistente Profile

Ein persistentes Profil muss weiterhin:

1. explizit vom Caller angegeben sein;
2. absolut sein;
3. ein reguläres, nicht verlinktes Verzeichnis sein oder unter einem erlaubten Root neu angelegt werden;
4. innerhalb der konfigurierten `browser_profile_roots` liegen.

Der daraus resultierende kanonische Pfad ist die explizite Auth-/Trust-Scope-Identität. Die Control-Plane veröffentlicht dafür nur einen SHA-256-Identitätsdigest; sie liest oder exportiert keine Cookies, Passwörter, Tokens oder Browserdaten.

Jeder Browserworker least atomar:

- `port:<port>`
- `browser-profile:<kanonischer-profilpfad>`

Dadurch kann dasselbe persistente Profil nicht gleichzeitig von zwei Workern verwendet werden. Verschiedene persistente Profile bleiben parallel nutzbar. Terminalisierung gibt nur exakt worker-eigene Leases frei; fremde Ersatz-Leases werden nicht übernommen oder gelöscht.

## Öffentliche Projektion

Bestehende Workerfelder und History-Semantik bleiben erhalten. Browserworker erhalten zusätzlich `control_plane` mit:

- Autoritätsquellen für Control-Plane, Lease, Worker-State, Outcome-Readback und Audit;
- Session-Intent und Effektklasse;
- Adapter-ID, Protokoll, Implementierungsstatus und Fähigkeiten;
- Browserfamilie und Auswahlrolle;
- Loopback-Endpoint;
- Profilmodus und gehashte Profil-/Lease-Identität;
- aktuellen Outcome-Zustand;
- expliziten Nichtbehauptungen.

Diese Projektion wird aus dem bestehenden Record berechnet. Daher ist keine Migration von `workers.sqlite3` erforderlich und auch historische Browserworker bleiben lesbar.

## Audit

Browser-Start/Stop-Audit erhält eine begrenzte `browser_control_plane`-Zusammenfassung:

- Adapter und Protokoll;
- Browserfamilie und Auswahlrolle;
- Profilmodus;
- gehashte Profilidentität;
- Loopback-Eigenschaft.

Nicht in die neue Auditprojektion gelangen Profilpfad, Cookies, Credentials, Formwerte oder andere Browserinhalte. Bereits vorhandene öffentliche Workerfelder werden durch diesen Vertrag weder erweitert noch als Secret-Quelle umgedeutet.

## Diagnostics-only Core

Console- und Network-Diagnostik bleibt bewusst **außerhalb** des Semantic Browser API. Die tooling-only Slice `src/grabowski_browser_diagnostics.py` mit `tools/browser_diagnostics.py` akzeptiert ausschließlich die ID eines bereits laufenden Grabowski-Browserworkers; Caller können weder CDP-Port noch WebSocket-URL noch Profilpfad als Authority einspeisen. Vor und nach jedem Sample werden Worker-Registry, frische systemd-Beobachtung und die exakten worker-eigenen Port-/Profil-Leases erneut gebunden. Ein unbekannter, terminaler, leasefremder oder während des Samples driftender Worker endet fail-closed.

Der Collector verwendet CDP nur passiv: `Runtime.enable`, `Log.enable` und `Network.enable`. Er ruft weder `Page.navigate`/`Page.reload` noch `Runtime.evaluate`, DOM-/Input-Methoden, Request-/Response-Body-Leser oder Screenshot-Methoden auf. Die Target-Discovery erfolgt direkt per `node:http` an `127.0.0.1`, damit Host-Proxy- oder DNS-Konfiguration keinen Loopback-Read umleiten kann. Ein optionaler späterer DevTools-MCP-Adapter darf diese Grenze nicht erweitern und bleibt der Grabowski-Worker-/Lease-/Outcome-Autorität untergeordnet.

Ausgegeben werden nur hart begrenzte, doppelt normalisierte Metadaten:

- Console-Text und Argumentwerte ausschließlich als SHA-256 plus Byte-Länge und ungefährliche Typmetadaten;
- URL nur als Scheme, Host-/Path-Digest sowie `query_present`/`fragment_present`; Query- und Fragmentwerte selbst bleiben draußen;
- Network nur mit Request-ID-Digest, Methode, Resource-/Initiator-Typ, Status, MIME/Protokoll sowie Cache-/Service-Worker-Bools;
- keine Cookies, Credentials, `Authorization`-Werte, beliebigen Raw-Headers, Post-Daten oder Request-/Response-Bodies;
- höchstens 50 Events pro Stream und höchstens 16 Console-Argumente je Event.

Screenshot-Diagnostik ist in dieser Slice absichtlich `not_implemented`. Sie wird erst ergänzt, wenn ein eigener bounded Artifact-/Digest-Vertrag vorliegt; unbounded Bildbytes gelangen weder in die normale Textdiagnostik noch in das Semantic Gateway. Der Report setzt invariant `read_only=true`, `page_effects=false`, `production_adapter_changed=false` und `retry_authorized=false`. Damit ist die Diagnostics-Schicht ein Beobachtungsinstrument und keine zweite Browser-Control-Plane.

## StructuredToolProvider-Vertrag

`src/grabowski_browser_structured_tools.py` definiert die nächste Schicht **oberhalb** der Browseradapter, ohne bereits einen Router oder einen Provider-Executor einzuführen. Ein `StructuredToolProvider` ist in dieser Slice ausschließlich eine begrenzte Deklaration: stabile Provider-ID, kanonische HTTP(S)-Origins und explizite Operationen mit einer benannten Effect-Class. Provider-Callables, Tokens, Sessions, Browserworker, Fallbackketten und Defaults sind absichtlich kein Teil dieses Vertrags.

Die kleine `StructuredToolProviderRegistry` ist nur ein in-memory Contract-Container. Sie persistiert nichts und besitzt insbesondere keine zweite Lifecycle- oder Routing-Wahrheit. Auch wenn mehrere Provider registriert sind, gibt es keine `select`-/`route`-/`invoke`-/`execute`-Operation. Eligibility wird nur für eine **explizit vom Aufrufer benannte Provider-ID** berechnet. Damit erzeugt das bloße Vorhandensein eines Structured-Tools noch keine Bevorzugung gegenüber dem Semantic Browser API und keinen automatischen Fallback.

Effektsemantik wird nicht dupliziert. Jede Provider-Operation nennt lediglich eine `effect_class`; bei Registrierung und bei jedem späteren Assess wird diese Klasse frisch über einen injizierten oder lazy gebundenen Resolver gegen `BROWSER_EFFECT_CONTRACTS` validiert. Der Structured-Provider-Code kopiert weder die Effect-Klassen noch deren Retry-/Readback-Regeln in eine zweite Autorität. Unbekannte Klassen, fehlende Kataloge, unvollständige Contracts oder nicht konservative Ambiguitätsregeln enden fail-closed. Eine im Browserkatalog selbst auf `admission=fail_closed` stehende Klasse bleibt auch für Structured Tools ineligible.

Provider-Origins müssen bereits kanonisch sein (`https://example.com`, ohne Userinfo, Pfad, Query, Fragment oder ausgeschriebene Default-Ports). Ein Assess akzeptiert nur absolute HTTP(S)-Ziele innerhalb eines Provider-Origin-Scope. V1 lehnt Query und Fragment am **Ziel selbst** vollständig ab, statt potenziell sensible Parameter zu hashen oder zu projizieren; diese bewusst enge Grenze kann später nur mit einem eigenen opaken Target-Binding erweitert werden. Öffentliche Eligibility enthält vom Ziel ausschließlich SHA-256-Bindungen für Target, Origin und Path.

`normalize_receipt(...)` führt ebenfalls keinen Provider aus. Es nimmt ein bereits caller-seitig erzeugtes Receipt entgegen und verlangt exakte Bindung an Provider-ID, Operation, Effect-Class, den **frisch gelesenen Effect-Contract-Digest** und den Target-Digest. Providerfremde Zusatzfelder wie Header, Body oder Credentials werden nicht in den Outcome übernommen. Der normalisierte Outcome nutzt die bestehende Effekt-/Readback-Semantik (`effect_state`, `authoritative_readback_required`) und setzt invariant `retry_authorized=false`, `readback_grants_retry_authority=false`, `normalizer_execution_performed=false` und `automatic_route_selected=false`. Ein Provider-Receipt ist dadurch gebunden und begrenzt, aber nicht automatisch authentifiziert oder fachlich wahr.

Die CLI `tools/browser_structured_tools.py` dient nur dem Offline-Validieren/Assess/Normalisieren dieser Contracts. Sie kann weder einen Provider aufrufen noch eine Route wählen. Eine echte Site-/API-Provider-Implementierung, öffentliche MCP-/Grip-Exposition und ein Router bleiben separate spätere Arbeiten. Ein Router ist erst sinnvoll, wenn mindestens zwei **reale, revisionsgebunden abgenommene Backends** existieren; dieser reine Contract zählt nicht als Backend-Promotion.

### Erster realer Backend-Slice: `github.public-rest`

`src/grabowski_browser_structured_provider_github.py` implementiert den ersten realen StructuredToolProvider **oberhalb** dieses Vertrags. Der Provider ist fest als `github.public-rest` gebunden, besitzt genau die Operation `repository.read` mit der bereits autoritativen Effect-Class `read` und akzeptiert ausschließlich kanonische Ziele der Form `https://api.github.com/repos/<owner>/<repo>`. Die Providerwahl ist damit weiterhin explizit: dieses Modul kann weder andere Provider auswählen noch ranken, routen oder als Fallback aufrufen.

Der Backend-Effekt ist absichtlich minimal. Ein erfolgreicher Aufruf führt genau einen anonymen HTTPS-GET an den festen Host `api.github.com` aus. Caller können weder Token, Cookie, `Authorization`, beliebige Header, Browserprofil noch Sessionidentität einspeisen. Der Transport verwendet nur feste, nicht geheime `Accept`-/`User-Agent`-Header, folgt keinen Redirects, hat ein festes Timeout und liest höchstens 128 KiB. Query, Fragment, Userinfo, alternative Origins, nicht-kanonische Default-Ports, zusätzliche Pfadsegmente, Traversal- und Encodingformen enden vor Provider-I/O fail-closed.

Eine 200-JSON-Antwort wird nicht roh weitergereicht. Die öffentliche Providerprojektion enthält nur eine kleine typisierte Repository-Metadatenmenge (`full_name`, Owner-/Repo-Name, Default-Branch, Visibility, vier Zustands-Bools und `open_issues_count`) sowie Response-/Projektionsdigests. Unselektierte Felder, beliebige Response-Header und Raw-Body bleiben außerhalb des Ergebnisses. HTTP-, Größen-, Content-Type-, JSON-, Schema-, Target- oder Transportfehler autorisieren keinen Retry.

Jeder Provider-Receipt bindet Provider-ID, Operation, den frisch gelesenen `read`-Effect-Contract-Digest und den bestehenden Target-Digest und läuft anschließend durch denselben `StructuredToolProviderRegistry.normalize_receipt(...)`-Pfad. Damit bleiben `normalizer_execution_performed=false`, `automatic_route_selected=false`, `retry_authorized=false`, `authoritative_readback_required=true` und `readback_grants_retry_authority=false` Eigentum des vorhandenen Vertrags. Der Provider führt keine zweite Effect-, Lifecycle-, Session- oder Retry-Autorität ein.

Diese Slice ist bewusst **Backend 1**. Sie veröffentlicht keinen neuen MCP-/Grip-Namen, ändert keinen Default und promotet keinen Router. Erst wenn mindestens ein zweites reales, revisionsgebunden abgenommenes Backend existiert, darf eine separate Arbeit überhaupt Routing-/Ranking-/Fallback-Policy evaluieren.

### Zweiter realer Backend-Slice: `github.public-web`

`src/grabowski_browser_structured_provider_github_web.py` implementiert genau einen zweiten realen StructuredToolProvider. Er ist fest als `github.public-web` an `https://github.com` gebunden und besitzt ausschließlich `repository.read` mit der bereits autoritativen Effect-Class `read`. Der Aufrufer muss diesen Provider ausdrücklich benennen; das Vorhandensein von nun zwei realen Backends erzeugt weiterhin weder Auswahl, Ranking, Routing, Fallback, Default noch Promotion.

Der Transport akzeptiert ausschließlich die exakte kanonische Form `https://github.com/<owner>/<repo>`. Query, Fragment, Userinfo, alternative Origins, nicht-kanonische Default-Ports, zusätzliche oder leere Pfadsegmente sowie Traversal- und Encodingformen scheitern vor I/O. Ein zulässiger Aufruf führt genau einen anonymen direkten HTTPS-GET an `github.com` mit festem Timeout und ausschließlich provider-eigenen `Accept`-/`User-Agent`-Headern aus. Es gibt keine Token-, Cookie-, `Authorization`-, Caller-Header-, Browserprofil- oder Sessioneingabe und keine Redirect-Folgeautorität.

Vom HTML wird höchstens ein fester früher Prefix von 256 KiB gelesen. Ein erfolgreicher Read verlangt HTTP 200 und `text/html`. Der stdlib-`HTMLParser` führt kein Skript aus und extrahiert ausschließlich die zwei festen öffentlichen GitHub-Metafelder für Repository-Identität und Public-Status. Raw-HTML, Scripts, beliebige Attribute oder Response-Header werden nicht projiziert. Ausgegeben wird nur die begrenzte Identität (`full_name`, Owner-/Repo-Name, `visibility=public`, `private=false`) plus Response-/Projektionsdigests. Fehlende, doppelte, widersprüchliche, nicht öffentliche oder targetfremde Metadaten enden fail-closed.

Receipt und Outcome laufen durch denselben `StructuredToolProviderRegistry.assess(...)`-/`normalize_receipt(...)`-Pfad wie Backend 1. Damit binden sie Provider-ID, Operation, den frisch gelesenen `read`-Effect-Contract-Digest und den kanonischen Target-Digest. Invariant bleiben `automatic_route_selected=false`, `retry_authorized=false`, `authoritative_readback_required=true` und `readback_grants_retry_authority=false`; insbesondere erzeugt weder ein HTTP-/Parserfehler noch ein unbekannter Transportausgang Retry-Autorität.

Backend 2 erfüllt damit die Voraussetzung „mindestens zwei reale, revisionsgebunden abgenommene Backends“ erst nach seinem eigenen Merge und Live-Readback. Daraus folgt ausdrücklich noch keine Routerfreigabe. Eine Routing-/Ranking-/Fallback-Policy bleibt eine separate, später zu begründende Arbeit.

## Semantischer Aktionsvertrag (observe → snapshot → act → verify)

Zusätzlich zur bestehenden Control-Plane-Projektion und zum bestehenden `grabowski_browser_worker_stored_form_action` stellt `src/grabowski_workers.py` die backend-neutrale Vertragsschicht `browser_semantic_observe()` und `browser_semantic_act()` bereit. Genau ein öffentliches Gateway, `grabowski_browser_worker_semantic`, macht sie mit den benannten Operationen `observe` und `act` agentenseitig nutzbar. Die historische interne Basisklasse `CDPAdapter` ist trotz ihres Namens die private Semantic-Adaptergrenze: `ChromeCDPAdapter` implementiert den kanonischen Primärpfad, `ChromeWebDriverBidiAdapter` ausschließlich den qualifizierten Chrome-Standby. Weder CDP-/BiDi-Methodennamen noch CSS-Selektoren oder interne DOM-/AX-/BiDi-Knotenidentitäten werden Teil des semantischen Aufrufervertrags.

Das bestehende `grabowski_operation_*`-Gateway ist dafür absichtlich nicht wiederverwendet: Es modelliert konfigurationsgetriebene argv-Rezepte mit Stringparametern, `terminal_execute`-Autorität und command-abhängigem Rollback. Snapshot-/Elementhandles und browserinterne TOCTOU-Revalidierung dort einzubauen würde Terminal- und Browserautorität vermischen. Das einzelne Browser-Gateway verhindert zugleich eine Tool-pro-Intent-Explosion.

### Stabile Publikation über die bestehende Grip-Surface

Ein Connector kann einen neuen MCP-Toolnamen später sehen als die bereits deployte Grabowski-Runtime. Dafür existieren nun zwei **Publikationsadapter innerhalb der schon stabilen `grip_run`-Surface**: `browser-semantic-observe` und `browser-semantic-act`. Sie sind keine zweite Browser-API. Beide importieren den Browsercode erst beim Aufruf und delegieren unmittelbar an dieselbe Funktion `browser_semantic_gateway()`. `browser-semantic-observe` fixiert die Operation auf `observe` und bleibt als Grip read-only; `browser-semantic-act` fixiert die Operation auf `act` und bleibt als Grip mutating.

Der Adapter führt keine eigene Effektklassifikation ein. Insbesondere kann der Aufrufer kein `effect_class` übergeben; unbekannte Adapterfelder werden vor der Delegation abgewiesen. Für `navigate` darf er zusätzlich genau ein `navigation_target` an das kanonische Gateway weiterreichen. Snapshot-, Element-, Zielvalidierungs-, TOCTOU-, Audit-, Outcome- und Retry-Semantik bleiben vollständig Eigentum des kanonischen Browser-Gateways. Die GripSpec bindet beide Publikationsadapter an die Capability `browser_worker`; der generische `grip_run`-Dispatcher erzwingt die Capability pro Grip statt pauschal `terminal_execute`. So bleiben browserfähige Least-Privilege-Profile nutzbar, ohne Terminalautorität zu erhalten. `browser-semantic-act` bleibt zusätzlich mutating und am bestehenden Transport-Roundtrip-Gate. Damit kann ein bereits veröffentlichter `grip_run` einen neuen semantischen Browservertrag konsumieren, ohne einen neuen Plattform-Toolnamen abzuwarten, ohne CDP nach außen zu spiegeln und ohne einen zweiten Lifecycle- oder Browservertrag zu schaffen. Der direkte Toolname `grabowski_browser_worker_semantic` bleibt der kanonische MCP-Einstieg, sobald der jeweilige Connector-Katalog ihn tatsächlich publiziert.

Die Vertragskonzepte:

- **Interne BrowserObservation**: Ergebnis von `browser_semantic_observe()`. Sie enthält für Härtung und Adapterauflösung weiterhin den begrenzten Origin-/Titel-/Semantik-Fingerprint. CDP gewinnt die Rolle aus der Accessibility-Projektion und verwendet den begrenzten AX-Namen als Primärquelle. Nur bei leerem AX-Namen darf ein side-effect-freier, fail-closed Fallback Beschriftungsattribute aus `DOM.describeNode` und für die ausdrücklich zugelassenen Labelrollen gerenderten sichtbaren Text aus einem privaten `DOMSnapshot` ableiten. Formular-/Value-Subtrees, effektives `contenteditable`, versteckte, geclippte oder transparente Textpfade sowie malformed/mehrdeutige Snapshotdaten werden dabei ausgeschlossen. SVG-Text bleibt ohne einen eigenen SVG-Paint-Nachweis vollständig aus diesem Fallback ausgeschlossen; der private Snapshot selbst wird nicht projiziert. Der BiDi-Standby bildet dieselbe begrenzte öffentliche Rollen-/Namensprojektion aus DOM-/ARIA-Semantik. Weder Formwerte noch AX-`value`, HTML, Selektoren, Backend-Knoten-IDs, Frame-/Loader-IDs, Cookies oder Credentials werden ausgegeben.
- **Öffentliche SemanticObservation**: unmittelbare Projektion des Gateways. Sie enthält `worker_id`, opaken `snapshot_id`, `observed_at_unix`, `ready_state` sowie höchstens 80 Elemente mit opakem `element_id`, auf 64 Zeichen begrenzter semantischer `role` und dem bereits intern auf 160 Zeichen begrenzten semantischen `name`. Origin, URL, Titel, rohe Selektoren und interne DOM-/AX-Knoten-IDs bleiben draußen.
- **snapshot_id**: unveränderlich und opak (`bsid2_<hex>`). Er wird mit HMAC-SHA-256 über `worker_id`, Origin/Ladezustand/Titel, internen Frame-/Loader-/Navigation-History-Bezug und die begrenzte semantische Elementprojektion einschließlich ihrer nur intern gehaltenen Backend-Knotenidentitäten sowie bei aktivierbaren Links des privaten Ziel-Digests gebildet. Der HMAC-Schlüssel ist ein zufälliger 32-Byte-Schlüssel pro Browserworker. Dadurch ändert nicht nur Navigation oder Reload, sondern auch relevante semantische DOM-/ARIA-/Accessibility-Drift den Snapshot; ohne den privaten Worker-Schlüssel lässt sich kein gültiger Snapshot-Handle offline konstruieren.
- **element_id**: opaker, deterministischer Handle (`beid1_<hex>`), ebenfalls HMAC-SHA-256-gebunden an den privaten Worker-Schlüssel, `worker_id`, den exakten `snapshot_id` und den internen Elementfingerprint. Bei einem aktivierbaren Link gehört der private SHA-256 des aufgelösten HTTP(S)-Ziels zu diesem Fingerprint; der Digest selbst wird nicht öffentlich projiziert. Ein Handle aus einem anderen Worker oder Snapshot kann weder neu hergeleitet noch auf einen rohen Selektor zurückfallen und wird nicht als Ziel akzeptiert.
- **Handle-Schlüssel**: wird beim Start jedes Browserworkers zufällig erzeugt und ausschließlich als private Datei `.semantic-handle-key` mit Modus `0600` im Worker-Instanzverzeichnis gespeichert. Er erscheint nicht in BrowserObservation, Workerprojektion, Audit oder Git und wird bei jeder terminalen Browser-Cleanup-Passage explizit entfernt, während das nicht geheime Worker-Manifest im Instanzverzeichnis als Evidenz erhalten bleiben darf. Die Entfernung löscht ausschließlich den festen Key-Pfad und folgt einem dort ersetzten Symlink nicht. Dieselbe terminale Cleanup-Passage entfernt best-effort zurückgebliebene reguläre, private `.browser-semantic-<token>.json`-/`.mjs`-Dateien; passende Symlinks werden weder verfolgt noch gelöscht.
- **Upgrade-Grenze**: Browserworker, die bereits vor Einführung dieses Schlüsselvertrags gestartet wurden, besitzen keinen Handle-Schlüssel. Der semantische Pfad erzeugt für sie keinen Schlüssel nachträglich und führt keinen Transport aus, sondern scheitert explizit und fail-closed mit der Anweisung, einen frischen Browserworker zu starten. Damit entsteht durch ein Runtime-Upgrade keine neue versteckte Identitätsmutation in einem bereits laufenden Worker.
- **BrowserIntent**: abstrakte Aktionsart aus dem systemeigenen `BROWSER_ACTION_CATALOG` (`read_state`, `navigate`, `scroll_into_view`, `activate`). Effektklasse sowie Element- oder Navigationszielbedarf kommen ausschließlich aus diesem Katalog; der Aufrufer liefert keine Effektklasse. `activate` ist nach dem getrennt deployten rückwärtskompatiblen Validator nun Teil des kanonisch publizierten Runtime-/Operatorvertrags.
- **Navigationsziel**: `navigate` verlangt genau ein absolutes HTTP(S)-Ziel von begrenzter Größe. Whitespace/Kontrollzeichen, Backslashes, Userinfo, fehlender Host, fremde Schemes und ungültige Ports werden vor Workerzugriff, Intent-Audit und Effekt abgewiesen. Das Ziel wird weder in BrowserOutcome noch Audit oder Effect-Receipt im Klartext zurückgegeben. Stattdessen bindet ein worker-keyed HMAC-SHA-256-Zieldigest Intent- und Outcome-Audit an dasselbe Ziel; der private Worker-HMAC-Schlüssel bleibt geheim.
- **BrowserAction**: Intent, gebunden an `worker_id`, `snapshot_id` und bei elementbezogenen Aktionen an `element_id`. `scroll_into_view` und `activate` akzeptieren keinen CSS-Selektor; `navigate` akzeptiert keine Browser-Backend- oder CDP-Parameter. `activate` ist zusätzlich auf die serverseitig gebundene Rolle `link` beschränkt.
- **BrowserOutcome**: enthält `ok`, `result_code`, `effect_state`, angeforderten Snapshot-/Elementhandle, die tatsächlich beobachtete Pre-/Post-Snapshot-ID und eine frische, öffentlich redigierte `observation`.

Effektvokabular (`BROWSER_EFFECT_CONTRACTS`): `read`, `local_ui`, `network_navigation`, `reversible_external`, `external_mutation`, `high_impact`. Dieser eine serverseitige Katalog ist die maschinenlesbare Quelle für Admission, Mutationsgate und Ambiguitätssemantik. Das Gateway liefert seine begrenzte öffentliche Projektion mit jeder erfolgreichen `observe`-Operation. Diese Slice implementiert `read`, `local_ui` und die eigene serverseitige Klasse `network_navigation`; `navigate` und das linkgebundene `activate` verwenden ausschließlich diese Klasse. `network_navigation` verlangt wie `local_ui` das Operator-Mutationsgate. Aktionsarten mit einer nicht implementierten Effektklasse scheitern fail-closed mit `result_code="effect_not_implemented"`, bevor ein Effekt versucht wird. `reversible_external`, `external_mutation` und `high_impact` bleiben unverändert gesperrt.

Jede Effektklasse trägt denselben konservativen Ambiguitätsvertrag: `retry_authorized=false`, `authoritative_readback_required=true` und `readback_grants_retry_authority=false`. Der konkrete Outcome ergänzt `effect_state` (`not_started`, `not_applicable`, `observed` oder `unknown`) und `retry_readback`. Bei `unknown` muss zuerst autoritativ gelesen werden; selbst ein erfolgreicher Readback macht aus dem verlorenen Intent keinen automatisch wiederholbaren Intent.

Zustandsbindung und TOCTOU-Schutz: `browser_semantic_act()` beobachtet unmittelbar vor einem Effekt den Worker und die begrenzte semantische Elementprojektion neu. Weicht der daraus berechnete `snapshot_id` ab, endet die Aktion mit `stale_snapshot`. Bei einer elementbezogenen Aktion muss anschließend der opake `element_id` innerhalb genau dieses frischen Snapshots wieder auflösbar sein; manipulierte oder workerfremde Handles enden mit `element_contract`. Der Adapter erhält ausschließlich die intern aufgelöste Elementbindung und den bestätigten Pre-State. CDP revalidiert dafür den Accessibility-/Backend-DOM-Knoten unmittelbar vor Wirkung. Der BiDi-Adapter erzeugt in seinem isolierten Realm pro Dokument stabile, private WeakMap-Knotenidentitäten, bindet diese in Snapshot und Elementhandle und liest das konkrete Element unmittelbar vor `scroll_into_view`/`activate` erneut; Rolle/Name bzw. Linkziel-Digest müssen weiterhin übereinstimmen. Drift zwischen Python-Precheck und Adaptereffekt endet auf beiden Wegen fail-closed als `stale_snapshot`.

Bei `activate` muss der opake Elementhandle zusätzlich auf ein Element mit Rolle `link` und einen bereits im Snapshot gebundenen privaten Linkziel-Digest zeigen. CDP liest Dokument-Base-URL und `href` über `DOM.getDocument`/`DOM.describeNode`; BiDi liest im isolierten Realm das reale `<a href>` mit `getAttribute`, kanonisiert dasselbe begrenzte absolute HTTP(S)-Ziel und hält im semantischen State ebenfalls nur dessen SHA-256. Direkt vor der Wirkung revalidiert jeder Adapter seine eigene interne Elementidentität und verlangt Digestgleichheit; reine `href`-Drift führt daher zu `stale_snapshot`. Beide Pfade rufen bewusst weder `.click()` noch Mouse-/DOM-Events auf. Damit werden Click-Handler, Formularwirkungen und generische UI-Aktionen nicht mitautorisiert; das Klartext-Linkziel bleibt außerhalb Public Outcome und Audit. Erst danach läuft das intern gehaltene Ziel durch die jeweilige backend-private Navigation.

Für `navigate` wird derselbe bestätigte Pre-Snapshot verwendet. Der private Adapter revalidiert zuerst den vollständigen internen Pre-State. CDP führt anschließend `Page.navigate` plus seine bestehende Frame-/Loader-/Same-Document-Korrelation aus. BiDi führt `browsingContext.navigate(wait="complete")` aus, **vertraut diesem ACK aber nicht als Outcome**, sondern pollt anschließend die eigene gebundene semantische Projektion bis `ready_state=complete` und ein gegenüber dem Pre-State veränderter Zustand beobachtet wurde. Ein identischer Zustand kann auf keinem Backend `observed` werden. Erst der geänderte autoritative Post-State erzeugt die neue gebundene `BrowserObservation`. Transportverlust oder fehlgeschlagener Readback nach abgesendetem Navigationskommando endet auf beiden Wegen fail-closed mit `effect_state=unknown`, ohne Retry-Autorität; unmittelbare Pre-State-/Elementdrift endet dagegen vor dem Navigationskommando als `stale_snapshot`/`not_started`. Auch ein späterer erfolgreicher Readback nach unbekanntem Effekt autorisiert keinen automatischen Retry.

### Audit und Receipt

`observe` schreibt einen begrenzten Outcome-Satz. Eine implementierte mutierende `act`-Operation schreibt vor dem Effekt zusätzlich einen Intent-Satz. Scheitert dieser Intent-Append, beginnt der Browser-Effekt nicht und das Ergebnis lautet `audit_unavailable`. Scheitert erst der Outcome-Append nach einem möglichen Effekt, bleibt der beobachtete oder unbekannte Effektzustand erhalten, `audit.outcome.recorded=false` und Retry-Autorität bleibt ausdrücklich gesperrt.

Die semantischen Audit-Sätze enthalten ausschließlich Worker-ID, Semantic-Operation/Intent, serverseitige Effektklasse, `ok`/`result_code`, `effect_state`, Retry-/Readback-Zustand, bei caller-seitig adressierter `navigate`-Navigation den worker-keyed Navigationszieldigest und die zur Korrelation nötigen opaken Snapshot-/Elementhandles. Bei `activate` bindet stattdessen der bereits auditierte opake `element_id` das Intent-Ziel; dieser Handle ist bereits an den privaten Linkziel-Digest gebunden. Weder Digest noch intern aufgelöste `href` werden als zweite öffentliche Zielautorität veröffentlicht. Sie enthalten weder Klartext-URL noch ein `name`-Feld, Origin, Titel, sonstigen Browserinhalt, Formwerte, Selektoren oder Backend-IDs. Der zentrale Effect-Receipt übernimmt ebenfalls nur Digests und Korrelationsevidenz, nicht die öffentliche Observation. Der Gateway-Return darf dagegen den begrenzten semantischen Namen liefern.

Für Dummies: Der Agent bekommt nicht mehr „klicke/rolle auf `#foo`“, sondern sinngemäß „Element `beid1_…`, Rolle Button, Name Weiter“. Diese ID funktioniert nur für genau den Browserworker und genau den beobachteten Seitenzustand. Ändert sich die Seite, wird die alte ID unbrauchbar statt versehentlich ein anderes Element zu treffen.

### Nichtbehauptungen dieser Slice

- Es wird **keine** generische externe Übermittlung implementiert: kein Formular-Submit und kein `reversible_external`/`external_mutation`/`high_impact`-Effekt.
- Es werden keine Formularwerte oder Accessibility-`value`-Felder projiziert. Semantische Namen werden ausschließlich begrenzt als Beschriftung im unmittelbaren Gateway-Return ausgegeben; daraus folgt keine Behauptung, dass beliebiger Seitentext generell nicht sensibel sein kann. Audit-Sätze bleiben namens- und inhaltsfrei. Der private Handle-Schlüssel selbst wird nie an den semantischen Aufrufer ausgegeben.
- Die öffentliche Elementliste ist bewusst begrenzt und auf ausgewählte öffentliche semantische Rollen beschränkt. CDP bezieht die Rollen aus Accessibility und die Namen primär aus AX; nur ein leerer AX-Name darf den oben beschriebenen begrenzten privaten DOM-Fallback auslösen. BiDi nutzt eine eng definierte DOM-/ARIA-Abbildung. Die veröffentlichte Liste ist ein relevanter semantischer DOM-Fingerprint, **kein** vollständiger Byte-für-Byte-DOM-Snapshot und keine Behauptung vollständiger Sichtbarkeits- oder Layoutidentität; der für den CDP-Fallback intern erfasste `DOMSnapshot` bleibt vollständig außerhalb der öffentlichen Projection und des Audits.
- `navigate` behauptet weder vollständiges Laden noch Erreichen eines bestimmten Seitentitels oder DOM-Zustands. Ein erfolgreicher Outcome belegt nur den korrelierten Navigations-ACK und den konkret beobachteten frischen Post-Command-Snapshot; dessen `ready_state` darf weiterhin einen laufenden Ladevorgang zeigen. Navigation garantiert insbesondere nicht die Abwesenheit serverseitiger GET-Wirkungen. Dasselbe gilt für `activate`, das ausschließlich das intern am gebundenen `<a>` gelesene HTTP(S)-Ziel navigiert und weder JavaScript-Click-Handler noch Formularaktionen ausführt. `scroll_into_view` wirkt nur lokal auf ein zuvor beobachtetes, opak gebundenes Element.
- `grabowski_browser_worker_stored_form_action` bleibt unverändert: eigenes Node-Skript, eigene Bestätigungs-/Origin-/Remote-IP-Prüfungen und eigene Result-Codes.
- Das Gateway exponiert weiterhin ausschließlich `observe` und `act`; `navigate` und `activate` sind backend-neutrale, kanonisch publizierte Act-Intents. Console, Network und Screenshot bleiben außerhalb dieser Slice. CDP bleibt der kanonische Chrome-Primärtransport; WebDriver BiDi ist ausschließlich der explizit qualifizierte Pre-Effect-Standby. Beide bleiben Implementierungsdetails und sind kein Teil des semantischen Public Contracts.
- `read_state` führt keinen zweiten Effekt-Roundtrip aus; die Pre-Action-Beobachtung dient zugleich als Post-Action-Beobachtung.
- Eine reine Scrollbewegung kann denselben Snapshot vor und nach dem Effekt behalten, weil Scrollposition und Layoutkoordinaten absichtlich nicht Teil des semantischen Fingerprints sind.

## WebDriver BiDi: Chrome-Standby und Firefox-Shadow

Chrome/WebDriver BiDi besitzt jetzt einen **engen Produktionsadapter**, aber ausschließlich in der Rolle `qualified-pre-effect-fallback`. Firefox/WebDriver BiDi bleibt dagegen unverändert **kein** Browser-Worker-Backend. `BROWSER_CONTROL_PLANE_FUTURE_ADAPTERS` beschreibt weiterhin ausschließlich diesen noch nicht produktiven Firefox-Pfad.

Der Chrome-Standby wird nicht durch eine allgemeine Adapterwahl aktiviert. `grabowski_browser_worker_start` bleibt standardmäßig CDP. Nur die optionale Angabe von `chromedriver_executable` armiert einen **startup-only Standby** innerhalb desselben synchronen Startvorgangs. Dabei gelten folgende Invarianten:

- die Option ist ausschließlich für Chrome Stable mit ephemerem Profil zugelassen;
- zusätzliche Chrome-Launch-Args müssen vollständig zur engen effektfreien Allowlist gehören; URL-Argumente, `--app=...` und alle sonstigen nicht klassifizierten Startoptionen werden **vor dem Primärstart** abgewiesen;
- Grabowski startet intern zuerst den normalen Chrome/CDP-Worker und prüft dessen `/json/version`-Readiness streng auf `127.0.0.1` und den exakt geleasten Port;
- ist CDP ready, wird nur dieser kanonische Primärworker zurückgegeben und BiDi nicht gestartet;
- ist CDP vor Worker-Rückgabe nicht ready, wird der noch private Primärversuch zuerst terminalisiert; seine Port-Lease muss vollständig frei und der CDP-Endpunkt anschließend unerreichbar sein; andernfalls endet der Start fail-closed;
- erst danach darf ein **neuer** `chrome-webdriver-bidi`-Worker auf demselben Port entstehen;
- `chromedriver` muss ein ausführbares, ownergebundenes, nicht gruppen-/weltbeschreibbares lokales Binary aus der expliziten Konfiguration oder dem begrenzten Selenium-Cache sein;
- ChromeDriver-HTTP und die zurückgegebene BiDi-WebSocket-URL müssen exakt denselben geleasten Loopback-Port und dieselbe Session-ID verwenden.

Der Primärworker wird während dieser Entscheidung niemals an den Caller herausgegeben. Dadurch kann zwischen Primärstart und Fallbackentscheidung weder ein Semantic-/Stored-Form- noch ein roher CDP-Caller-Effekt stattfinden. Nach Rückgabe eines Workers gibt es **keine** Fallback-API, kein Backend-Rebinding, keinen Snapshot-/Handle-Transfer und keinen zweiten Versuch auf BiDi. Insbesondere kann ein späteres `outcome_unknown` niemals Eingabe dieses Startpfads sein.

Die private BiDi-Sessionidentität liegt nur in `.webdriver-bidi-session.json` mit Modus `0600` im ephemeren Worker-Instanzverzeichnis. Public Worker Projection und Audit zeigen ausschließlich Adapter-ID, Protokoll, Auswahlrolle und die vorhandenen begrenzten Control-Plane-Metadaten; Session-ID und WebSocket-URL bleiben privat. Terminalisierung beendet die gesamte systemd-Control-Group, entfernt Profil und private Sessiondatei und gibt ausschließlich die worker-eigenen Port-/Profil-Leases frei.

### Bestehender Firefox-/BiDi-Shadow

Für Firefox und für unabhängige Vergleichsevidenz bleibt der separate **Shadow-Benchmark** (`tools/browser_bidi_shadow_benchmark_core.py` plus `tools/browser_bidi_shadow_benchmark.py`) bestehen. Er liegt außerhalb der öffentlichen MCP-/Grip-Surface und darf weder Session-, Profil-, Lease-, Outcome- oder Auditautorität der produktiven Browser-Control-Plane ersetzen noch eine Produktionsaktion auslösen.

Der Shadow-Vertrag ist absichtlich enger als der Produktionsadapter:

- geckodriver und Firefox werden als explizite lokale Executable-Pfade übergeben; der Runner installiert nichts systemweit und fügt keine neue Python-Runtime-Abhängigkeit hinzu;
- der Runner besitzt absichtlich keine zweite Lease-Autorität: der aufrufende Operator bindet HTTP-Port, WebSocket-Port und Work-Root vor dem Start; Live-Proben laufen als dauerhafte Grabowski-Task statt innerhalb der synchronen Operator-Surface, damit Browserkindprozess und Ressourcen denselben terminalen Lifecycle besitzen;
- WebDriver HTTP und BiDi WebSocket werden hart an `127.0.0.1` gebunden;
- Firefox läuft headless mit einem temporären Profil unter einem caller-eigenen Work-Root; geckodriver läuft in einer eigenen Prozessgruppe, die beim Closeout inklusive Eskalationspfad vollständig beendet wird;
- die Probe verwendet eine deterministische lokale `data:`-Seite und liest über BiDi ausschließlich `browsingContext.getTree`, `browsingContext.navigate` und `script.evaluate`;
- verglichen wird nur die kleine semantische Projektion `ready_state` plus geordnete `role`/`name`-Elemente gegen eine caller-gelieferte kanonische Referenz;
- Session-ID wird im Report nur als SHA-256 ausgegeben, die WebSocket-URL gar nicht; Timings sind Messwerte des Kandidatenpfads und keine statistische Performance- oder Produktionsparitätsaussage;
- Fehler enden `failed_closed`, `retry_authorized=false`; ein negativer Lauf beweist weder dauerhafte Transport-Unverfügbarkeit noch eine Berechtigung zum Retry oder Cutover.

### BiDi-Shadow-Matrix

`tools/browser_bidi_shadow_matrix.py` bleibt ebenfalls tooling-only. Sie führt Chrome/WebDriver-BiDi und Firefox/WebDriver-BiDi wiederholt gegen exakt dieselbe kleine Semantikreferenz aus; die Chrome/CDP-Referenz wird bewusst von außen geliefert und über einen externen Receipt-Digest gebunden. Die Matrix selbst besitzt weiterhin **keine** Routing-, Fallback- oder Produktionsautorität, auch wenn Chrome/BiDi inzwischen einen separat gehärteten Produktions-Standby besitzt.

- Chrome, ChromeDriver, Firefox und geckodriver werden ausschließlich als explizite Executable-Pfade übergeben; der Runner lädt oder installiert nichts.
- Beide WebDriver-Server sind loopback-only; temporäre Profile und alle Browser-/Driver-Prozesse gehören zum Lifecycle des jeweiligen Benchmark-Tasks.
- Eine Matrix umfasst 1 bis 5 Wiederholungen je Engine. Einzelmessungen sowie Min/Median/Max bleiben advisory.
- Jeder Einzelrun muss dieselbe normalisierte Projektion und denselben Semantikdigest wie die gelieferte Chrome/CDP-Referenz erreichen; ein Mismatch endet fail-closed.
- Die Matrix kann weder einen unbekannten Effekt wiederholen noch Firefox zum Produktionsbackend machen oder den Chrome/CDP-Default ändern.

Aktueller Produktionsvertrag:

- **Primary:** Chrome Stable / CDP;
- **Qualified Standby:** Chrome Stable / WebDriver BiDi, nur nach dem oben beschriebenen Pre-Effect-Proof;
- **Diversity/Shadow:** Firefox / WebDriver BiDi;
- **kein Auto-Router** und kein Fallback nach möglicher Wirkung;
- `retry_authorized=false` und autoritativer Outcome-Readback bleiben backendunabhängige Invarianten.

## Runtime-Grenze dieses Changes

Die Repository-Implementierung aktualisiert Worker/Gateway-Code, den privaten Chrome/BiDi-Transporthelper, den kanonischen Runtime-Source-Set, fokussierte Tests und dieses Dokument. Der normale Chrome/CDP-Start bleibt API- und Default-kompatibel; die neue Wirkung ist ausschließlich der explizit gebundene Standby-Start.

Der Repository-PR selbst erzeugt keine Runtime-Wirkung. Die Slice ist erst nach dem revisionsgebundenen Merge **und** der anschließenden Live-Abnahme auf dem exakt gemergten Grabowski-Head abgeschlossen. Die Live-Abnahme muss mindestens belegen:

1. Deployment auf den exakten gemergten Grabowski-Head;
2. den normalen Start mit armiertem `chromedriver_executable`, wobei ein kontrollierter Readiness-Negativfall **innerhalb des noch privaten Startvorgangs** den CDP-Primärversuch terminalisiert, Portfreigabe und Endpunkt-Abwesenheit liest und erst danach `chrome-webdriver-bidi` auf demselben Port startet;
3. den Gegenbeleg, dass derselbe armierte Start bei gesundem CDP ausschließlich `chrome-cdp` zurückgibt und keinen BiDi-Worker erzeugt;
4. auf diesem Standby `observe → navigate → frische Observation → linkgebundenes activate → stale replay`, wobei erfolgreiche Navigationen `observed` und der alte Handle `stale_snapshot/not_started` liefern;
5. einen Negativbeleg, dass nicht effektfreie Start-Args, nicht terminalisierbarer privater Primärversuch, verbliebene Port-Lease oder noch erreichbarer CDP-Endpunkt den Standby-Start fail-closed verhindern;
6. terminalen Stop und exakte Freigabe aller Worker-Port-/Profil-Leases sowie Entfernung der ephemeren BiDi-Sessiondatei;
7. gesunden Runtime-/Contract-Readback ohne Änderung des Chrome/CDP-Defaults und ohne Firefox-Promotion.

Deployment und Live-Abnahme laufen ausschließlich über die dafür vorgesehenen typisierten Grabowski-Operatorpfade. Die Slice autorisiert keinen automatischen Router, keinen Backendwechsel innerhalb eines Workers, keinen Retry nach `outcome_unknown`, keine Änderung des Desktop-Default-Browsers, keine Nutzung des menschlichen Standardprofils und keine Exposition von CDP/WebDriver/BiDi über Loopback hinaus.
