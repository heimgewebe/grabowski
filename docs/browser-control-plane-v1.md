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
| Brave | `chromium-cdp` | CDP | `fallback-test` |
| Chromium | `chromium-cdp` | CDP | `fallback-test` |
| Chrome for Testing | `chrome-cdp` | CDP | `reproducible-test` |

Chrome Stable ist damit die kanonische allgemeine Operatorwahl. Brave bleibt ausdrücklich zulässig, wird aber nicht zur kanonischen Agentenbasis erklärt. Chrome for Testing ist eine reproduzierbare Testoption und kein Zwang für allgemeines Browsing.

Ein Executable ohne implementierten CDP-Adapter wird vor Profilerzeugung und Workerstart abgewiesen. Eine bloße Aufnahme in `GRABOWSKI_BROWSER_EXECUTABLES` erzeugt also keine neue Protokollunterstützung. Der Adapter-Launchvertrag besitzt außerdem die protokollspezifische Port-/Argument-Validierung, Endpoint-Projektion und Argv-Konstruktion; `browser_start()` selbst verwaltet nur den gemeinsamen Worker-, Profil- und Lease-Lifecycle.

## Kanonischer Operatorpfad

Für normale Agenten-Browserarbeit gilt ab jetzt als Default, sofern kein konkretes Task-Erfordernis dagegen spricht:

1. `grabowski_context(...)` lesen und den runtimegebundenen `browser_operator_contract` beachten.
2. Chrome Stable über `grabowski_browser_worker_start` starten. Grabowski besitzt Worker-, Profil- und Lease-Lifecycle.
3. Standardmäßig ein separates ephemeres Profil verwenden; persistente Profile nur als explizite Auth-/Trust-Scopes.
4. Den von Grabowski erzeugten CDP-Endpunkt ausschließlich über `127.0.0.1` benutzen.
5. Semantisch abgedeckte Navigation und Aktionen über `grabowski_browser_worker_semantic` ausführen; nicht abgedeckte Browserfunktionen dürfen weiterhin den loopback-only CDP-Transport verwenden. Vendor-MCPs sind nur optionale Adapter/Diagnostik und übernehmen keine Lifecycle-Autorität.
6. Outcome durch eine frische autoritative Browserbeobachtung prüfen. Insbesondere begründet ein Command-ACK allein keinen Navigationserfolg.
7. Den eigenen Worker terminalisieren und anschließend Profilentfernung sowie Port-/Profil-Leasefreigabe lesen.
8. Menschliche Browserprofile und den Desktop-Default nicht verändern; Brave bleibt menschlicher Default/Fallback.

Dieser Pfad bleibt im versionierten Runtime-Entrypoint-Contract als allgemeiner Default verankert. Der aktuell veröffentlichte Schema-2-Vertrag beschreibt weiterhin ein partiell abdeckendes `semantic_gateway` mit `observe`/`act` für `read_state`, `navigate` und `scroll_into_view`. Diese Slice **staged** zusätzlich die interne, vollständig gehärtete Aktion `activate`, veröffentlicht sie aber noch nicht als kanonisch unterstützten Runtime-Intent. Gleichzeitig akzeptiert der kanonische Runtime-Validator für einen zweistufigen, cold-reentry-sicheren Rollout sowohl die aktuelle Dreierliste als auch die nächste Viererliste mit `activate`. Erst nachdem genau dieser rückwärtskompatible Validator deployt ist, darf ein separater Folgecommit den versionierten Runtime-Contract auf `activate` erweitern. `activate` selbst ist keine generische Klick-Autorität: Es akzeptiert ausschließlich ein opak snapshot-gebundenes Element mit Accessibility-Rolle `link`. Bereits die Observation bindet einen privaten SHA-256 des über CDP-DOM-Metadaten aufgelösten HTTP(S)-Linkziels in Snapshot und Elementhandle; unmittelbar vor der Wirkung wird derselbe `<a>`-Knoten samt Ziel erneut gelesen und erst bei Digestgleichheit über denselben korrelierten Navigationspfad wie `navigate` ausgeführt. Die Abdeckung bleibt partiell, weil Console, Network, Screenshot und weitere Browserfunktionen nicht Teil dieses Vertrags sind. Navigation ist öffentlich backend-neutral; der aktuelle Chrome-Adapter setzt sie intern ausschließlich mit CDP `Page.navigate` um. Wegen dieser Netznavigation ist die Capability mindestens `risk_class=high` und veröffentlicht den Effekt `browser-network-navigation`. Das ist keine neue Netzwerkautorität: Der Browserworker besitzt bereits normale Browser-Netzreichweite; insbesondere private oder Loopback-Ziele werden durch den semantischen Pfad weder neu autorisiert noch pauschal verboten, sondern erben ausschließlich die bereits bestehende Browserautorität. Der Repository-Stand dieser Slice behauptet ausdrücklich noch keine Runtime-Publikation von `activate`.

Ein zusätzlicher Praxistest am 12. August 2026 hat den kompletten Pfad erneut bestätigt: ein frischer Chrome-Stable-Worker öffnete `https://example.com/` direkt über CDP; `Page.loadEventFired` trat ein und `Runtime.evaluate` las `title=Example Domain`, `h1=Example Domain`, `readyState=complete` zurück. Danach wurden ephemeres Profil sowie Port-/Profil-Leases vollständig entfernt.

## Endpoint- und Transportvertrag

Der heutige Browserworker bindet CDP weiterhin ausschließlich an Loopback:

- `--remote-debugging-address=127.0.0.1`
- serverseitig gewählter `--remote-debugging-port=<port>`
- serverseitig gewähltes `--user-data-dir=<profil>`

Caller dürfen diese drei Bindungen weiterhin nicht über `args` überschreiben. Damit bleibt insbesondere der Chrome-Vertrag erhalten, dass Remote-Debugging mit einem separaten, nicht standardmäßigen User-Data-Directory erfolgt.

Die semantische Projektion weist den Endpoint als `loopback_only=true` aus. Das ist keine Erlaubnis, CDP über Tailscale, LAN, Funnel oder Internet zu exponieren.

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

Zusätzlich zur bestehenden Control-Plane-Projektion und zum bestehenden `grabowski_browser_worker_stored_form_action` stellt `src/grabowski_workers.py` die backend-neutrale Vertragsschicht `browser_semantic_observe()` und `browser_semantic_act()` bereit. Genau ein öffentliches Gateway, `grabowski_browser_worker_semantic`, macht sie mit den benannten Operationen `observe` und `act` agentenseitig nutzbar. Die interne `CDPAdapter`-Grenze wird für die aktuelle Chrome-/Chromium-Familie kohärent durch `ChromeCDPAdapter` implementiert. Weder CDP-Methodennamen noch CSS-Selektoren oder DOM-/AX-Knoten-IDs werden Teil des semantischen Aufrufervertrags.

Das bestehende `grabowski_operation_*`-Gateway ist dafür absichtlich nicht wiederverwendet: Es modelliert konfigurationsgetriebene argv-Rezepte mit Stringparametern, `terminal_execute`-Autorität und command-abhängigem Rollback. Snapshot-/Elementhandles und browserinterne TOCTOU-Revalidierung dort einzubauen würde Terminal- und Browserautorität vermischen. Das einzelne Browser-Gateway verhindert zugleich eine Tool-pro-Intent-Explosion.

### Stabile Publikation über die bestehende Grip-Surface

Ein Connector kann einen neuen MCP-Toolnamen später sehen als die bereits deployte Grabowski-Runtime. Dafür existieren nun zwei **Publikationsadapter innerhalb der schon stabilen `grip_run`-Surface**: `browser-semantic-observe` und `browser-semantic-act`. Sie sind keine zweite Browser-API. Beide importieren den Browsercode erst beim Aufruf und delegieren unmittelbar an dieselbe Funktion `browser_semantic_gateway()`. `browser-semantic-observe` fixiert die Operation auf `observe` und bleibt als Grip read-only; `browser-semantic-act` fixiert die Operation auf `act` und bleibt als Grip mutating.

Der Adapter führt keine eigene Effektklassifikation ein. Insbesondere kann der Aufrufer kein `effect_class` übergeben; unbekannte Adapterfelder werden vor der Delegation abgewiesen. Für `navigate` darf er zusätzlich genau ein `navigation_target` an das kanonische Gateway weiterreichen. Snapshot-, Element-, Zielvalidierungs-, TOCTOU-, Audit-, Outcome- und Retry-Semantik bleiben vollständig Eigentum des kanonischen Browser-Gateways. Die GripSpec bindet beide Publikationsadapter an die Capability `browser_worker`; der generische `grip_run`-Dispatcher erzwingt die Capability pro Grip statt pauschal `terminal_execute`. So bleiben browserfähige Least-Privilege-Profile nutzbar, ohne Terminalautorität zu erhalten. `browser-semantic-act` bleibt zusätzlich mutating und am bestehenden Transport-Roundtrip-Gate. Damit kann ein bereits veröffentlichter `grip_run` einen neuen semantischen Browservertrag konsumieren, ohne einen neuen Plattform-Toolnamen abzuwarten, ohne CDP nach außen zu spiegeln und ohne einen zweiten Lifecycle- oder Browservertrag zu schaffen. Der direkte Toolname `grabowski_browser_worker_semantic` bleibt der kanonische MCP-Einstieg, sobald der jeweilige Connector-Katalog ihn tatsächlich publiziert.

Die Vertragskonzepte:

- **Interne BrowserObservation**: Ergebnis von `browser_semantic_observe()`. Sie enthält für Härtung und Adapterauflösung weiterhin den begrenzten Origin-/Titel-/Accessibility-Fingerprint, gibt aber weder Formwerte noch AX-`value`, HTML, Selektoren, Backend-Knoten-IDs, Frame-/Loader-IDs, Cookies oder Credentials aus.
- **Öffentliche SemanticObservation**: unmittelbare Projektion des Gateways. Sie enthält `worker_id`, opaken `snapshot_id`, `observed_at_unix`, `ready_state` sowie höchstens 80 Elemente mit opakem `element_id`, auf 64 Zeichen begrenzter Accessibility-`role` und dem bereits intern auf 160 Zeichen begrenzten Accessibility-`name`. Origin, URL, Titel, rohe Selektoren und interne DOM-/AX-Knoten-IDs bleiben draußen.
- **snapshot_id**: unveränderlich und opak (`bsid2_<hex>`). Er wird mit HMAC-SHA-256 über `worker_id`, Origin/Ladezustand/Titel, internen Frame-/Loader-/Navigation-History-Bezug und die begrenzte semantische Elementprojektion einschließlich ihrer nur intern gehaltenen Backend-Knotenidentitäten sowie bei aktivierbaren Links des privaten Ziel-Digests gebildet. Der HMAC-Schlüssel ist ein zufälliger 32-Byte-Schlüssel pro Browserworker. Dadurch ändert nicht nur Navigation oder Reload, sondern auch relevante semantische DOM-/Accessibility-Drift den Snapshot; ohne den privaten Worker-Schlüssel lässt sich kein gültiger Snapshot-Handle offline konstruieren.
- **element_id**: opaker, deterministischer Handle (`beid1_<hex>`), ebenfalls HMAC-SHA-256-gebunden an den privaten Worker-Schlüssel, `worker_id`, den exakten `snapshot_id` und den internen Elementfingerprint. Bei einem aktivierbaren Link gehört der private SHA-256 des aufgelösten HTTP(S)-Ziels zu diesem Fingerprint; der Digest selbst wird nicht öffentlich projiziert. Ein Handle aus einem anderen Worker oder Snapshot kann weder neu hergeleitet noch auf einen rohen Selektor zurückfallen und wird nicht als Ziel akzeptiert.
- **Handle-Schlüssel**: wird beim Start jedes Browserworkers zufällig erzeugt und ausschließlich als private Datei `.semantic-handle-key` mit Modus `0600` im Worker-Instanzverzeichnis gespeichert. Er erscheint nicht in BrowserObservation, Workerprojektion, Audit oder Git und wird bei jeder terminalen Browser-Cleanup-Passage explizit entfernt, während das nicht geheime Worker-Manifest im Instanzverzeichnis als Evidenz erhalten bleiben darf. Die Entfernung löscht ausschließlich den festen Key-Pfad und folgt einem dort ersetzten Symlink nicht. Dieselbe terminale Cleanup-Passage entfernt best-effort zurückgebliebene reguläre, private `.browser-semantic-<token>.json`-/`.mjs`-Dateien; passende Symlinks werden weder verfolgt noch gelöscht.
- **Upgrade-Grenze**: Browserworker, die bereits vor Einführung dieses Schlüsselvertrags gestartet wurden, besitzen keinen Handle-Schlüssel. Der semantische Pfad erzeugt für sie keinen Schlüssel nachträglich und führt keinen Transport aus, sondern scheitert explizit und fail-closed mit der Anweisung, einen frischen Browserworker zu starten. Damit entsteht durch ein Runtime-Upgrade keine neue versteckte Identitätsmutation in einem bereits laufenden Worker.
- **BrowserIntent**: abstrakte Aktionsart aus dem systemeigenen `BROWSER_ACTION_CATALOG` (`read_state`, `navigate`, `scroll_into_view`, `activate`). Effektklasse sowie Element- oder Navigationszielbedarf kommen ausschließlich aus diesem Katalog; der Aufrufer liefert keine Effektklasse. `activate` ist in dieser Slice implementiert und testbar, bleibt aber bis zur separaten Runtime-Contract-Promotion ein gestagter Intent und ist noch nicht Teil des kanonisch publizierten Operatorvertrags.
- **Navigationsziel**: `navigate` verlangt genau ein absolutes HTTP(S)-Ziel von begrenzter Größe. Whitespace/Kontrollzeichen, Backslashes, Userinfo, fehlender Host, fremde Schemes und ungültige Ports werden vor Workerzugriff, Intent-Audit und Effekt abgewiesen. Das Ziel wird weder in BrowserOutcome noch Audit oder Effect-Receipt im Klartext zurückgegeben. Stattdessen bindet ein worker-keyed HMAC-SHA-256-Zieldigest Intent- und Outcome-Audit an dasselbe Ziel; der private Worker-HMAC-Schlüssel bleibt geheim.
- **BrowserAction**: Intent, gebunden an `worker_id`, `snapshot_id` und bei elementbezogenen Aktionen an `element_id`. `scroll_into_view` und `activate` akzeptieren keinen CSS-Selektor; `navigate` akzeptiert keine Browser-Backend- oder CDP-Parameter. `activate` ist zusätzlich auf die serverseitig gebundene Rolle `link` beschränkt.
- **BrowserOutcome**: enthält `ok`, `result_code`, `effect_state`, angeforderten Snapshot-/Elementhandle, die tatsächlich beobachtete Pre-/Post-Snapshot-ID und eine frische, öffentlich redigierte `observation`.

Effektvokabular (`BROWSER_EFFECT_CONTRACTS`): `read`, `local_ui`, `network_navigation`, `reversible_external`, `external_mutation`, `high_impact`. Dieser eine serverseitige Katalog ist die maschinenlesbare Quelle für Admission, Mutationsgate und Ambiguitätssemantik. Das Gateway liefert seine begrenzte öffentliche Projektion mit jeder erfolgreichen `observe`-Operation. Diese Slice implementiert `read`, `local_ui` und die eigene serverseitige Klasse `network_navigation`; `navigate` und das linkgebundene `activate` verwenden ausschließlich diese Klasse. `network_navigation` verlangt wie `local_ui` das Operator-Mutationsgate. Aktionsarten mit einer nicht implementierten Effektklasse scheitern fail-closed mit `result_code="effect_not_implemented"`, bevor ein Effekt versucht wird. `reversible_external`, `external_mutation` und `high_impact` bleiben unverändert gesperrt.

Jede Effektklasse trägt denselben konservativen Ambiguitätsvertrag: `retry_authorized=false`, `authoritative_readback_required=true` und `readback_grants_retry_authority=false`. Der konkrete Outcome ergänzt `effect_state` (`not_started`, `not_applicable`, `observed` oder `unknown`) und `retry_readback`. Bei `unknown` muss zuerst autoritativ gelesen werden; selbst ein erfolgreicher Readback macht aus dem verlorenen Intent keinen automatisch wiederholbaren Intent.

Zustandsbindung und TOCTOU-Schutz: `browser_semantic_act()` beobachtet unmittelbar vor einem Effekt den Worker und die begrenzte semantische Elementprojektion neu. Weicht der daraus berechnete `snapshot_id` ab, endet die Aktion mit `stale_snapshot`. Bei einer elementbezogenen Aktion muss anschließend der opake `element_id` innerhalb genau dieses frischen Snapshots wieder auflösbar sein; manipulierte oder workerfremde Handles enden mit `element_contract`. Der Adapter erhält ausschließlich die intern aufgelöste Elementbindung und den bestätigten Pre-State. Direkt vor einem Elementeffekt liest er den semantischen Zustand erneut, prüft den konkreten Accessibility-Knoten nochmals über dessen interne Backend-Identität, löst diesen erst dann in ein DOM-Objekt auf und prüft im Effektaufruf zusätzlich `isConnected`. Drift zwischen Python-Precheck und Adaptereffekt wird damit fail-closed als `stale_snapshot` behandelt.

Bei `activate` muss der opake Elementhandle zusätzlich auf ein Element mit Rolle `link` und einen bereits im Snapshot gebundenen privaten Linkziel-Digest zeigen. Der Adapter liest das Dokument-Base-URL und die `href` ausschließlich über CDP-DOM-Metadaten (`DOM.getDocument`/`DOM.describeNode`), normalisiert nur ein begrenztes absolutes HTTP(S)-Ziel ohne Userinfo und hält davon im semantischen State ausschließlich SHA-256. Direkt vor der Wirkung revalidiert er denselben Accessibility-Fingerprint und DOM-Knoten und verlangt Digestgleichheit; reine `href`-Drift führt daher zu `stale_snapshot`, selbst wenn Rolle, Name und Backend-Knoten gleich bleiben. Der Pfad ruft bewusst weder `.click()` noch Mouse-/DOM-Events oder einen seitenüberschreibbaren `href`-Getter auf. Damit werden Click-Handler, Formularwirkungen und generische UI-Aktionen nicht mitautorisiert; das Klartext-Linkziel bleibt außerhalb Public Outcome und Audit. Erst danach läuft das intern gehaltene Ziel durch dieselbe korrelierte Navigation wie `navigate`.

Für `navigate` wird derselbe bestätigte Pre-Snapshot verwendet. Der private Navigate-Adapter erhält diesen erwarteten internen Pre-State und führt die letzte vollständige `sameState`-Revalidierung, `Page.navigate`, begrenztes Korrelations-Polling und den frischen Post-Readback in genau einem Node-/Adapter-Roundtrip aus. Ein erfolgreicher Command-ACK begründet niemals allein `ok=true`: Für dokumentübergreifende Navigation muss der Post-State zu ACK-`frameId`/`loaderId` passen; für Same-Document-Navigation müssen ein nach dem finalen Precheck beobachtetes backend-privates `Page.navigatedWithinDocument`-Signal und ein gewechselter Navigation-History-Eintrag zusammenpassen. Ein bloß identischer `[before, ACK, before]`-State kann daher nie `observed` werden. Erst der korrelierte, geänderte Post-State erzeugt die neue gebundene `BrowserObservation`; genau deren Snapshot wird als `post_action_snapshot_id`, `observation.snapshot_id` und `authoritative_post_action_observation` zurückgegeben. Ein CDP-`errorText`, Transportverlust, fehlende Korrelation oder fehlgeschlagener Readback endet fail-closed mit `effect_state=unknown`, ohne Post-Snapshot und ohne Retry-Autorität. Drift bei der unmittelbaren Adapter-Revalidierung endet dagegen vor `Page.navigate` als `stale_snapshot`/`not_started`. Auch ein späterer erfolgreicher Readback nach unbekanntem Effekt autorisiert keinen automatischen Retry.

### Audit und Receipt

`observe` schreibt einen begrenzten Outcome-Satz. Eine implementierte mutierende `act`-Operation schreibt vor dem Effekt zusätzlich einen Intent-Satz. Scheitert dieser Intent-Append, beginnt der Browser-Effekt nicht und das Ergebnis lautet `audit_unavailable`. Scheitert erst der Outcome-Append nach einem möglichen Effekt, bleibt der beobachtete oder unbekannte Effektzustand erhalten, `audit.outcome.recorded=false` und Retry-Autorität bleibt ausdrücklich gesperrt.

Die semantischen Audit-Sätze enthalten ausschließlich Worker-ID, Semantic-Operation/Intent, serverseitige Effektklasse, `ok`/`result_code`, `effect_state`, Retry-/Readback-Zustand, bei caller-seitig adressierter `navigate`-Navigation den worker-keyed Navigationszieldigest und die zur Korrelation nötigen opaken Snapshot-/Elementhandles. Bei `activate` bindet stattdessen der bereits auditierte opake `element_id` das Intent-Ziel; dieser Handle ist bereits an den privaten Linkziel-Digest gebunden. Weder Digest noch intern aufgelöste `href` werden als zweite öffentliche Zielautorität veröffentlicht. Sie enthalten weder Klartext-URL noch ein `name`-Feld, Origin, Titel, sonstigen Browserinhalt, Formwerte, Selektoren oder Backend-IDs. Der zentrale Effect-Receipt übernimmt ebenfalls nur Digests und Korrelationsevidenz, nicht die öffentliche Observation. Der Gateway-Return darf dagegen den begrenzten Accessibility-Namen liefern.

Für Dummies: Der Agent bekommt nicht mehr „klicke/rolle auf `#foo`“, sondern sinngemäß „Element `beid1_…`, Rolle Button, Name Weiter“. Diese ID funktioniert nur für genau den Browserworker und genau den beobachteten Seitenzustand. Ändert sich die Seite, wird die alte ID unbrauchbar statt versehentlich ein anderes Element zu treffen.

### Nichtbehauptungen dieser Slice

- Es wird **keine** generische externe Übermittlung implementiert: kein Formular-Submit und kein `reversible_external`/`external_mutation`/`high_impact`-Effekt.
- Es werden keine Formularwerte oder Accessibility-`value`-Felder gelesen oder projiziert. Accessibility-Namen werden ausschließlich begrenzt als semantische Beschriftung im unmittelbaren Gateway-Return ausgegeben; daraus folgt keine Behauptung, dass beliebiger Seitentext generell nicht sensibel sein kann. Audit-Sätze bleiben namens- und inhaltsfrei. Der private Handle-Schlüssel selbst wird nie an den semantischen Aufrufer ausgegeben.
- Die Elementliste ist bewusst begrenzt und auf ausgewählte semantische Accessibility-Rollen beschränkt. Sie ist ein relevanter semantischer DOM-Fingerprint, **kein** vollständiger Byte-für-Byte-DOM-Snapshot und keine Behauptung vollständiger Sichtbarkeits- oder Layoutidentität.
- `navigate` behauptet weder vollständiges Laden noch Erreichen eines bestimmten Seitentitels oder DOM-Zustands. Ein erfolgreicher Outcome belegt nur den korrelierten Navigations-ACK und den konkret beobachteten frischen Post-Command-Snapshot; dessen `ready_state` darf weiterhin einen laufenden Ladevorgang zeigen. Navigation garantiert insbesondere nicht die Abwesenheit serverseitiger GET-Wirkungen. Dasselbe gilt für `activate`, das ausschließlich das intern am gebundenen `<a>` gelesene HTTP(S)-Ziel navigiert und weder JavaScript-Click-Handler noch Formularaktionen ausführt. `scroll_into_view` wirkt nur lokal auf ein zuvor beobachtetes, opak gebundenes Element.
- `grabowski_browser_worker_stored_form_action` bleibt unverändert: eigenes Node-Skript, eigene Bestätigungs-/Origin-/Remote-IP-Prüfungen und eigene Result-Codes.
- Das Gateway exponiert weiterhin ausschließlich `observe` und `act`; `navigate` ist kanonisch publiziert, während `activate` in dieser Slice backend-neutral implementiert, aber bis zum separaten Folge-Rollout noch nicht im versionierten Runtime-Contract freigeschaltet ist. Console, Network und Screenshot bleiben außerhalb dieser Slice. CDP bleibt Implementierungsdetail des aktuellen Chrome-Adapters und ist kein Teil des semantischen Public Contracts.
- `read_state` führt keinen zweiten Effekt-Roundtrip aus; die Pre-Action-Beobachtung dient zugleich als Post-Action-Beobachtung.
- Eine reine Scrollbewegung kann denselben Snapshot vor und nach dem Effekt behalten, weil Scrollposition und Layoutkoordinaten absichtlich nicht Teil des semantischen Fingerprints sind.

## WebDriver BiDi / Firefox

`webdriver-bidi` bleibt in v1 als **nicht implementierter Produktionsadapter** modelliert. Wave B ändert diese Aussage ausdrücklich nicht: Firefox wird weder als Browser-Worker-Backend freigeschaltet noch zum Default, und `BROWSER_CONTROL_PLANE_FUTURE_ADAPTERS` bleibt fail-closed.

Für die kontrollierte Kandidatenprüfung existiert stattdessen ein separater **Shadow-Benchmark** (`tools/browser_bidi_shadow_benchmark_core.py` plus `tools/browser_bidi_shadow_benchmark.py`). Er liegt außerhalb der öffentlichen MCP-/Grip-Surface und darf deshalb weder Session-, Profil-, Lease-, Outcome- oder Auditautorität der produktiven Browser-Control-Plane ersetzen noch eine Produktionsaktion auslösen.

Der Shadow-Vertrag ist absichtlich enger als ein Adapter:

- geckodriver und Firefox werden als explizite lokale Executable-Pfade übergeben; der Runner installiert nichts systemweit und fügt keine neue Python-Runtime-Abhängigkeit hinzu;
- der Runner besitzt absichtlich keine zweite Lease-Autorität: der aufrufende Operator bindet HTTP-Port, WebSocket-Port und Work-Root vor dem Start; Live-Proben laufen als dauerhafte Grabowski-Task statt innerhalb der synchronen Operator-Surface, damit Browserkindprozess und Ressourcen denselben terminalen Lifecycle besitzen;
- WebDriver HTTP und BiDi WebSocket werden hart an `127.0.0.1` gebunden; eine zurückgegebene WebSocket-URL muss denselben Loopback-Port und exakt die erzeugte Session-ID tragen;
- Firefox läuft headless mit einem temporären Profil unter einem caller-eigenen Work-Root; geckodriver läuft in einer eigenen Prozessgruppe, die beim Closeout inklusive Eskalationspfad vollständig beendet wird;
- die Probe verwendet eine deterministische lokale `data:`-Seite und liest über BiDi ausschließlich `browsingContext.getTree`, `browsingContext.navigate` und `script.evaluate`;
- verglichen wird nur die kleine semantische Projektion `ready_state` plus geordnete `role`/`name`-Elemente gegen eine caller-gelieferte kanonische Referenz;
- Session-ID wird im Report nur als SHA-256 ausgegeben, die WebSocket-URL gar nicht; Timings sind Messwerte des Kandidatenpfads und keine statistische Performance- oder Produktionsparitätsaussage;
- Fehler enden `failed_closed`, `retry_authorized=false`; ein negativer Lauf beweist weder dauerhafte Transport-Unverfügbarkeit noch eine Berechtigung zum Retry oder Cutover.

### BiDi-Shadow-Matrix

Für Wave B existiert ergänzend `tools/browser_bidi_shadow_matrix.py`. Die Matrix ist ebenfalls ausschließlich tooling-only und erweitert den Einzelbenchmark nicht zu einem Produktionsadapter. Sie führt Chrome/WebDriver-BiDi und Firefox/WebDriver-BiDi wiederholt gegen exakt dieselbe kleine Semantikreferenz aus. Die Chrome/CDP-Referenz wird bewusst von außen geliefert. Die CLI verlangt zusätzlich den SHA-256 des externen Semantic-Gateway-/Observation-Receipts und bindet ihn unverändert in den Report; ohne gültigen 64-Hex-Digest startet keine Matrix. Die Matrix verifiziert nicht selbst, dass Receipt und Referenzbytes zusammengehören: diese Korrespondenz bleibt Aufgabe des produktiven Semantic-Gateway-/Receipt-Pfads und muss außerhalb des Tools revisionsgebunden belegt sein.

- Chrome, ChromeDriver, Firefox und geckodriver werden ausschließlich als explizite Executable-Pfade übergeben; der Runner lädt oder installiert nichts.
- Beide WebDriver-Server sind loopback-only. ChromeDriver erhält einen temporären `user-data-dir`; Firefox verwendet weiterhin den temporären geckodriver-Profile-Root. Sämtliche Browser-/Driver-Prozesse gehören zur Prozessgruppe des langlebigen Benchmark-Tasks und werden nach jedem Lauf beendet.
- Die Chrome-BiDi-WebSocket-URL muss eine exakt sessiongebundene Loopback-URL sein. Ein `localhost`-Alias wird nur akzeptiert, wenn seine IPv4-Auflösung ausschließlich `127.0.0.1` ergibt; intern wird anschließend die numerische Loopback-Adresse verwendet.
- Eine Matrix umfasst 1 bis 5 Wiederholungen je Engine. Ausgegeben werden Einzelmessungen sowie Min/Median/Max für Sessionaufbau und Gesamtdauer. Diese Werte sind ausdrücklich advisory: die Matrix enthält kein Gewinnerfeld und begründet weder Performanceüberlegenheit noch Promotion.
- Jeder Einzelrun muss dieselbe normalisierte Projektion `ready_state` plus geordnete `role`/`name`-Elemente und denselben Semantikdigest wie die gelieferte Chrome/CDP-Referenz erreichen. Ein Mismatch oder Lifecyclefehler beendet die Matrix fail-closed.
- `production_adapter_changed=false` und `retry_authorized=false` sind invariant. Die Matrix kann weder Routing umschalten noch einen unbekannten Effekt wiederholen oder Firefox/Chrome-BiDi als Produktionsbackend freischalten.
- Browser-/WebDriver-Liveproben laufen als langlebige Grabowski/systemd-Tasks. Der synchrone Terminalpfad ist kein gültiger Browserprozess-Lifecycle-Beleg.

Bis ein eigener BiDi-Produktionsadapter mit separaten Tests und Runtime-Acceptance existiert:

- Firefox ist kein Browser-Worker-Backend;
- eine Allowlist-Erweiterung allein aktiviert Firefox nicht;
- der produktive Start scheitert explizit und fail-closed;
- Shadow-Parität in einem Szenario behauptet keine Funktionsgleichheit zu Chrome/CDP;
- Chrome/CDP bleibt der allgemeine Operator-Default; semantisches `navigate` wird beim aktuellen Produktionsadapter intern durch CDP ausgeführt, ohne CDP in den öffentlichen Vertrag aufzunehmen.

## Runtime-Grenze dieses Changes

Die Repository-Implementierung aktualisiert Worker/Gateway-Code, den kanonischen Runtime-/Capability-/Toolbudget-Vertrag, fokussierte Tests und dieses Dokument. Parallel verantwortete generierte Operator-Context-Artefakte werden in dieser Lane nicht überschrieben; bis zu deren kanonischer Regeneration darf `context-check` deshalb exakt diese Drift melden.

Der Repository-PR selbst erzeugt keine Runtime-Wirkung. Der Bureau-Task ist jedoch erst nach dem revisionsgebundenen Merge **und** der anschließenden Live-Abnahme auf dem exakt gemergten Grabowski-Head abgeschlossen. Die Live-Abnahme muss mindestens belegen:

1. Deployment auf den exakten gemergten Grabowski-Head;
2. einen frischen Chrome-Stable-Worker über den neuen Adaptervertrag;
3. loopback-only CDP- und Control-Plane-Readback;
4. terminalen Stop und exakte Freigabe von Port-/Profil-Leases;
5. per separatem Readback, dass der menschliche Desktop-Default weiterhin Brave ist.

Deployment und Live-Abnahme laufen ausschließlich über die dafür vorgesehenen typisierten Grabowski-Operatorpfade. Der Task autorisiert keine Änderung des Desktop-Default-Browsers, keine Nutzung des menschlichen Standardprofils und keine Exposition des Debugging-Endpunkts über Loopback hinaus.
