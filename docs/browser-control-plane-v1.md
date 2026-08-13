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
5. Navigation, allgemeine Aktionen und Readback primär direkt über CDP ausführen. Vendor-MCPs sind nur optionale Adapter/Diagnostik und übernehmen keine Lifecycle-Autorität.
6. Outcome durch echten CDP-/DOM-Readback prüfen, nicht nur durch eine Control-Plane-Projektion.
7. Den eigenen Worker terminalisieren und anschließend Profilentfernung sowie Port-/Profil-Leasefreigabe lesen.
8. Menschliche Browserprofile und den Desktop-Default nicht verändern; Brave bleibt menschlicher Default/Fallback.

Dieser Pfad bleibt im versionierten Runtime-Entrypoint-Contract als allgemeiner Default verankert. Schema 2 ergänzt lediglich ein partiell abdeckendes `semantic_gateway`: `grabowski_browser_worker_semantic` unterstützt `observe`/`act` für `read_state` und `scroll_into_view`. `navigate` ist ausdrücklich nicht abgedeckt und erfordert weiterhin direct CDP. Es gibt in dieser Slice weder eine semantische Navigation noch einen allgemeinen Default-Cutover auf das Gateway. Ein neu generierter und anschließend deployter `grabowski_context` kann diesen Teilvertrag später tragen; der Repository-Stand allein behauptet keine Runtime-Aktualisierung.

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

## Semantischer Aktionsvertrag (observe → snapshot → act → verify)

Zusätzlich zur bestehenden Control-Plane-Projektion und zum bestehenden `grabowski_browser_worker_stored_form_action` stellt `src/grabowski_workers.py` die backend-neutrale Vertragsschicht `browser_semantic_observe()` und `browser_semantic_act()` bereit. Genau ein öffentliches Gateway, `grabowski_browser_worker_semantic`, macht sie mit den benannten Operationen `observe` und `act` agentenseitig nutzbar. Der Chrome-Adapter verwendet intern CDP, doch weder CDP-Methodennamen noch CSS-Selektoren oder DOM-/AX-Knoten-IDs werden Teil des semantischen Aufrufervertrags.

Das bestehende `grabowski_operation_*`-Gateway ist dafür absichtlich nicht wiederverwendet: Es modelliert konfigurationsgetriebene argv-Rezepte mit Stringparametern, `terminal_execute`-Autorität und command-abhängigem Rollback. Snapshot-/Elementhandles und browserinterne TOCTOU-Revalidierung dort einzubauen würde Terminal- und Browserautorität vermischen. Das einzelne Browser-Gateway verhindert zugleich eine Tool-pro-Intent-Explosion.

### Stabile Publikation über die bestehende Grip-Surface

Ein Connector kann einen neuen MCP-Toolnamen später sehen als die bereits deployte Grabowski-Runtime. Dafür existieren nun zwei **Publikationsadapter innerhalb der schon stabilen `grip_run`-Surface**: `browser-semantic-observe` und `browser-semantic-act`. Sie sind keine zweite Browser-API. Beide importieren den Browsercode erst beim Aufruf und delegieren unmittelbar an dieselbe Funktion `browser_semantic_gateway()`. `browser-semantic-observe` fixiert die Operation auf `observe` und bleibt als Grip read-only; `browser-semantic-act` fixiert die Operation auf `act` und bleibt als Grip mutating.

Der Adapter führt keine eigene Effektklassifikation ein. Insbesondere kann der Aufrufer kein `effect_class` übergeben; unbekannte Adapterfelder werden vor der Delegation abgewiesen. Snapshot-, Element-, TOCTOU-, Audit-, Outcome- und Retry-Semantik bleiben vollständig Eigentum des kanonischen Browser-Gateways. Die GripSpec bindet beide Publikationsadapter an die Capability `browser_worker`; der generische `grip_run`-Dispatcher erzwingt die Capability pro Grip statt pauschal `terminal_execute`. So bleiben browserfähige Least-Privilege-Profile nutzbar, ohne Terminalautorität zu erhalten. `browser-semantic-act` bleibt zusätzlich mutating und am bestehenden Transport-Roundtrip-Gate. Damit kann ein bereits veröffentlichter `grip_run` einen neuen semantischen Browservertrag konsumieren, ohne einen neuen Plattform-Toolnamen abzuwarten, ohne CDP nach außen zu spiegeln und ohne einen zweiten Lifecycle- oder Browservertrag zu schaffen. Der direkte Toolname `grabowski_browser_worker_semantic` bleibt der kanonische MCP-Einstieg, sobald der jeweilige Connector-Katalog ihn tatsächlich publiziert.

Die Vertragskonzepte:

- **Interne BrowserObservation**: Ergebnis von `browser_semantic_observe()`. Sie enthält für Härtung und Adapterauflösung weiterhin den begrenzten Origin-/Titel-/Accessibility-Fingerprint, gibt aber weder Formwerte noch AX-`value`, HTML, Selektoren, Backend-Knoten-IDs, Frame-/Loader-IDs, Cookies oder Credentials aus.
- **Öffentliche SemanticObservation**: unmittelbare Projektion des Gateways. Sie enthält `worker_id`, opaken `snapshot_id`, `observed_at_unix`, `ready_state` sowie höchstens 80 Elemente mit opakem `element_id`, auf 64 Zeichen begrenzter Accessibility-`role` und dem bereits intern auf 160 Zeichen begrenzten Accessibility-`name`. Origin, URL, Titel, rohe Selektoren und interne DOM-/AX-Knoten-IDs bleiben draußen.
- **snapshot_id**: unveränderlich und opak (`bsid2_<hex>`). Er wird mit HMAC-SHA-256 über `worker_id`, Origin/Ladezustand/Titel, internen Frame-/Loader-Bezug und die begrenzte semantische Elementprojektion einschließlich ihrer nur intern gehaltenen Backend-Knotenidentitäten gebildet. Der HMAC-Schlüssel ist ein zufälliger 32-Byte-Schlüssel pro Browserworker. Dadurch ändert nicht nur Navigation oder Reload, sondern auch relevante semantische DOM-/Accessibility-Drift den Snapshot; ohne den privaten Worker-Schlüssel lässt sich kein gültiger Snapshot-Handle offline konstruieren.
- **element_id**: opaker, deterministischer Handle (`beid1_<hex>`), ebenfalls HMAC-SHA-256-gebunden an den privaten Worker-Schlüssel, `worker_id`, den exakten `snapshot_id` und den internen Elementfingerprint. Ein Handle aus einem anderen Worker oder Snapshot kann weder neu hergeleitet noch auf einen rohen Selektor zurückfallen und wird nicht als Ziel akzeptiert.
- **Handle-Schlüssel**: wird beim Start jedes Browserworkers zufällig erzeugt und ausschließlich als private Datei `.semantic-handle-key` mit Modus `0600` im Worker-Instanzverzeichnis gespeichert. Er erscheint nicht in BrowserObservation, Workerprojektion, Audit oder Git und wird bei jeder terminalen Browser-Cleanup-Passage explizit entfernt, während das nicht geheime Worker-Manifest im Instanzverzeichnis als Evidenz erhalten bleiben darf. Die Entfernung löscht ausschließlich den festen Key-Pfad und folgt einem dort ersetzten Symlink nicht.
- **Upgrade-Grenze**: Browserworker, die bereits vor Einführung dieses Schlüsselvertrags gestartet wurden, besitzen keinen Handle-Schlüssel. Der semantische Pfad erzeugt für sie keinen Schlüssel nachträglich und führt keinen Transport aus, sondern scheitert explizit und fail-closed mit der Anweisung, einen frischen Browserworker zu starten. Damit entsteht durch ein Runtime-Upgrade keine neue versteckte Identitätsmutation in einem bereits laufenden Worker.
- **BrowserIntent**: abstrakte Aktionsart aus dem systemeigenen `BROWSER_ACTION_CATALOG` (`read_state`, `scroll_into_view`). Effektklasse und die Frage, ob ein Elementhandle erforderlich ist, kommen ausschließlich aus diesem Katalog; der Aufrufer liefert keine Effektklasse.
- **BrowserAction**: Intent, gebunden an `worker_id`, `snapshot_id` und bei elementbezogenen Aktionen an `element_id`. `scroll_into_view` akzeptiert keinen CSS-Selektor mehr.
- **BrowserOutcome**: enthält `ok`, `result_code`, `effect_state`, angeforderten Snapshot-/Elementhandle, die tatsächlich beobachtete Pre-/Post-Snapshot-ID und eine frische, öffentlich redigierte `observation`.

Effektvokabular (`BROWSER_EFFECT_CONTRACTS`): `read`, `local_ui`, `reversible_external`, `external_mutation`, `high_impact`. Dieser eine serverseitige Katalog ist die maschinenlesbare Quelle für Admission, Mutationsgate und Ambiguitätssemantik. Das Gateway liefert seine begrenzte öffentliche Projektion mit jeder erfolgreichen `observe`-Operation. Diese Slice implementiert ausschließlich `read` und `local_ui`. Aktionsarten mit einer nicht implementierten Effektklasse scheitern fail-closed mit `result_code="effect_not_implemented"`, bevor ein Effekt versucht wird. `reversible_external`, `external_mutation` und `high_impact` bleiben gesperrt.

Jede Effektklasse trägt denselben konservativen Ambiguitätsvertrag: `retry_authorized=false`, `authoritative_readback_required=true` und `readback_grants_retry_authority=false`. Der konkrete Outcome ergänzt `effect_state` (`not_started`, `not_applicable`, `observed` oder `unknown`) und `retry_readback`. Bei `unknown` muss zuerst autoritativ gelesen werden; selbst ein erfolgreicher Readback macht aus dem verlorenen Intent keinen automatisch wiederholbaren Intent.

Zustandsbindung und TOCTOU-Schutz: `browser_semantic_act()` beobachtet unmittelbar vor einem Effekt den Worker und die begrenzte semantische Elementprojektion neu. Weicht der daraus berechnete `snapshot_id` ab, endet die Aktion mit `stale_snapshot`. Bei einer elementbezogenen Aktion muss anschließend der opake `element_id` innerhalb genau dieses frischen Snapshots wieder auflösbar sein; manipulierte oder workerfremde Handles enden mit `element_contract`. Der Adapter erhält ausschließlich die intern aufgelöste Elementbindung und den bestätigten Pre-State. Direkt vor dem Effekt liest er den semantischen Zustand erneut, prüft den konkreten Accessibility-Knoten nochmals über dessen interne Backend-Identität, löst diesen erst dann in ein DOM-Objekt auf und prüft im Effektaufruf zusätzlich `isConnected`. Drift zwischen Python-Precheck und Adaptereffekt wird damit fail-closed als `stale_snapshot` behandelt. Nach einem ausgeführten Effekt erfolgt eine neue autoritative Beobachtung; nur diese wird als `authoritative_post_action_observation` ausgewiesen.

### Audit und Receipt

`observe` schreibt einen begrenzten Outcome-Satz. Eine implementierte mutierende `act`-Operation schreibt vor dem Effekt zusätzlich einen Intent-Satz. Scheitert dieser Intent-Append, beginnt der Browser-Effekt nicht und das Ergebnis lautet `audit_unavailable`. Scheitert erst der Outcome-Append nach einem möglichen Effekt, bleibt der beobachtete oder unbekannte Effektzustand erhalten, `audit.outcome.recorded=false` und Retry-Autorität bleibt ausdrücklich gesperrt.

Die semantischen Audit-Sätze enthalten ausschließlich Worker-ID, Semantic-Operation/Intent, serverseitige Effektklasse, `ok`/`result_code`, `effect_state`, Retry-/Readback-Zustand und die zur Korrelation nötigen opaken Snapshot-/Elementhandles. Sie enthalten weder ein `name`-Feld noch Origin, Titel, sonstigen Browserinhalt, Formwerte, Selektoren oder Backend-IDs. Der zentrale Effect-Receipt übernimmt ebenfalls nur Digests und Korrelationsevidenz, nicht die öffentliche Observation. Der Gateway-Return darf dagegen den begrenzten Accessibility-Namen liefern.

Für Dummies: Der Agent bekommt nicht mehr „klicke/rolle auf `#foo`“, sondern sinngemäß „Element `beid1_…`, Rolle Button, Name Weiter“. Diese ID funktioniert nur für genau den Browserworker und genau den beobachteten Seitenzustand. Ändert sich die Seite, wird die alte ID unbrauchbar statt versehentlich ein anderes Element zu treffen.

### Nichtbehauptungen dieser Slice

- Es wird **keine** generische externe Übermittlung implementiert: kein Formular-Submit und kein `reversible_external`/`external_mutation`/`high_impact`-Effekt.
- Es werden keine Formularwerte oder Accessibility-`value`-Felder gelesen oder projiziert. Accessibility-Namen werden ausschließlich begrenzt als semantische Beschriftung im unmittelbaren Gateway-Return ausgegeben; daraus folgt keine Behauptung, dass beliebiger Seitentext generell nicht sensibel sein kann. Audit-Sätze bleiben namens- und inhaltsfrei. Der private Handle-Schlüssel selbst wird nie an den semantischen Aufrufer ausgegeben.
- Die Elementliste ist bewusst begrenzt und auf ausgewählte semantische Accessibility-Rollen beschränkt. Sie ist ein relevanter semantischer DOM-Fingerprint, **kein** vollständiger Byte-für-Byte-DOM-Snapshot und keine Behauptung vollständiger Sichtbarkeits- oder Layoutidentität.
- Das Gateway implementiert keine Navigation; `navigate` bleibt außerhalb seiner Teilabdeckung und erfordert direct CDP. `scroll_into_view` wirkt nur lokal auf ein zuvor beobachtetes, opak gebundenes Element.
- `grabowski_browser_worker_stored_form_action` bleibt unverändert: eigenes Node-Skript, eigene Bestätigungs-/Origin-/Remote-IP-Prüfungen und eigene Result-Codes.
- Das Gateway exponiert ausschließlich `observe` und `act`; Navigation, Console, Network und Screenshot bleiben außerhalb dieser Slice. Direct CDP bleibt der allgemeine Operator-Default und für `navigate` erforderlich; es ist kein Teil des semantischen Public Contracts.
- `read_state` führt keinen zweiten Effekt-Roundtrip aus; die Pre-Action-Beobachtung dient zugleich als Post-Action-Beobachtung.
- Eine reine Scrollbewegung kann denselben Snapshot vor und nach dem Effekt behalten, weil Scrollposition und Layoutkoordinaten absichtlich nicht Teil des semantischen Fingerprints sind.

## WebDriver BiDi / Firefox

`webdriver-bidi` ist in v1 nur als **nicht implementierter Zukunftsadapter** modelliert. Das ermöglicht eine zweite Engine hinter derselben semantischen Control-Plane, ohne Session-, Profil-, Lease-, Outcome- oder Auditautorität neu zu entwerfen.

Bis ein eigener BiDi-Adapter mit separaten Tests und Runtime-Acceptance existiert:

- Firefox ist kein Browser-Worker-Backend;
- eine Allowlist-Erweiterung allein aktiviert Firefox nicht;
- der Start scheitert explizit und fail-closed;
- es wird keine Funktionsgleichheit zu Chrome/CDP behauptet.

## Runtime-Grenze dieses Changes

Die Repository-Implementierung aktualisiert Worker/Gateway-Code, den kanonischen Runtime-/Capability-/Toolbudget-Vertrag, fokussierte Tests und dieses Dokument. Parallel verantwortete generierte Operator-Context-Artefakte werden in dieser Lane nicht überschrieben; bis zu deren kanonischer Regeneration darf `context-check` deshalb exakt diese Drift melden.

Der Repository-PR selbst erzeugt keine Runtime-Wirkung. Der Bureau-Task ist jedoch erst nach dem revisionsgebundenen Merge **und** der anschließenden Live-Abnahme auf dem exakt gemergten Grabowski-Head abgeschlossen. Die Live-Abnahme muss mindestens belegen:

1. Deployment auf den exakten gemergten Grabowski-Head;
2. einen frischen Chrome-Stable-Worker über den neuen Adaptervertrag;
3. loopback-only CDP- und Control-Plane-Readback;
4. terminalen Stop und exakte Freigabe von Port-/Profil-Leases;
5. per separatem Readback, dass der menschliche Desktop-Default weiterhin Brave ist.

Deployment und Live-Abnahme laufen ausschließlich über die dafür vorgesehenen typisierten Grabowski-Operatorpfade. Der Task autorisiert keine Änderung des Desktop-Default-Browsers, keine Nutzung des menschlichen Standardprofils und keine Exposition des Debugging-Endpunkts über Loopback hinaus.
