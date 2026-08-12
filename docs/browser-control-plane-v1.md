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
5. Navigation, Aktionen und Readback primär direkt über CDP ausführen. Vendor-MCPs sind nur optionale Adapter/Diagnostik und übernehmen keine Lifecycle-Autorität.
6. Outcome durch echten CDP-/DOM-Readback prüfen, nicht nur durch eine Control-Plane-Projektion.
7. Den eigenen Worker terminalisieren und anschließend Profilentfernung sowie Port-/Profil-Leasefreigabe lesen.
8. Menschliche Browserprofile und den Desktop-Default nicht verändern; Brave bleibt menschlicher Default/Fallback.

Dieser Pfad ist sowohl im versionierten Runtime-Entrypoint-Contract als auch im Live-Output von `grabowski_context` verankert. Damit hängt die Kenntnis des Standardwegs nicht von Chat-Historie oder Modellgedächtnis ab.

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

Zusätzlich zur bestehenden Control-Plane-Projektion und zum bestehenden `grabowski_browser_worker_stored_form_action` führt dieser Change eine kleine, backend-neutrale Vertragsschicht in `src/grabowski_workers.py` ein: `browser_semantic_observe()` und `browser_semantic_act()`. Beide sind auf dem bestehenden Chrome/CDP-Adaptervertrag aufgebaut (`_run_node_browser_semantic`, ein eigenständiges, kleineres Node-CDP-Skript neben dem bestehenden Stored-Form-Skript) und in dieser Slice **nicht** als eigenständige `grabowski_browser_worker_*`-MCP-Tools exponiert. Sie sind internes Fundament für eine spätere Slice.

Die Vertragskonzepte:

- **BrowserObservation**: Ergebnis von `browser_semantic_observe()`. Enthält `worker_id`, einen opaken `snapshot_id`, `observed_at_unix` sowie semantische Felder (`origin`, `ready_state`, `title`). Keine rohen CDP-Methodennamen, keine Frame-/Loader-IDs, keine Cookies, keine Credentials. Der Worker-Preflight beobachtet systemd transient über `_observe()` und persistiert dabei weder Worker-State noch Reconciliation-/Lease-Cleanup.
- **snapshot_id**: unveränderlich und opak. Er wird aus einer begrenzten, internen Beobachtungsmenge (`origin`, `ready_state`, `title`, `main_frame_id`, `loader_id`, gebunden an `worker_id`) per SHA-256 deterministisch abgeleitet (`bsid1_<hex>`). Dieselbe begrenzte Beobachtung erzeugt immer denselben `snapshot_id`; jede Abweichung — auch nur eine neue `loader_id` nach einem Reload — erzeugt einen anderen.
- **BrowserIntent**: eine abstrakte Aktionsart aus einem festen Katalog (`read_state`, `scroll_into_view`), niemals eine CDP-Methode. Jede Aktionsart trägt fest eine Effektklasse.
- **BrowserAction**: ein Intent, gebunden an `worker_id` und den `snapshot_id`, den der Aufrufer beim Beobachten erhalten hat.
- **BrowserOutcome**: Ergebnis von `browser_semantic_act()`. Enthält `ok`, `result_code`, die angeforderte sowie die tatsächlich beobachtete Pre-/Post-Snapshot-ID und eine frische `observation` (BrowserObservation).

Effektvokabular (`BROWSER_EFFECT_CLASSES`): `read`, `local_ui`, `reversible_external`, `external_mutation`, `high_impact`. Diese Slice implementiert ausschließlich `read` und `local_ui` (`BROWSER_EFFECT_CLASSES_IMPLEMENTED`). Jede Aktionsart, deren Effektklasse nicht implementiert ist, scheitert fail-closed mit `result_code="effect_not_implemented"`, ohne dass ein Effekt versucht wird. Es gibt in dieser Slice keine Aktionsart mit `reversible_external`, `external_mutation` oder `high_impact` im Katalog; das Vokabular ist ausschließlich für zukünftige Slices vorbereitet.

Zustandsbindung und Fail-Closed-Kontrakt: `browser_semantic_act()` bindet jede Aktion an `worker_id` + `snapshot_id`. Unmittelbar vor jedem Effekt beobachtet er den Worker erneut autoritativ. Weicht der frisch berechnete `snapshot_id` vom angeforderten ab, scheitert die Aktion mit dem stabilen `result_code="stale_snapshot"`, und es wird kein Effekt ausgeführt — unabhängig davon, ob die Aktionsart `read` oder `local_ui` ist. Für `local_ui` wird der gerade bestätigte begrenzte Pre-State zusätzlich an denselben Adapteraufruf gebunden, der den Effekt ausführt; der Adapter liest diesen Zustand nochmals und verweigert den Effekt mit `stale_snapshot`, falls zwischen Python-Precheck und Adaptereffekt Drift eingetreten ist. Nach jedem tatsächlich ausgeführten Effekt erfolgt eine erneute autoritative Beobachtung, aus der das `BrowserOutcome` seine Post-Snapshot-ID bezieht.

### Nichtbehauptungen dieser Slice

- Es wird **keine** generische externe Übermittlung implementiert (kein Formular-Submit, kein `reversible_external`/`external_mutation`/`high_impact`-Effekt).
- Es werden **keine** Credentials gelesen, geschrieben oder verarbeitet.
- Es gibt **keine** Navigation zu beliebigen entfernten Zielen; die einzige lokale UI-Aktion ist `scroll_into_view` auf einen bereits sichtbaren, selektorgebundenen Origin-eigenen Zustand.
- `grabowski_browser_worker_stored_form_action` bleibt vollständig unverändert: eigenes Node-Skript, eigene Bestätigungs-/Origin-/Remote-IP-Prüfungen, eigene Result-Codes. Der neue semantische Vertrag teilt sich keine Zustands- oder Vertrauensautorität mit ihm.
- Diese Slice exponiert `browser_semantic_observe()`/`browser_semantic_act()` **nicht** als MCP-Tools und schreibt für sie **keine** neuen Audit-Kettensätze; das bleibt einer folgenden Slice vorbehalten.
- `read_state` führt keinen zweiten CDP-Roundtrip aus; die Pre-Action-Beobachtung dient zugleich als Post-Action-Beobachtung, da eine reine Lesung keinen weiteren Zustand erzeugt.
- Die begrenzte Beobachtungsmenge enthält keine Scroll-Position, keinen DOM-Inhalt und keine Sichtbarkeitsdetails; eine `scroll_into_view`-Aktion kann daher denselben `snapshot_id` vor und nach dem Effekt erzeugen, wenn Origin, Ladezustand, Titel, Frame und Loader unverändert bleiben. Das ist beabsichtigt: die aktuelle Slice bindet Navigation-/Reload-Zustand und schließt das beobachtbare Precheck→Adapter-TOCTOU-Fenster, behauptet aber noch **keine** DOM-weite Snapshot-Identität oder opaken Element-IDs.

## WebDriver BiDi / Firefox

`webdriver-bidi` ist in v1 nur als **nicht implementierter Zukunftsadapter** modelliert. Das ermöglicht eine zweite Engine hinter derselben semantischen Control-Plane, ohne Session-, Profil-, Lease-, Outcome- oder Auditautorität neu zu entwerfen.

Bis ein eigener BiDi-Adapter mit separaten Tests und Runtime-Acceptance existiert:

- Firefox ist kein Browser-Worker-Backend;
- eine Allowlist-Erweiterung allein aktiviert Firefox nicht;
- der Start scheitert explizit und fail-closed;
- es wird keine Funktionsgleichheit zu Chrome/CDP behauptet.

## Runtime-Grenze dieses Changes

Die Repository-Implementierung ändert ausschließlich:

- `src/grabowski_workers.py`
- `tests/test_workers.py`
- dieses Dokument.

Der Repository-PR selbst erzeugt keine Runtime-Wirkung. Der Bureau-Task ist jedoch erst nach dem revisionsgebundenen Merge **und** der anschließenden Live-Abnahme auf dem exakt gemergten Grabowski-Head abgeschlossen. Die Live-Abnahme muss mindestens belegen:

1. Deployment auf den exakten gemergten Grabowski-Head;
2. einen frischen Chrome-Stable-Worker über den neuen Adaptervertrag;
3. loopback-only CDP- und Control-Plane-Readback;
4. terminalen Stop und exakte Freigabe von Port-/Profil-Leases;
5. per separatem Readback, dass der menschliche Desktop-Default weiterhin Brave ist.

Deployment und Live-Abnahme laufen ausschließlich über die dafür vorgesehenen typisierten Grabowski-Operatorpfade. Der Task autorisiert keine Änderung des Desktop-Default-Browsers, keine Nutzung des menschlichen Standardprofils und keine Exposition des Debugging-Endpunkts über Loopback hinaus.
