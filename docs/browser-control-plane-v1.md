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

Ein Executable ohne implementierten CDP-Adapter wird vor Profilerzeugung und Workerstart abgewiesen. Eine bloße Aufnahme in `GRABOWSKI_BROWSER_EXECUTABLES` erzeugt also keine neue Protokollunterstützung.

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

Deployment und Live-Abnahme gehören in einen separaten Bureau-Nachfolgetask mit `runtime_mutation`-Freigabe. Dieser Nachfolgetask muss mindestens belegen:

1. Deployment auf den exakten gemergten Grabowski-Head;
2. frischen Chrome-Stable-Worker über den neuen Adaptervertrag;
3. loopback-only CDP-Readback;
4. terminalen Stop und exakte Freigabe von Port-/Profil-Leases;
5. unveränderten menschlichen Desktop-Default Brave.

Der Repository-Task selbst autorisiert keine Runtime-Wirkung und keine Änderung des Desktop-Default-Browsers.
