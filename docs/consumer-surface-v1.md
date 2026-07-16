# Grabowski Consumer Surface v1

Stand: 2026-07-16

## Zweck

Consumer Surface v1 trennt kurze Operatorantworten von vollständiger Audit-Evidenz. Die Oberfläche reduziert wiederkehrenden Kontext, ohne Blocker, Warnungen oder Unsicherheitsgrenzen auszublenden.

## Gemeinsamer Antwortvertrag

Unterstützte Sichten:

- `minimal`: Entscheidungskern, Pflichtwarnungen, nächste Aktion und Nichtaussagen;
- `standard`: kompakte Betriebs- und Diagnoseinformationen für den normalen Operatorlauf;
- `evidence`: vollständige prüfbare Detailformen für Audit, Review und Fehleranalyse.

Kompatibilitätsaliasse:

- `concise` entspricht `minimal`;
- `full` entspricht `evidence`.

Optionale Feldprojektion erhält zwingend:

- Schema und Sicht;
- Warnungen;
- empfohlene nächste Aktion;
- `does_not_establish`.

Unbekannte Felder werden abgewiesen.

## Pagination

Task-, Friction- und Checkout-Antworten unterstützen begrenzte Cursor-Pagination. Cursor sind gebunden an:

- Oberfläche;
- Sicht;
- Filter;
- Snapshot, sofern die Oberfläche einen Snapshot bildet.

Ein Cursor aus einer anderen Sicht oder Filterkombination wird abgewiesen. Ändert sich ein gebundener Snapshot, liefert die Fehlermeldung das stabile Präfix `cursor_snapshot_changed:` und fordert zum Neustart ab Seite eins auf. Cursor besitzen keine Ablaufzeit, weil sie keine Autorisierung darstellen. Mehrseitenläufe ohne Duplikate oder Lücken sind regressionsgetestet.

## Capability Profiles v2

Die Profile sind:

- `observe`: lesende Beobachtung;
- `maintain`: begrenzte Wartung;
- `trusted-owner`: bestehende volle beaufsichtigte Betreiberautorität.

Der Upgrader ergänzt `observe` und `maintain`, erhält das aktive Profil und verändert den bestehenden `trusted-owner`-Inhalt nicht. Apply ist an den gelesenen SHA-256 gebunden und ersetzt die Policy atomar.

Nicht daraus ableitbar:

- ein bereits geöffneter Client hat seine Werkzeugliste aktualisiert;
- neue Aktionsautorität wurde erteilt;
- ein Profilwechsel ist ohne explizite Policyänderung erfolgt.

## Durable Job Notification Outbox

Ein Job mit `notify_on_done.requested=true` erzeugt nach Terminalisierung ein privates, selbsthashgebundenes `notification.json`. Neue Jobs binden das Receipt zusätzlich an einen vor dem Unit-Start berechneten Origin-Hash und das typisierte Startwerkzeug.

Die Outbox kennt nur:

- `queued`;
- `acknowledged`.

Ack ist create-only, receipt-hashgebunden, idempotent und auditiert. Schema 2 verlangt exakte Receipt- und Ack-Felder sowie die Origin-Bindung; unbekannte neu gehashte Claims werden abgewiesen. Schema-1-Receipts bleiben lesbar und quittierbar. Manipulierte, falsch gebundene, verlinkte oder unsichere Receipts werden nicht als gültig behandelt.

Die Trust Boundary lautet `same_uid_authorized_job`: Die Bindung erkennt Metadatendrift gegenüber der systemd-Startprecondition, solange diese Precondition nicht ebenfalls kontrolliert wird. Sie ist ausdrücklich **keine Isolation** gegen kompromittierten Same-UID-Code.

Die Outbox behauptet ausdrücklich nicht:

- externe Pushzustellung;
- dass der Nutzer die Meldung gesehen hat;
- Job-Erfolg jenseits der Terminalisierungsevidenz.

## Core-Dump-Härtung

`LimitCORE=0` gilt für:

- den Operator-Service;
- Durable Jobs;
- Tasks;
- Worker.

Das Inventarwerkzeug ist rein lesend, ignoriert Symlinks, begrenzt Tiefe, Hashgröße und Fehlerausgabe und prüft Dateidentität während des Hashens. Es autorisiert keine Löschung.

## Wirkungsnachweis

Der versionierte Nachweis liegt unter:

- `docs/proofs/consumer-surface-v1-benchmark-20260712.md`;
- `docs/proofs/consumer-surface-v1-benchmark-20260712.json`.

Der Standardmodus reduziert die gemessenen Median-JSON-Bytes auf allen fünf großen Oberflächen um mindestens 50 Prozent. Der Evidence-Modus bleibt prüfbar, vermeidet aber doppelte vollständige Werkzeug- und Kontextlisten durch Count-, Hash- und Referenzbindung.

Der kompatible Migrationsvertrag liegt unter `docs/consumer-surface-migration-v2.md`.

## Connector-Snapshot und Systemübersicht

Serverseitiger Werkzeugvertrag und Client-Snapshot sind getrennte Wahrheiten. Ein Runtime-Deploy kann 141 Werkzeuge serverseitig belegen, ohne einen bereits geöffneten Client-Snapshot automatisch zu erneuern.

Der mutierende Grip `connector-snapshot-bind` vergleicht eine begrenzte clientseitige Erklärung mit dem aktuellen serverseitigen Werkzeug-, Release- und Instruktionsvertrag. Das Receipt ist privat, selbsthashgebunden und eine Stunde gültig. Der Vertrauensmodus lautet `client-declared-server-compared-v1`; er ist keine plattformseitige Attestierung des Clientprozesses.

Die Sichten `standard` und `evidence` enthalten zusätzlich `system_overview`. Diese kompakte Projektion liest Runtime-Integrität, Connector-Zustand, Task-Projektionen, aktive Leases und Operator-Verpflichtungen aus ihren bestehenden Quellen. Sie speichert keinen zweiten Status und setzt `operator_ready=false`, wenn eine notwendige Komponente nicht beobachtbar oder nur abgeschnitten lesbar ist. Bureau, GitHub/CI, RepoBrief, Systemkatalog und Chronik erscheinen als Quellenkarte mit ihrer Autorität und benötigten Zielbindung; ohne Zielidentität wird ihre Aktualität nicht behauptet.

Der vollständige Vertrag ist in `docs/connector-snapshot-handshake-v1.md` beschrieben.
