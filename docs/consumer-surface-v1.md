# Grabowski Consumer Surface v1

Stand: 2026-07-12

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

Ein Cursor aus einer anderen Sicht oder Filterkombination wird abgewiesen. Mehrseitenläufe ohne Duplikate oder Lücken sind regressionsgetestet.

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

Ein Job mit `notify_on_done.requested=true` erzeugt nach Terminalisierung ein privates, selbsthashgebundenes `notification.json`.

Die Outbox kennt nur:

- `queued`;
- `acknowledged`.

Ack ist create-only, receipt-hashgebunden, idempotent und auditiert. Manipulierte, falsch gebundene, verlinkte oder unsichere Receipts werden nicht als gültig behandelt.

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

Der Standardmodus reduziert die gemessenen Median-JSON-Bytes auf allen fünf großen Oberflächen um mindestens 50 Prozent. Der Evidence-Modus bleibt bewusst vollständig.

## Betriebsgrenze

Serverseitiger Werkzeugvertrag und Client-Snapshot sind getrennte Wahrheiten. Ein Runtime-Deploy kann 120 Werkzeuge serverseitig belegen, ohne einen bereits geöffneten Client-Snapshot automatisch zu erneuern.
