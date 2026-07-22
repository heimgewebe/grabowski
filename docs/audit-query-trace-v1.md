# Audit Query / Trace v1

## Zweck

Die Grabowski-Audit-Kette bleibt die unveränderliche, manipulationsnachweisende Beweisschicht. Audit Query / Trace v1 legt darüber ausschließlich eine verwerfbare Read-only-Projektion. Die Projektion besitzt keine eigene Autorität und kann jederzeit aus der vollständig verifizierten Segmentkette neu aufgebaut werden.

## Wahrheitsmodell

1. Vor jeder Projektion wird die bestehende segmentübergreifende Audit-Leseroutine unter dem gemeinsamen Audit-Koordinationslock verwendet.
2. Aktives Segment und alle Vorgängersegmente werden durch die bestehende Audit-Verifikation geprüft.
3. Ergebnisse werden in historischer Reihenfolge normalisiert und an Record- sowie Segment-SHA-256 gebunden.
4. Ein `chain_fingerprint_sha256` bindet die konkrete Segmentfolge, aus der ein Ergebnis abgeleitet wurde.
5. Es wird kein zweiter persistenter Index und keine zweite Wahrheit geschrieben.

Ein Query- oder Trace-Ergebnis beweist damit, aus welcher verifizierten Audit-Evidenz es abgeleitet wurde. Es beweist nicht automatisch, dass die protokollierte Handlung fachlich korrekt war oder dass zwei korrelierte Records kausal zusammenhängen.

## Oberflächen

### `grabowski_audit_query`

Begrenzte Suche über sichere, explizit freigegebene Record-Felder.

Unterstützte Filter:

- `operation`
- `operation_prefix`
- `task_id`
- `owner_id`
- `transaction_id`
- `host`
- `unit`
- `authoritative_unit`
- `path`
- `repo`
- `service`
- `branch`
- `resource_key`
- `record_sha256`
- `since_unix`
- `until_unix`
- `has_failure_signal`

Ergebnisse sind standardmäßig absteigend sortiert und auf maximal 200 Records begrenzt. Filter werden vollständig validiert, bevor die Audit-Kette gelesen wird; `record_sha256` akzeptiert ausschließlich exakt 64 kleingeschriebene Hexzeichen und ein Zeitfenster mit `since_unix > until_unix` wird abgewiesen.

### `grabowski_audit_trace`

Erzeugt einen begrenzten Ein-Hop-Korrelationspfad ausgehend von einem exakten Anker.

Unterstützte Anker:

- `record_sha256`
- `task_id`
- `owner_id`
- `transaction_id`
- `resource_key`
- `unit`
- `path`

Direkte Treffer werden markiert. Weitere Records werden nur dann aufgenommen, wenn sie einen aus den direkten Treffern abgeleiteten stabilen Korrelationsschlüssel teilen. Verwendet werden Task-, Owner-, Transaktions-, Unit-, Pfad-, Repo-, Branch- und Ressourcenbezüge.

Die Trace-Schicht behauptet ausdrücklich keine Kausalität. Sie ist eine Navigations- und Forensikhilfe. Korrelationswerte sind pro Feld auf 64 begrenzt; jede Kürzung wird mit `correlation_tokens_truncated` und der exakten Zahl ausgelassener Werte in `correlation_token_omissions` offengelegt.

### `grabowski_audit_analyze`

Berechnet ausschließlich deskriptive, neu erzeugbare Statistiken:

- häufigste Operationen,
- häufigste Ressourcenschlüssel,
- häufigste Task-IDs,
- häufigste Owner-IDs,
- Zeitbereich der ausgewählten Records,
- Anzahl und begrenzte Evidenzbeispiele für Fehlerindikatoren,
- `launcher_outcome_unknown`,
- `recovery_required`.

Die Analyse beweist weder Root Cause noch zukünftige Fehlerwahrscheinlichkeit.

## Sichere Projektion

Die öffentliche Projektion gibt nicht beliebige Audit-Felder zurück. Nur ein expliziter Allowlist-Satz struktureller Felder wird ausgegeben. Dadurch werden versehentlich in historischen Records enthaltene fremde oder sensitive Zusatzfelder nicht automatisch zu einer neuen Leseoberfläche.

Jeder projizierte Record enthält:

- `audit_ref`,
- den Evidenzhash des Records,
- Segmentpfad und Segment-SHA-256,
- Segment- und Record-Ordinal,
- globale Ordinalposition,
- die allowlist-basierte Record-Projektion.

Für Legacy-Records ohne gespeicherten `record_sha256` wird der SHA-256 der verifizierten Rohzeile als Evidenzreferenz verwendet.

## Fail-closed-Verhalten

Kann die bestehende Audit-Segmentkette nicht verifiziert oder sicher gelesen werden, wird keine Query-, Trace- oder Analyseantwort aus unbestätigten Daten erzeugt. Der Fehler der Audit-Verifikation wird weitergegeben.

## Nicht-Ziele

Audit Query / Trace v1 ist nicht:

- eine neue Audit-Datenbank,
- ein persistenter Suchindex,
- eine Policy-Engine,
- eine automatische Root-Cause-Engine,
- ein Berechtigungsnachweis für zukünftige Aktionen,
- ein Ersatz für Task-, Receipt-, GitHub-, Chronik- oder Bureau-Wahrheit.

Diese Systeme können später als getrennte Verbraucher oder als zusätzliche, explizit verifizierte Evidenzquellen angebunden werden. Die Audit-Kette bleibt dabei Provenienzanker, nicht semantische Gesamtwahrheit.
