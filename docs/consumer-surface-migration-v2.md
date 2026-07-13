# Consumer Surface v2 – Migrationsvertrag

Stand: 2026-07-13

## Zweck

Dieser Vertrag beschreibt die kompatible Weiterentwicklung der mit Consumer Surface v1 eingeführten Antwortformen. Er richtet sich an Clients, Tests und Operatorprogramme, die Antworten oder Durable-Job-Evidence strukturiert auswerten.

## Sichtnamen

Die kanonischen Sichten bleiben:

- `minimal`;
- `standard`;
- `evidence`.

Die bisherigen Aliasse bleiben gültig:

- `concise` → `minimal`;
- `full` → `evidence`.

Neue Clients sollen die kanonischen Namen senden und das zurückgegebene Feld `view` auswerten.

## Antwortschemata

`schema_version` versioniert die konkrete Antwortform einer Oberfläche, nicht das gesamte Grabowski-Protokoll. Ein Client muss deshalb pro Werkzeug und Antwortobjekt auf die angegebene Schemaversion reagieren.

Für Consumer-Antworten mit Schema 2 gilt:

- Warnungen, nächste Aktion und Top-Level-Nichtaussagen bleiben bei Feldprojektion erhalten;
- unbekannte Projektionsfelder werden abgewiesen;
- `evidence` darf Detailblöcke durch Hash, Anzahl und eindeutige Referenz entduplizieren, sofern die vollständige prüfbare Information an anderer Stelle derselben Antwort oder im versionierten Vertrag vorhanden bleibt.

`grabowski_context(view="evidence")` liefert den erwarteten Werkzeugvertrag deshalb als Anzahl und SHA-256 statt als zweite vollständige Namensliste. Die kompakte Capability-Liste bleibt vollständig nach Werkzeug, Kategorie und Risikoklasse.

## Cursor

Cursor bleiben an Oberfläche, Sicht, Filter und gegebenenfalls Snapshot gebunden. Sie besitzen absichtlich keine Zeitablaufsemantik, weil sie keine Autorisierung darstellen.

Bei einer Änderung des Snapshot-Hashes antwortet der Server mit dem stabilen Fehlerpräfix `cursor_snapshot_changed:` und fordert zum Neustart ab Seite eins auf. Clients dürfen einen solchen Cursor nicht unverändert wiederholen. Ein Sicht- oder Filterwechsel bleibt dagegen ein normaler Scope-Mismatch.

## Durable Jobs

Neu gestartete Durable Jobs verwenden Metadaten-Schema 2. Es ergänzt:

- `origin`: den normalisierten Startvertrag;
- `origin_sha256`: den Hash dieses Vertrags;
- `invoker_tool`: das typisierte Werkzeug, das den Job gestartet hat.

Der Origin-Hash wird vor dem Start berechnet und zusätzlich in die systemd-Unit-Umgebung geschrieben. Der Stop-Finalizer akzeptiert ein Schema-2-Receipt nur, wenn Metadaten, Unitname, Werkzeug und die beim Start gesetzte Hash-Precondition übereinstimmen.

Der Jobstatus trennt den Ausgang des Hauptprozesses von der aggregierten systemd-Unit. Schlägt nur `ExecStopPost` fehl, bleibt `final_status="succeeded"`, während `terminalization_evidence.postflight_evidence.state="failed"` den Finalizer-/Postflightfehler sichtbar hält.

Alte Job-Metadaten ohne Origin-Vertrag bleiben lesbar. Der Legacy-Pfad wird nur verwendet, wenn weder Origin-Metadaten noch eine Launcher-Precondition vorhanden sind. Ein teilweise vorhandener Origin-Vertrag scheitert geschlossen. Schema-2-Receipts sind ausschließlich für kanonische zwölfstellige Hex-Job-IDs zulässig; nichtkanonische historische Namen bleiben auf Schema 1 beschränkt.

## Outbox-Receipts und Acknowledgements

Neue Notification-Receipts und Acknowledgements verwenden Schema 2 und binden zusätzlich:

- `origin_sha256`;
- `invoker_tool`;
- beim Receipt `origin_binding` und `trust_boundary`.

Unbekannte zusätzliche Felder werden auch bei neu berechnetem Selbsthash abgewiesen. Alte Schema-1-Receipts bleiben auf ihrem bisherigen exakten Feldvertrag lesbar und quittierbar.

`notify_on_done` beschreibt jetzt die tatsächliche lokale Funktion:

- nicht angefordert: `delivery_mode="none"`, `delivery_enabled=false`;
- angefordert: `delivery_mode="operator_outbox"`, `delivery_enabled=true`.

Dies belegt keine externe Pushzustellung und nicht, dass der Nutzer die Nachricht gesehen hat.

## Vertrauensgrenze

Durable Jobs laufen derzeit als autorisierte lokale Prozesse desselben Benutzers. Der Launcher-Origin-Vertrag erkennt nachträgliche Metadatenänderungen nur, solange die Startprecondition nicht ebenfalls vom Angreifer kontrolliert wird. **Er ist keine Isolation.** Kontrolliert ein kompromittierter Same-UID-Prozess Metadaten und Finalizer-Precondition gemeinsam, kann er einen konsistent gefälschten Origin-Vertrag herstellen.

Vollständig untrusted Code benötigt eine eigene Sicherheitsdomäne, beispielsweise einen getrennten Benutzer, root-eigenen Broker, Container oder eine MicroVM. Consumer Surface v2 behauptet diese Grenze nicht. Der adversariale Vertragstest hält diese Nichtaussage absichtlich ausführbar fest.

## Breaking für neue Clients

Für bereits vorhandene Schema-1-Leser bleibt der Lesepfad kompatibel. Neue oder auf Schema 2 migrierte Clients müssen jedoch folgende Änderungen als verbindlich behandeln:

- `notify_on_done.requested=true` bedeutet eine lokale Outbox-Funktion und nicht mehr `metadata_only`;
- Schema-2-Receipts und Acknowledgements besitzen exakte Feldmengen und werden bei unbekannten Feldern abgewiesen;
- Schema-2-Receipts erfordern kanonische zwölfstellige Hex-Job-IDs;
- Snapshotwechsel liefern das stabile Fehlerpräfix `cursor_snapshot_changed:`;
- `context(evidence)` bindet den Werkzeugvertrag über Anzahl und SHA-256 statt über eine zweite vollständige Namensliste.

## Client-Snapshot

Ein Server-Deploy aktualisiert keinen bereits eingefrorenen clientseitigen Werkzeug-Snapshot. Nach einer Änderung des serverseitigen Werkzeugvertrags muss der Client seinen Snapshot über den jeweiligen Plattformmechanismus erneuern. Der Server kann diese Aktualisierung nur als nicht beobachtbar kennzeichnen.

## Umstellungsreihenfolge

1. Kanonische Sichtnamen senden und `view` auswerten.
2. Pro Antwortobjekt `schema_version` prüfen.
3. Bei Snapshotwechsel die Pagination von vorne beginnen.
4. Für Evidence nicht auf eine zweite vollständige `expected_tools`-Liste bestehen; Anzahl und Hash gegen den versionierten Vertrag prüfen.
5. Bei Durable Jobs Origin- und Trust-Boundary-Felder anzeigen, aber nicht als Untrusted-Isolation interpretieren.
6. Schema-1-Jobs weiterhin lesen; neue Mutationen und Tests auf Schema 2 ausrichten.
