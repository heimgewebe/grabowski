# Grabowski Lifecycle Archive Core v1

## Zweck

Der Lifecycle-Archive-Core ist der konfliktfreie Kern von `GRABOWSKI-OPERATOR-SURFACE-V1-T071`.
Er trennt drei Dinge, die zuvor leicht vermischt wurden:

1. aktuelle Lifecycle-Klassifikation;
2. unveränderliche Archivierung terminaler Taskdatensätze;
3. eine begrenzte Standardprojektion, die nur handlungsrelevante Zustände zeigt.

Der Core löscht keine Task-, Workspace- oder Recovery-Belege und registriert noch keine neue MCP-Oberfläche. Diese Integration bleibt getrennt, solange zentrale Registrierungsdateien durch andere laufende Arbeiten exklusiv belegt sind.

## Einheitliche Klassifikation

`classify_lifecycle()` liefert genau eine der folgenden Klassen:

- `active`: laufende Task oder belegter lebender Prozess;
- `blocking`: nicht terminal oder durch eine aktive Lease blockiert;
- `recovery_required`: unklarer Taskausgang oder terminaler Zustand ohne gültige Receipt-Integrität;
- `terminal_archivable`: terminal beziehungsweise geschlossen, vollständig beobachtet und nicht blockiert;
- `archived`: ein gültiger Archivzustand ohne widersprechende Live-Evidenz;
- `ambiguous`: fehlende, fehlerhafte oder widersprüchliche Beobachtungen;
- `untouchable`: dirty Checkout, fremde Retention oder gemeinsame Workspace-Referenz.

Fehlende Beobachtungen werden nicht optimistisch interpretiert. Ein unbekannter Prozess-, Lease-, Dirty-, Retention-, Shared-Reference- oder Receipt-Zustand ergibt `ambiguous` und damit keine Archivierungsautorität.

## Bounded Current Projection

`bounded_current_projection()` behält standardmäßig nur:

- aktive;
- blockierende;
- recovery-pflichtige;
- mehrdeutige;
- unberührbare Zustände.

`terminal_archivable` und `archived` bleiben aus der aktuellen Standardansicht heraus, ohne historische Daten zu löschen. Drill-down auf Archivsegmente bleibt möglich.

## Task-Archivplan

`build_task_archive_plan()` ist wirkungsfrei. Ein Task wird nur als eligible aufgenommen, wenn:

- seine Lifecycle-Klasse `terminal_archivable` ist;
- die Mindestaufbewahrung abgelaufen ist;
- ein gültiger `lifecycle_receipt_sha256` vorliegt.

Der Plan bindet Task-IDs und die SHA-256-Digests der vollständigen Record-Projektionen. Eine Änderung des Quellrecords ändert den Plan-Digest.

## Immutable Archive Segments

`write_task_archive_segment()` erzeugt create-only:

- `records.jsonl` mit kanonisch sortierten vollständigen Taskrecords;
- `manifest.json` mit Quellstore-Digest, Quellschema, Plan-Digest, Record-Anzahl, erstem und letztem Record-Hash, vollständiger Record-Hashfolge und Segment-SHA-256.

Dateien und Verzeichnisse werden fsync-sicher persistiert. Ein identisches Segment ist idempotent lesbar. Existierende widersprüchliche Segmente oder manipulierte Records schlagen fail-closed fehl.

Die Segmentarchivierung begründet ausdrücklich keine Erlaubnis, Records aus der Taskdatenbank zu löschen. Die spätere aktive Projektion darf erst nach erfolgreicher Segmentverifikation umgestellt werden.

## Noch getrennte Integrationsarbeit

Für den vollständigen T071-Abschluss fehlen nach diesem Core noch:

- Live-Aggregation von Task-, Workspace-, Lease-, Checkout-, Prozess- und tmux-Evidenz in dieselbe Klassifikation;
- persistente Workspace-Archive und Retention-Konvergenz;
- atomare beziehungsweise recovery-sichere Umstellung der aktiven Taskprojektion nach Segmentverifikation;
- typisierte paginierte Archiv-Read-Oberflächen;
- MCP- und Capability-Katalog-Registrierung;
- Deployment und isolierter Livebeweis.

Diese Schritte dürfen die bestehenden Safety-Grenzen nicht lockern: dirty, fremd geschützt, gemeinsam referenziert oder uneindeutig bleibt unberührbar.

## Hashgebundene Live-Evidenzaggregation

`grabowski_lifecycle_evidence` normalisiert die sieben für T071 relevanten aktuellen Quellen `task`, `workspace`, `lease`, `checkout`, `process`, `tmux` und `receipt` in einen gemeinsamen Evidenzsnapshot. Eine Quelle gilt nur dann als beobachtet, wenn ihr aktueller Zustand explizit geprüft wurde; auch ein belegtes Nichtvorhandensein ist eine Beobachtung. Für jede beobachtete Quelle ist zusätzlich der SHA-256-Digest der normalisierten, redigierten Quellprojektion erforderlich. Fehlende Beobachtungen, fehlende Digests und Quellfehler werden als `ambiguous` klassifiziert und begründen keine Archivierungsautorität.

Die Aggregation bildet zusätzliche Safety-Fälle explizit ab:

- offene Workspace- oder Taskrollen bleiben `active`;
- aktive exakte Leases bleiben `blocking`;
- dirty Checkouts, Shared-Workspace-Referenzen und aktive fremde Retentionen bleiben `untouchable`;
- eine abgelaufene fremde Retention bleibt `recovery_required`, bis eine getrennte Recovery-Archivierung belegt ist;
- eine tmux-Session ohne lebende Rollen- oder Prozessbindung ist `ambiguous` und wird weder als aktive Arbeit noch als Cleanup-Freigabe interpretiert;
- unbekannte Prozess- oder systemd-nahe Beobachtungen bleiben fail-closed.

Der normalisierte Snapshot erhält einen eigenen `evidence_sha256`. Er ist read-only und begründet weder einen Effekt noch eine Aussage darüber, dass die Quellzustände nach der Beobachtung unverändert geblieben sind. Die spätere Effektplanung muss den Snapshot deshalb erneut gegen aktuelle Quellen und exakte Leases binden.
