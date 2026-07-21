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

## Effect Plan, Revalidation und create-only Execution Receipts

`build_effect_plan()` bindet einen geplanten Lifecycle-Effekt an die exakten Evidence- und Quell-SHA-256-Digests der betroffenen Identitäten sowie an die erforderlichen typisierten Ressourcen. `revalidate_effect_plan()` prüft diese Bindungen unmittelbar vor einem Effekt erneut gegen aktuelle Klassifikation und exakte Lease-Beobachtungen. Weder Plan noch Revalidation führen selbst eine Mutation aus.

`build_effect_execution_receipt()` erzeugt anschließend ausschließlich den unveränderlichen Beleg für einen bereits beobachteten Effektversuch. Das Receipt bindet Plan, Revalidation, Source-Bindings, Lease-Bindings und Post-State-Digests. Ein bestätigter Erfolg ist nur mit verifiziertem Post-State zulässig. Ein unbekannter Transportausgang oder ein bestätigter Fehler nach möglicher beziehungsweise erfolgter Mutation wird zwingend als `recovery_required` klassifiziert und benötigt mindestens eine konkrete Recovery-Referenz; `blind_retry_allowed` bleibt immer `false`.

`write_effect_execution_receipt()` persistiert create-only unter einer aus der Execution-ID abgeleiteten Identität und ist nur für exakt denselben Plan-/Revalidation-/Receipt-Inhalt idempotent wiederholbar. Ein gleichnamiger widersprüchlicher Beleg schlägt fail-closed fehl. Writer und Verifier verlangen die Ursprungsbelege erneut, sodass ein selbstkonsistent neu gehashter Receipt-Body keine fremde Plan- oder Source-Bindung vortäuschen kann. Das Receipt selbst führt keinen Effekt aus und begründet weder Löschautorität noch abgeschlossene Recovery.

## Noch getrennte Integrationsarbeit

Für den vollständigen T071-Abschluss fehlen nach diesem Core noch:

- Ausführungsadapter, die den bereits belegten Plan/Revalidation/Receipt-Vertrag tatsächlich umsetzen, ohne Blind-Retry zu erlauben;
- persistente Workspace-Archive und Retention-Konvergenz;
- atomare beziehungsweise recovery-sichere Umstellung der aktiven Taskprojektion nach Segmentverifikation;
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

## Typisierte Archiv-Leseoberflächen

`grabowski_task_archive_list` stellt einen bounded, paginierten Katalog der unveränderlichen Task-Archivsegmente bereit. Der Katalog akzeptiert ausschließlich kanonische `segment-<sha-prefix>`-Verzeichnisse, blockiert Symlinks und unerwartete Root-Einträge und verifiziert für den gesamten bounded Katalog die Manifest-Selbsthashes, Segmentidentitäten und Record-Hashsequenz-Metadaten. Der Cursor bindet die verifizierten Manifestidentitäten des gesamten Katalogs; Änderungen am Katalog invalidieren bestehende Cursor. Die Katalogoberfläche kennzeichnet ausdrücklich, dass die eigentlichen `records.jsonl`-Payloads zu diesem Zeitpunkt noch nicht vollständig verifiziert wurden.

`grabowski_task_archive_read` liest genau ein kanonisch identifiziertes Segment. Vor Ausgabe eines Records wird das komplette Segment innerhalb einer serverseitigen Byte-Obergrenze mit `verify_task_archive_segment` geprüft. Erst danach werden die Records paginiert ausgegeben. Der Cursor ist an Segment-ID, View und Manifest-SHA gebunden.

Beide Oberflächen sind reine Read-Tools mit `file_read`-Capability. Sie nehmen keinen frei wählbaren Dateipfad entgegen, ändern weder Archive noch Taskstore und begründen insbesondere keine Löschautorität oder aktuelle Projektionsmitgliedschaft. Physisches Pruning historischer Evidenz bleibt weiterhin außerhalb von T071.
