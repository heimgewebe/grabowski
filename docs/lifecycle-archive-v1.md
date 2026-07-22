# Grabowski Lifecycle Archive Core v1

## Zweck

Der Lifecycle-Archive-Core ist der konfliktfreie Kern von `GRABOWSKI-OPERATOR-SURFACE-V1-T071`.
Er trennt drei Dinge, die zuvor leicht vermischt wurden:

1. aktuelle Lifecycle-Klassifikation;
2. unveränderliche Archivierung terminaler Taskdatensätze;
3. eine begrenzte Standardprojektion, die nur handlungsrelevante Zustände zeigt.

Der Core löscht keine Task-, Workspace- oder Recovery-Belege. Physisches Pruning bleibt außerhalb des T071-Vertrags.

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

- `records.jsonl` mit kanonisch sortierten Task-Archivrecords;
- `manifest.json` mit Quellstore-Digest, Quellschema, Plan-Digest, Record-Anzahl, erstem und letztem Record-Hash, vollständiger Record-Hashfolge und Segment-SHA-256.

Dateien und Verzeichnisse werden fsync-sicher persistiert. Ein identisches Segment ist idempotent lesbar. Existierende widersprüchliche Segmente oder manipulierte Records schlagen fail-closed fehl.

Für produktive Task-Store-Archive definiert `grabowski_tasks._task_archive_record()` die stabile Record-Projektion. Sie ist bewusst unabhängig von später veränderbarer Redaktionslogik: Identität, Status, Ressourcen- und Terminalisierungsbindungen werden explizit gespeichert; dynamische oder potentiell sensible JSON-Payloads werden durch SHA-256-Digests gebunden. Dadurch kann die aktuelle Task-Projektion einen unveränderten Datenbankrecord auch nach einer späteren Änderung der Ausgaberadaktion zuverlässig gegen das Archiv prüfen.

Die Segmentarchivierung begründet ausdrücklich keine Erlaubnis, Records aus der Taskdatenbank zu löschen. Die aktive Projektion darf erst nach erfolgreicher Segmentverifikation umgestellt werden.

## Effect Plan, Revalidation und create-only Execution Receipts

`build_effect_plan()` bindet einen geplanten Lifecycle-Effekt an die exakten Evidence- und Quell-SHA-256-Digests der betroffenen Identitäten sowie an die erforderlichen typisierten Ressourcen. `revalidate_effect_plan()` prüft diese Bindungen unmittelbar vor einem Effekt erneut gegen aktuelle Klassifikation und exakte Lease-Beobachtungen. Weder Plan noch Revalidation führen selbst eine Mutation aus.

`build_effect_execution_receipt()` erzeugt anschließend ausschließlich den unveränderlichen Beleg für einen bereits beobachteten Effektversuch. Das Receipt bindet Plan, Revalidation, Source-Bindings, Lease-Bindings und Post-State-Digests. Ein bestätigter Erfolg ist nur mit verifiziertem Post-State zulässig. Ein unbekannter Transportausgang oder ein bestätigter Fehler nach möglicher beziehungsweise erfolgter Mutation wird zwingend als `recovery_required` klassifiziert und benötigt mindestens eine konkrete Recovery-Referenz; `blind_retry_allowed` bleibt immer `false`.

Ein Execution-Receipt darf nur einen Effektversuch belegen, dessen Startzeitpunkt strikt vor der frühesten im Revalidation-Beleg gebundenen Lease-Ablaufzeit liegt. Writer und Verifier erzwingen dieselbe Zeitgrenze; auch ein selbstkonsistent neu gehashter Receipt-Body mit zu spätem Start schlägt fail-closed fehl. Der Receipt-Abschluss darf für einen `recovery_required`-Ausgang nach dem Lease-Ablauf liegen, damit ein unbekannter Transport- oder Mutationseffekt weiterhin unveränderlich dokumentiert werden kann.

`write_effect_execution_receipt()` persistiert create-only unter einer aus der Execution-ID abgeleiteten Identität und ist nur für exakt denselben Plan-/Revalidation-/Receipt-Inhalt idempotent wiederholbar. Ein gleichnamiger widersprüchlicher Beleg schlägt fail-closed fehl. Writer und Verifier verlangen dieselben Ursprungsbelege und prüfen deren exakte Digest-Bindungen erneut. Das Receipt selbst führt keinen Effekt aus und begründet weder Löschautorität noch abgeschlossene Recovery.

## Recovery-sicherer Task-Archive Projection Switch

`apply_task_archive_projection_switch()` verändert nicht den Taskstore, sondern persistiert create-only einen Projektionsumschaltbeleg für ein bereits vollständig verifiziertes Archivsegment.

Der Switch ist gebunden an:

- Segment-ID und Segment-Identity-SHA-256;
- Manifest-, Segment-, Archivplan- und Quellstore-SHA-256;
- die vollständige Task-ID-zu-Record-SHA-256-Bindung des Archivsegments;
- einen `current_projection_switch`-Effect-Plan mit ausschließlich `archived` klassifizierten Identitäten;
- dessen unmittelbaren `ready_for_effect`-Revalidation-Beleg;
- die exakte Projection-Root-Ressource als gebundene Lease;
- einen `applied_at_unix`, der strikt vor der frühesten gebundenen Lease-Ablaufzeit liegt.

Die Mutation wird innerhalb eines exklusiven Directory-Locks serialisiert. Ein vorhandener identischer Switch ist idempotent. Mehrere Archivsegmente dürfen denselben Task nur dann projizieren, wenn sie exakt denselben Record-SHA-256 binden; ein abweichender Record-Hash wird vor dem zweiten Switch-Write abgelehnt. Jeder spätere `load_task_archive_projection()`-Readback verifiziert die Switch-Dateien und die referenzierten Archivsegmente erneut.

`bounded_current_task_projection()` blendet einen projizierten Task nur aus, wenn der aktuell vorgelegte Taskrecord bytekanonisch denselben SHA-256 wie der archivierte Record besitzt. Jede Record-Drift schlägt fail-closed fehl. Die Umschaltung löscht keine Taskzeile, kein Archiv und keinen Recovery-Beleg und begründet weiterhin keine physische Löschautorität.

Der erfolgreiche Switch liefert verifizierte Post-State-Digests für Archivmanifest, Switch und Gesamtprojektion. Diese Digests können unmittelbar in ein create-only Execution-Receipt übernommen werden. Scheitert ein späterer Schritt, bleibt der deterministische Switch als Recovery-Readback erhalten.

## Produktive Current-Task-Leseoberfläche

`grabowski_task_list` lädt vor jeder paginierten Ausgabe den verifizierten Task-Projection-Switch-State. Der Standardpfad ist damit die aktuelle Handlungsprojektion und nicht mehr die unverdichtete historische Datenbankansicht.

Für jeden projizierten Task wird innerhalb desselben SQLite-Read-Snapshots erneut der gespeicherte Taskrecord gelesen, in die stabile Archivprojektion überführt und gegen den im Archiv gebundenen Record-SHA-256 geprüft. Ein fehlender Taskrecord oder jede relevante Record-Drift blockiert die gesamte Leseoberfläche fail-closed. Die physische Taskzeile bleibt dabei erhalten.

Pagination und Counts folgen derselben Projektion:

- archivierte Records verbrauchen keinen Platz in einer Current-Page;
- `total_matching`, `state_counts` und `projection_counts` beziehen sich auf `current_projection`;
- der Cursor ist zusätzlich an `projection_sha256` gebunden;
- ändert sich die Projection zwischen zwei Seiten, wird der alte Cursor mit `cursor_snapshot_changed` abgelehnt;
- `current_projection` bleibt auch bei feldprojizierten Antworten als erforderliche Safety-Evidenz erhalten.

Die Archive- und Projection-Roots folgen expliziten `GRABOWSKI_TASK_ARCHIVE_ROOT`- beziehungsweise `GRABOWSKI_TASK_PROJECTION_ROOT`-Overrides. Ohne Override liegen sie neben der tatsächlich geöffneten `TASK_DB`; dadurch lesen isolierte Test- oder Recovery-Stores nicht versehentlich den produktiven Projection-State.

## Produktive Workspace-Archive- und Retention-Konvergenz

`grabowski_agent_workspace_cleanup` bindet seine bestehende zweiphasige Checkout-Lifecycle-Kette jetzt automatisch an den T071-Effect-Vertrag. Die bisherige sichere Archiv- und Cleanup-Implementierung bleibt dabei die einzige Git-Mutationslogik; T071 legt eine zusätzliche, getrennte Evidenz- und Autoritätsschicht darum.

Vor `workspace_archive` und `retention_converge` werden sieben Lifecycle-Quellen erneut gelesen und als `terminal_archivable` klassifiziert. Auch ein bereits vollständig geschlossener Workspace verlässt sich dabei nicht nur auf sein Close-Receipt: Rollen-Tasks, die Workspace-Ressourcen und die tmux-Sitzung werden frisch nachbeobachtet; sichtbare Live-Tasks, Ressourcen, Beobachtungsfehler oder eine weiter bestehende Sitzung blockieren bereits den Cleanup-Plan. Die separate Task-Quelle bindet die frischen Rollen-Readbacks, und die Lease-Quelle inspiziert jeden im Workspace-Manifest gebundenen Ressourcenkey exakt, sodass auch eine nach dem Close neu erschienene oder fremd übernommene Lease fail-closed blockiert. Der Effect Plan bindet diese Source-Digests und eine eigene `gate:workspace-lifecycle:<workspace_id>`-Lease. Diese Gate-Lease kollidiert absichtlich nicht mit den darunterliegenden exakten Checkout- und Git-Common-Dir-Leases, die `grabowski_checkouts` weiterhin unmittelbar um jede Git-Mutation hält. Plan und Revalidation werden create-only persistiert; erst danach beginnt der Effektversuch.

Die Archivphase verifiziert nach dem bestehenden `grabowski_checkout_archive` den gespeicherten Archive-Record, das Archive-Manifest und alle Recovery-Refs und schreibt dafür ein create-only `workspace_archive` Execution Receipt. Ein bereits vorhandenes älteres Checkout-Archiv kann ohne erneute Mutation durch denselben verifizierten Post-State als `mutation_state=not_performed` in die T071-Kette aufgenommen werden. Während der bestehenden Cleanup-Grace bleibt der Writer-Worktree erhalten.

Nach abgelaufener Grace bleibt der vorhandene Checkout-Cleanup-Dry-Run mit seinem eigenen `plan_sha256` die unmittelbare Löschautorität für den temporären Linked Worktree. Unmittelbar vor dem Apply wird zusätzlich `retention_converge` geplant und revalidiert. Erfolg ist erst belegt, wenn der Archive-Record `cleaned_at_unix` und `cleanup_plan_id` enthält, der Writer-Worktree fehlt und die Recovery-Refs weiterhin auflösbar sind. Beide Effect-Referenzen werden in das abschließende Workspace-Cleanup-Receipt übernommen; Workspace-Zustand und historische Belege werden nicht gelöscht.

Ein unklarer Effektversuch schreibt konservativ `recovery_required` mit `blind_retry_allowed=false`. Der Workspace-Cleanup-Intent wechselt dann ebenfalls auf `recovery_required`; ein weiterer normaler Cleanup-Aufruf wird durch `cleanup_recovery_required` blockiert. Ist nach einem unterbrochenen Retention-Apply der Worktree bereits weg und der Checkout-Archive-Record eindeutig als bereinigt verifiziert, wird die bestehende Missing-Worktree-Reconciliation durch einen neuen, rein lesenden `retention_converge`-Post-State-Beleg abgeschlossen, statt die Mutation blind zu wiederholen.

## Noch getrennte Integrationsarbeit

Für den vollständigen T071-Abschluss fehlen weiterhin:

- gegebenenfalls weitere Effektadapter auf demselben Plan/Revalidation/Receipt-Vertrag, ohne Blind-Retry zu erlauben;
- Deployment eines kohärenten T071-Heads und isolierter Livebeweis;
- abschließende Audit-Integritätsprüfung und Bureau-Closeout.

Das separat als Bureau-Candidate erfasste Directory-FD/openat-Hardening bleibt ein eigener Follow-up-Pfad. Es darf diese Safety-Grenzen weiter verkleinern, ist aber keine Erlaubnis, dirty, fremd geschützte, gemeinsam referenzierte oder uneindeutige Zustände anzufassen.

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
