# Grabowski Lifecycle Collectors v1

## Zweck

Dieser Slice ergänzt `GRABOWSKI-OPERATOR-SURFACE-V1-T071` um eine rein read-only Adaptergrenze zwischen bereits ausgeführten typisierten Grabowski-Readbacks und der hashgebundenen Lifecycle-Klassifikation.

`grabowski_lifecycle_collectors` führt selbst keine Task-, Git-, tmux-, Prozess-, Lease-, Checkout- oder Workspace-Mutation aus. Insbesondere ruft der Collector keine Statusfunktion auf, deren Beobachtung nebenbei persistente Taskzustände reconciliert. Der aufrufende Operator führt die benötigten Readbacks zuerst über die dafür vorgesehenen typisierten Oberflächen aus und übergibt deren Ergebnisse anschließend als `SourceReadback`.

## Sieben gebundene Quellen

Eine vollständige Klassifikation bindet weiterhin exakt die in T071 vorgesehenen Quellen:

- `task`
- `workspace`
- `lease`
- `checkout`
- `process`
- `tmux`
- `receipt`

`observed=True, payload=None` bedeutet eine ausdrücklich beobachtete Abwesenheit. Eine fehlende Quelle oder `observed=False` bedeutet dagegen, dass diese Wahrheit nicht geprüft wurde; die Klassifikation wird fail-closed `ambiguous`.

Jeder beobachtete Readback wird auf eine kleine deterministische Projektion reduziert und separat per SHA-256 gebunden. Die daraus entstehenden Source-Digests fließen unverändert in den bestehenden `evidence_sha256` ein. Änderungen an einem relevanten Readback ändern damit auch die gebundene Lifecycle-Evidenz.

## Fail-Closed-Regeln

### Tasks

Ein direkt gelesener Taskdatensatz kann unmittelbar gebunden werden. Wird dagegen eine paginierte Taskliste übergeben und die Ziel-ID ist nicht enthalten, gilt Abwesenheit nur dann als belegt, wenn `snapshot_complete=true` und `pagination.has_more=false` sind. Eine partielle Seite darf niemals aus "nicht gefunden" auf "nicht vorhanden" schließen.

Bei terminalen Tasks muss der Receipt-Readback einen gültigen `lifecycle_receipt_sha256` enthalten, der exakt dem im Task-Readback beobachteten Digest entspricht. Fehlende oder widersprüchliche Receipts führen zu `recovery_required`, nicht zu einer stillen Archivfreigabe.

### Leases

Bounded `resource_list`-Ergebnisse sind für den Nachweis der Abwesenheit einer exakten Lease unzureichend. Für jeden in `exact_resource_keys` verlangten Schlüssel erwartet der Collector daher einen einzelnen exakten Inspection-Readback nach dem Modell von `grabowski_resource_inspect`, einschließlich des expliziten Falls `lease=null`.

Fehlt eine solche exakte Inspection, bleibt die Klassifikation `ambiguous`. Eine nicht abgelaufene exakte Lease führt zu `blocking` beziehungsweise wird mit anderen aktiven Evidenzen konservativ zusammengeführt.

### Checkouts und Retentionen

Checkout-Evidenz wird aus dem deterministischen Checkout-Inventar gelesen. Dirty-Zustände bleiben `untouchable`. Aktive Prozesse, Tasks oder Resource-Leases aus der Checkout-Koordination werden zusätzlich als lebende Evidenz berücksichtigt.

Eine fremde aktive Retention bleibt `untouchable`. Eine abgelaufene fremde Retention wird nicht als frei behandelt: Ohne passendes Recovery-Archiv bleibt sie `recovery_required`. Ein passendes Checkout-Archiv ist dabei ausschließlich Recovery-Evidenz für die Retention und wird nicht als Beweis missverstanden, dass das Lifecycle-Objekt selbst bereits archiviert ist.

### Workspaces

Für Workspace-Archivierung reicht der normale Workspace-Status allein nicht aus. Zusätzlich ist das aktuelle Cleanup-Inventar erforderlich, damit Shared-Workspace-Referenzen und unvollständige Reference-Scans fail-closed berücksichtigt werden können.

Offene Rollen bleiben `active`; offene Shared-Referenzen bleiben `untouchable`; unvollständige Reference-Scans bleiben `ambiguous`. Ein geschlossener Workspace benötigt außerdem einen zum Status passenden gültigen Close-Receipt.

### Prozesse und tmux

Eine vom Checkout-Inventar gelieferte, bereits zielgebundene Prozessliste kann direkt gebunden werden. Für das allgemeine `grabowski_process_list`-Format ist zusätzlich ein exakter `process_scope` erforderlich, der dem Readback-Pattern entsprechen muss. Ein ungebundener globaler Prozessscan darf Abwesenheit nicht beweisen.

Persistierte `pane_ids` aus einem Workspace-Manifest gelten nicht als Live-Rollenbindung. Der Collector interpretiert nur ein ausdrücklich beobachtetes `role_bound=true` als aktuelle Rollenbindung. Eine lebende tmux-Session ohne aktive Rolle oder Prozess bleibt dadurch `ambiguous` statt fälschlich aktiv oder archivierbar.

## Wirkung und Grenzen

Der Collector liefert eine Klassifikation, ihre Source-Projektionen und die gebundene Evidenz zurück. `mutation_performed` bleibt immer `false`.

Der Collector begründet ausdrücklich nicht:

- dass die Quellen nach der Beobachtung unverändert geblieben sind;
- Effekt- oder Löschautorität;
- die fortbestehende Gültigkeit einer Lease;
- die Berechtigung, fremde Retentionen zu überschreiben.

Vor einem späteren Effekt bleibt deshalb die bereits implementierte unmittelbare Revalidierung des T071-Effektplans erforderlich. Physisches Löschen historischer Evidenz bleibt außerhalb von T071.
