# Checkout-Binding-Reconciler

Der Checkout-Binding-Reconciler vergleicht durable Lifecycle-Bindings read-only mit aktuell beobachteten Git-Worktree-Records.

## Runtime-Oberfläche

`grabowski_checkout_binding_reconciliation` liest die über `GRABOWSKI_CHECKOUT_DB` gebundene Checkout-Datenbank und vergleicht jedes Lifecycle-Binding mit der kanonischen Git-Inventarisierung aus `grabowski_checkouts`.

Die SQLite-Quelle wird nie migriert oder beschrieben. Ohne WAL wird die unveränderte Datenbank über `mode=ro&immutable=1` gelesen. Bei vorhandenem WAL erzeugt die bestehende kanonische Snapshot-Hilfe eine private gebundene Datenbank-plus-WAL-Kopie und verifiziert danach, dass beide Quelldateien unverändert geblieben sind. Schema-Version, Pflicht-Tabellen, Pflicht-Spalten und `integrity_check` werden vor der Projektion fail-closed geprüft.

Die Ausgabe ist auf höchstens 100 Datensätze je Seite begrenzt. Der Cursor ist an den vollständigen Datenbank- und Git-Snapshot gebunden; eine Änderung der Binding-Zeilen, Repository-Beobachtungen oder Fehlerprojektion macht einen alten Cursor ungültig.

## Zustände

- `bound_present`: Binding und Worktree-Identität stimmen überein.
- `archived_cleaned`: Das Repository ist beobachtbar, der Worktree fehlt und ein identitätsgleiches `archived`-Binding besitzt einen vollständigen Archive-Record mit `cleaned_at_unix` und `cleanup_plan_id`. Der Zustand ist terminal und nicht blockierend.
- `orphaned_binding`: Das Repository ist beobachtbar, aber für das Binding existiert weder ein aktueller Git-Worktree-Record noch vollständige Cleanup-Evidenz.
- `repository_unobservable`: Der Repository-Zustand konnte nicht autoritativ beobachtet werden.
- `binding_identity_drift`: Checkout-Key, Common-Dir, Repository-Pfad, Checkout-Pfad, Branch, Owner oder terminaler Head widersprechen sich. Bei archivierten Legacy-Retentions darf eine fehlende terminale Branch-/Head-Angabe nur dann als historische Auslassung gelten, wenn das Lifecycle-Binding und der immutable Archive-Record den konkreten Terminalwert exakt gemeinsam tragen; echte Widersprüche bleiben blockierend.

## Current Work und Attention

`bound_present` und `archived_cleaned` erzeugen keine zweite Current-Work-Zeile. Blockierende Reconciliation-Ergebnisse werden an eine bereits vorhandene `checkout:<key>`-Gruppe angehängt. Fehlt ein physischer Checkout ohne vollständige Cleanup-Evidenz, entsteht eine ungebundene `checkout-binding:<key>`-Gruppe. Historische, fehlende oder nur heuristische Bindings erscheinen in `grabowski_current_work` als `hygiene` und verdrängen keine positiv autoritäts- oder physisch gebundenen Gruppen auf begrenzten Seiten. Diese Projektion ist Aufmerksamkeitsevidenz, keine Checkout- oder Eigentumsautorität.

Die direkte Tool-Antwort enthält zusätzlich eine begrenzte `attention`-Projektion für die Datensätze der aktuellen Seite und `attention_total_count` für den vollständigen Snapshot. Sie erzeugt oder verändert keine dauerhafte Attention-Entscheidung.

## Sicherheitsvertrag

Die Projektion ist rein beobachtend. Seltene, belegte Reparaturen laufen getrennt über CAS-gebundene Lifecycle-Grips; der Reconciler selbst schreibt weiterhin nichts. Insbesondere begründen weder ein fehlender Worktree noch Retention- oder Archiv-Evidenz eine Berechtigung zu:

- Archivierung,
- Cleanup,
- Binding-Löschung,
- Branch-Löschung,
- automatischer Terminalisierung oder
- Reparatur fremder Bindings.

Aktive Bindings ohne Worktree bleiben blockierend. Checkout-Abwesenheit allein terminalisiert nichts. `archived_cleaned` verlangt zusätzlich einen identitätsgleichen Archive-Record, einen positiven Cleanup-Zeitpunkt und eine gebundene Cleanup-Plan-ID; unvollständige Cleanup-Evidenz oder ein weiterhin vorhandener Worktree werden blockierende Identitätsdrift. Fehlende Pflichtidentität, unbekannte Lifecycle-Phasen, fehlende Worktree-Keys und doppelte Checkout-Keys werden ebenfalls als `binding_identity_drift` behandelt; es gibt kein „last row wins“. Ein nicht gesetzter Branch bleibt zulässig, wenn Binding und Worktree darin übereinstimmen. Terminale Head-Identität wird exakt geprüft; Head-Bewegung in `active` bleibt zulässig. Ergebnisse sind deterministisch sortiert und Evidenz ist begrenzt.
