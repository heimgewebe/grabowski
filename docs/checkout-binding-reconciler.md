# Checkout-Binding-Reconciler

Der Checkout-Binding-Reconciler vergleicht durable Lifecycle-Bindings read-only mit aktuell beobachteten Git-Worktree-Records.

## Zustände

- `bound_present`: Binding und Worktree-Identität stimmen überein.
- `orphaned_binding`: Das Repository ist beobachtbar, aber für das Binding existiert kein aktueller Git-Worktree-Record.
- `repository_unobservable`: Der Repository-Zustand konnte nicht autoritativ beobachtet werden.
- `binding_identity_drift`: Checkout-Key, Common-Dir, Repository-Pfad, Checkout-Pfad, Branch oder terminaler Head widersprechen sich.

## Sicherheitsvertrag

Die Projektion ist rein beobachtend. Insbesondere begründen weder ein fehlender Worktree noch Retention- oder Archiv-Evidenz eine Berechtigung zu:

- Archivierung,
- Cleanup,
- Binding-Löschung,
- Branch-Löschung,
- automatischer Terminalisierung oder
- Reparatur fremder Bindings.

Aktive Bindings ohne Worktree bleiben blockierend. Terminale Head-Identität wird exakt geprüft; Head-Bewegung in `active` bleibt zulässig. Ergebnisse sind deterministisch sortiert und Evidenz ist begrenzt.

Die Komponente stellt zunächst den reinen Reconciliation-Kern bereit. Runtime- und Current-Work-Oberflächen dürfen ihn nur ergänzend einbinden und müssen regulär projizierte Checkouts deduplizieren.
