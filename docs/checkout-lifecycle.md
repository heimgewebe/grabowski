# Checkout-Lifecycle

Grabowski verwaltet temporäre verlinkte Git-Checkouts als typisierte lokale
Ressourcen. Der Vertrag schützt Branches, erzeugt dauerhafte Recovery-Refs und
trennt Inventar, Archivierung und Cleanup.

## Werkzeuge

- `grabowski_checkout_inventory`: deterministische Sicht auf alle Worktrees
  eines Repositories, inklusive HEAD, Branch, Dirty-Status, Retention,
  durablem Lifecycle-Binding, jüngstem Archiv, aktiven Tasks, Prozessen und
  Resource-Leases.
- `grabowski_checkout_retain`: weist einem verlinkten Checkout einen
  expliziten Retention-Owner, Zweck und Ablaufzeitpunkt zu.
- `grabowski_checkout_archive`: archiviert einen sauberen verlinkten Checkout,
  indem es Recovery-Refs unter `refs/grabowski/checkouts/...` erzeugt und ein
  Manifest im Grabowski-State schreibt.
- `grabowski_checkout_cleanup`: erzeugt zuerst einen persistierten Dry-Run-Plan
  und führt erst danach, mit Plan-ID und Plan-Hash, `git worktree remove` ohne
  Force-Option aus.

## Inventar-Markierungen

`grabowski_checkout_inventory` klassifiziert jeden Worktree mit
`lifecycle_state`, `hygiene_mark` und einer `lifecycle_decision`. Diese
Markierung ist read-only Evidenz. Sie autorisiert weder Cleanup noch
Branch-Löschung.

| Markierung | Typische States | Bedeutung |
| --- | --- | --- |
| `primary` | `main` | Haupt-Worktree; nie temporärer Cleanup-Kandidat. |
| `dirty` | `dirty` | Änderungen oder untracked Dateien vorhanden; erst reviewen oder retainen. |
| `retained` | `retained`, `completed_retained`, `completed_retained_blocked` | Aktive managed Arbeit ist wirksam retained; terminale managed Arbeit bleibt bis zur Archivierung explizit sichtbar. |
| `archived` | `archived_grace`, `archived_blocked` | Eine konsistente `phase=archived`-Bindung besitzt ein passendes offenes Recovery-Archiv; Grace oder aktive Koordination blockieren Cleanup. |
| `obsolete` | `cleanup_candidate`, `prunable_or_missing` | Nur lokal gemeint: ein sauberer Checkout hat ein passendes offenes Recovery-Archiv und braucht vor Apply trotzdem einen Dry-Run; oder Git meldet den Worktree als prunable/missing. |
| `unknown` | `unclassified_clean`, `managed_active_attention`, `managed_lifecycle_drift`, `archive_drifted`, `archive_closed`, `blocked_unarchived`, `unobservable` | Lokale Evidenz reicht nicht für eine sichere Lifecycle-Entscheidung. `unclassified_clean` bleibt unmanaged oder legacy; managed Retention-Ablauf und Identitätsdrift werden ausdrücklich blockierend. |

Die Entscheidung enthält zusätzlich:

- `binding_present`, `binding_phase`, `binding_consistent` und begrenzte
  `binding_drift_reasons`,
- `retention_active` und `retention_owner_id`,
- `archive_present`, `archive_open` und `archive_matches_checkout`,
- `coordination_blocking`,
- `cleanup_candidate`,
- `requires_cleanup_dry_run`,
- `recommended_next_step`,
- `does_not_establish`.

## Managed Binding-Konvergenz

Eine vorhandene managed Binding-Zeile wird gegen Checkout-Key,
Repository/Common-Dir, Checkout-Pfad und Branch geprüft. Für terminale Phasen
muss zusätzlich die maßgebliche HEAD-Identität stimmen. Binding und Retention
müssen demselben Owner und derselben Checkout-Identität entsprechen.

Die Phasen werden read-only wie folgt projiziert:

- `active` mit wirksamer Retention bleibt `retained`.
- `active` ohne wirksame Retention wird `managed_active_attention` und fällt
  nicht auf `unclassified_clean` zurück.
- `completed_retained` bleibt als terminal-retained und
  archivierungspflichtig sichtbar.
- `archived` gelangt nur mit passendem offenem Recovery-Archiv in
  `archived_grace`, `archived_blocked` oder `cleanup_candidate`.
- Unbekannte Phase oder widersprüchliche Path-, Repository-, Branch-, Owner-,
  Head-, Retention- oder Archivdaten werden `managed_lifecycle_drift`.

`grabowski_current_work` übernimmt Phase und Konsistenz als autoritative
Checkout-Evidenz. Nur ein konsistentes Binding darf zugleich die exakte
Owner-Zuordnung des Checkouts begründen. Ein widersprüchliches Binding bleibt
blockierende Drift-Evidenz, wird aber weder als Owner-Autorität noch als
terminale Konvergenzautorität verwendet. Konsistente aktive Bindungen bleiben
aktiv; abgelaufene managed Bindungen blockieren; `completed_retained` und
`archived` werden als `closed-not-cleaned` priorisiert, solange der Checkout
noch existiert. Daraus folgt keine Effekt- oder Löschautorität.

Eine vollständig verwaiste Binding-Zeile ohne Git-Worktree-Record gehört nicht
zu dieser Worktree-Inventarsicht. `grabowski_checkout_binding_reconciliation`
vergleicht solche Bindings read-only mit der kanonischen Git-Beobachtung und
projiziert unklare oder widersprüchliche Fälle blockierend. Die Binding-Zeile
darf nicht aus Abwesenheit allein automatisch entfernt oder terminalisiert werden.

Steuerboard-, Bureau- oder GitHub-Signale können helfen, die `unknown`-Fälle zu
priorisieren. Sie ersetzen aber nicht Recovery-Ref, Dirty-State-Prüfung,
Owner-Entscheidung und Dry-Run-Plan-Hash. Der Name `obsolete` bedeutet hier
nicht: Branch löschen. Er bedeutet: lokal cleanupfähig wirkende Arbeitskopie,
weiterhin nur nach Archiv- und Dry-Run-Vertrag.

## Invarianten

1. Der Haupt-Worktree ist kein temporärer Cleanup-Kandidat.
2. Dirty oder untracked Checkouts werden nicht archiviert oder entfernt.
3. Branches werden nicht gelöscht. Cleanup entfernt nur die verlinkte
   Arbeitskopie; `refs/heads/...` und Recovery-Refs bleiben erhalten.
4. Cleanup verlangt eine vorherige Archivierung mit verifizierbaren
   Recovery-Refs.
5. Cleanup verlangt einen frischen Dry-Run-Plan. Apply scheitert, wenn der
   aktuelle Zustand vom Plan-Hash abweicht.
   `cleanup_candidate=true` im Inventar ersetzt diesen Plan nicht.
6. Aktive Tasks, Prozesse oder fremde Resource-Leases am Checkout oder am
   Repository blockieren Apply.
7. Ein Lifecycle-Binding autorisiert weder automatische Archivierung noch
   Cleanup oder Branch-Löschung.
8. `~/repos/merges` bleibt unveränderbare Evidence-Zone.
9. Es gibt keine direkte oder forcierte Dateisystemlöschung durch den
   Lifecycle-Code.

## Recovery

Jedes Archivmanifest enthält die Recovery-Refs und einen Rollback-Hinweis:

```bash
git -C REPO worktree add CHECKOUT_PATH refs/grabowski/checkouts/.../head
```

Wenn der Checkout auf einem Branch lag, bleibt der Branch selbst erhalten. Der
zusätzliche `branch-head` Recovery-Ref konserviert den archivierten Branch-Stand
auch dann, wenn der Branch später weiterbewegt wird.

## Ownership

Retention ist owner-gebunden. Solange die Retention aktiv ist, darf Cleanup nur
vom gleichen `owner_id` geplant und angewendet werden. Resource-Leases sind
kurzlebige Kollisionskontrolle; der durable Retention-Owner steht in der
Checkout-Lifecycle-Datenbank.
