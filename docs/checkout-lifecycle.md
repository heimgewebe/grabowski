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
- `grabowski_checkout_binding_terminal_preview`: prüft read-only, ob ein bereits
  verschwundener managed Checkout durch unveränderliche Quellterminalität, exakte
  Binding-Identität und fehlende Koordination als Evidenzzustand abschließbar ist.
- `grabowski_checkout_binding_terminal_apply`: übernimmt ausschließlich einen
  frischen, zeitgebundenen Preview-Digest per Compare-and-Swap in
  `externally_terminal_missing`. Ist der erhaltene Branch-Head ein nachweislicher
  Descendant des gebundenen Heads, darf derselbe CAS zusätzlich ausschließlich
  `expected_head` in Binding und Retention auf diesen Descendant rebind-en.
  Divergenz oder nicht beobachtbare Ancestry bleiben blockierend. Der Aufruf
  archiviert oder löscht nichts und verändert weder Branch noch Ref.
- Die Grips `checkout-owner-handoff-preview` und `checkout-owner-handoff-apply`
  sind ein enger Reconciliation-Pfad für genau `binding-retention-owner-mismatch`:
  nur sauberer, unkoordinierter Checkout; nur `completed_retained`; kein
  Archiv; aktuelle Retention muss aktiv und identitätsgleich außer dem Owner sein;
  eine historisch kürzere Lifecycle-Retention wird nicht umgeschrieben; Zielowner muss bereits Lifecycle- oder
  Retention-Owner sein; Apply ist Snapshot-/Zeit-/Bestätigungs-CAS. Es entsteht
  keine zusätzliche öffentliche MCP-Tooloberfläche.

## Inventar-Markierungen

`grabowski_checkout_inventory` klassifiziert jeden Worktree mit
`lifecycle_state`, `hygiene_mark` und einer `lifecycle_decision`. Diese
Markierung ist read-only Evidenz. Sie autorisiert weder Cleanup noch
Branch-Löschung.

| Markierung | Typische States | Bedeutung |
| --- | --- | --- |
| `primary` | `main` | Haupt-Worktree; nie temporärer Cleanup-Kandidat. |
| `dirty` | `dirty` | Änderungen oder untracked Dateien vorhanden; immer sichtbar, nie löschbar. Coordination-blocking nur bei realer Ressourcenüberschneidung (Leases, Tasks, Prozesse). |
| `retained` | `retained`, `completed_retained`, `completed_retained_blocked` | Aktive managed Arbeit ist wirksam retained; terminale managed Arbeit bleibt bis zur Archivierung explizit sichtbar. |
| `archived` | `archived_blocked`, `archived_not_remote_secured` | Eine konsistente `phase=archived`-Bindung besitzt ein passendes offenes Recovery-Archiv. Cleanup setzt zusätzlich Grace, Remote-Sicherung und Koordinationsfreiheit voraus. Lokale Remote-Tracking-Refs sind der schnelle Nachweis; nur der Cleanup-Dry-Run darf ersatzweise einen exakt passenden gemergten GitHub-PR-Head und `refs/pull/<n>/head` aktiv verifizieren. |
| `terminal` | `externally_terminal_missing` | Der Checkout fehlt bereits und seine externe Quelle ist revisions- und receiptgebunden terminal. Das ist weder Archiv noch Cleanup-Kandidat. |
| `obsolete` | `cleanup_candidate`, `prunable_or_missing` | Nur lokal gemeint: ein terminaler, sauberer, remote-gesicherter Checkout hat ein reifes Recovery-Archiv und ist lease-/prozess-/retentionfrei; vor Apply bleibt der Dry-Run Pflicht. Oder Git meldet den Worktree als prunable/missing. |
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
  Für die globale Active-Creation-Kapazität reservieren nur `active`-Bindings
  mit wirksamer Retention einen der acht Parallelitäts-Slots. Retention-Ablauf
  lässt Lifecycle-, Dirty-, Pfad- und Branch-Schutz unverändert und erteilt
  keine Cleanup-, Terminalitäts- oder Wiederverwendungsautorität.
- `completed_retained` bleibt als terminal-retained und
  archivierungspflichtig sichtbar.
- `externally_terminal_missing` bezeichnet ausschließlich einen durch
  Quellreceipt und CAS belegten externen Abschluss bei bereits fehlendem Checkout.
  Ein inzwischen fortgeschrittener Branch ist nur zulässig, wenn Git den gebundenen
  Head als Ancestor des aktuellen Branch-Heads bestätigt; dann werden Binding und
  Retention im selben CAS auf den Descendant-Head rebind-et. Dieser Zustand ist
  weder Archiv noch Cleanup-Kandidat. Ein wieder erschienener
  Worktree wird erneut blockierende Identitätsdrift.
- `archived` gelangt mit passendem offenem Recovery-Archiv in
  `archived_blocked` oder `cleanup_candidate`; Apply bleibt jedoch für mindestens
  24 Stunden nach der Archivierung gesperrt. Auch Retention desselben Owners muss
  vollständig abgelaufen sein.
- Agent-Workspace-Cleanup archiviert und entfernt nie im selben Top-Level-Aufruf:
  Nach `archived_ready_for_cleanup` folgt ohne Wartezeit ein frischer Plan und ein zweiter Aufruf.
- Unbekannte Phase oder widersprüchliche Path-, Repository-, Branch-, Owner-,
  Head-, Retention- oder Archivdaten werden `managed_lifecycle_drift`.

`grabowski_current_work` übernimmt Phase und Konsistenz als autoritative
Checkout-Evidenz. Nur ein konsistentes Binding darf zugleich die exakte
Owner-Zuordnung des Checkouts begründen. Ein widersprüchliches Binding bleibt
blockierende Drift-Evidenz, wird aber weder als Owner-Autorität noch als
terminale Konvergenzautorität verwendet. Konsistente aktive Bindungen bleiben
aktiv; abgelaufene managed Bindungen blockieren; `completed_retained` und
`archived` werden als `closed-not-cleaned` priorisiert, solange der Checkout
noch existiert. `externally_terminal_missing` wird nur als terminale Evidenz
projiziert und erzeugt keine Aufräumaktion. Daraus folgt keine Effekt- oder
Löschautorität.

Eine vollständig verwaiste Binding-Zeile ohne Git-Worktree-Record gehört nicht
zu dieser Worktree-Inventarsicht. `grabowski_checkout_binding_reconciliation`
vergleicht solche Bindings read-only mit der kanonischen Git-Beobachtung und
projiziert unklare oder widersprüchliche Fälle blockierend. Die Binding-Zeile
darf nicht aus Abwesenheit allein automatisch entfernt oder terminalisiert werden.
Der T140-Vertrag erlaubt nur einen gesonderten Evidenzzustandswechsel: Ein
read-only Preview bindet Checkout-Key, Repository/Common-Dir, Pfad, Owner, Branch,
HEAD, Source-Kind und Source-ID, die source-spezifische Terminalquittung sowie
fehlende Tasks, Prozesse, Leases und Archive. Der Apply verlangt denselben Digest
mit gebundenem Erstellungs- und Ablaufzeitpunkt, die exakte Bestätigung
`record-external-terminal-missing`, frische Quell- und Konfliktbeobachtung sowie
einen unveränderten SQLite-CAS-Readback. Unterstützte Quellen sind Bureau-Task,
Operator-Verpflichtung, Thread-Fokus, GitHub-Issue und Work-Lane.
Nur wenn ein identitätsgleiches `archived`-Binding zusätzlich einen vollständigen
Archive-Record mit positivem `cleaned_at_unix` und gebundener `cleanup_plan_id`
besitzt, wird die frisch beobachtete Checkout-Abwesenheit als `archived_cleaned`
terminal und nicht blockierend projiziert. Daraus entsteht weiterhin keine neue
Cleanup-, Branch-Lösch- oder Binding-Löschautorität.

Reposkop-, Bureau- oder GitHub-Signale können helfen, die `unknown`-Fälle zu
priorisieren. Sie ersetzen aber nicht Recovery-Ref, Dirty-State-Prüfung,
Owner-Entscheidung und Dry-Run-Plan-Hash. Der Name `obsolete` bedeutet hier
nicht: Branch löschen. Er bedeutet: lokal cleanupfähig wirkende Arbeitskopie,
weiterhin nur nach Archiv- und Dry-Run-Vertrag.

## Invarianten

1. Der Haupt-Worktree ist kein temporärer Cleanup-Kandidat.
2. Dirty oder untracked Checkouts werden nicht archiviert oder entfernt.
   Dirty-State wird nie gelöscht und ist nur bei realer Ressourcenüberschneidung
   coordination-blocking.
3. Branches werden nicht gelöscht. Cleanup entfernt nur die verlinkte
   Arbeitskopie; `refs/heads/...` und Recovery-Refs bleiben erhalten.
4. Cleanup verlangt eine vorherige Archivierung mit verifizierbaren
   Recovery-Refs.
5. Cleanup verlangt einen frischen Dry-Run-Plan. Apply scheitert, wenn der
   aktuelle Zustand vom Plan-Hash abweicht.
   `cleanup_candidate=true` im Inventar ersetzt diesen Plan nicht.
6. Cleanup ist nur zulässig, wenn der Checkout terminal, sauber und auf
   lokalen Remote-Tracking-Refs gesichert ist sowie lease-, prozess- und
   retentionfrei bleibt. Aktive Tasks, Prozesse oder fremde Resource-Leases
   am Checkout oder am Repository blockieren Apply.
7. Ein Lifecycle-Binding autorisiert weder automatische Archivierung noch
   Cleanup oder Branch-Löschung.
8. `externally_terminal_missing` verändert Phase und Terminalzeit. Nur bei
   nachgewiesener Descendant-Branchbewegung darf derselbe CAS außerdem
   `expected_head` in Binding und Retention auf den beobachteten Descendant setzen;
   Branch, Ref, Archiv und Dateisystem bleiben unverändert.
9. `~/repos/merges` bleibt unveränderbare Evidence-Zone.
10. Es gibt keine direkte oder forcierte Dateisystemlöschung durch den
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
Checkout-Lifecycle-Datenbank. Ein historischer Owner-Mismatch wird nicht durch
`retain` überschrieben: Der Owner-Handoff-Grip darf ausschließlich einen sauberen,
archive-freien Checkout mit genau diesem einen Driftgrund auf einen der zwei bereits
durabel vorhandenen Owner konvergieren und bindet die Änderung an einen frischen
Snapshot.

## Terminal evidence source contract

Managed checkout creation now accepts only lifecycle source kinds with a concrete immutable terminal-evidence observer: `bureau_task`, `operator_obligation`, `thread_focus`, and `github_issue`. Producers must bind one of these evidence-bearing sources before `worktree_ensure` creates a checkout.

`source.kind=automation` is intentionally not inferred terminal from checkout absence, retention expiry, missing leases, a merged base commit, or a successful worktree-creation receipt. Historical automation bindings therefore remain visible and fail closed until an immutable source-id- and outcome-bound terminal receipt contract exists. This restriction does not authorize archive, cleanup, branch deletion, ref deletion, or rewriting historical lifecycle evidence.
