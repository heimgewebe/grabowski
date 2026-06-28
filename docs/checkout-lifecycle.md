# Checkout-Lifecycle

Grabowski verwaltet temporäre verlinkte Git-Checkouts als typisierte lokale
Ressourcen. Der Vertrag schützt Branches, erzeugt dauerhafte Recovery-Refs und
trennt Inventar, Archivierung und Cleanup.

## Werkzeuge

- `grabowski_checkout_inventory`: deterministische Sicht auf alle Worktrees
  eines Repositories, inklusive HEAD, Branch, Dirty-Status, Retention,
  jüngstem Archiv, aktiven Tasks, Prozessen und Resource-Leases.
- `grabowski_checkout_retain`: weist einem verlinkten Checkout einen
  expliziten Retention-Owner, Zweck und Ablaufzeitpunkt zu.
- `grabowski_checkout_archive`: archiviert einen sauberen verlinkten Checkout,
  indem es Recovery-Refs unter `refs/grabowski/checkouts/...` erzeugt und ein
  Manifest im Grabowski-State schreibt.
- `grabowski_checkout_cleanup`: erzeugt zuerst einen persistierten Dry-Run-Plan
  und führt erst danach, mit Plan-ID und Plan-Hash, `git worktree remove` ohne
  Force-Option aus.

## Invarianten

1. Der Haupt-Worktree ist kein temporärer Cleanup-Kandidat.
2. Dirty oder untracked Checkouts werden nicht archiviert oder entfernt.
3. Branches werden nicht gelöscht. Cleanup entfernt nur die verlinkte
   Arbeitskopie; `refs/heads/...` und Recovery-Refs bleiben erhalten.
4. Cleanup verlangt eine vorherige Archivierung mit verifizierbaren
   Recovery-Refs.
5. Cleanup verlangt einen frischen Dry-Run-Plan. Apply scheitert, wenn der
   aktuelle Zustand vom Plan-Hash abweicht.
6. Aktive Tasks, Prozesse oder fremde Resource-Leases am Checkout oder am
   Repository blockieren Apply.
7. `~/repos/merges` bleibt unveränderbare Evidence-Zone.
8. Es gibt keine direkte oder forcierte Dateisystemlöschung durch den
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
