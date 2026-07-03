# Worktree Orientation v1 — Filterbefund

Status: blocked.

## Ziel

Der nächste Slice soll die Arbeitsbaum-Orientierung nicht nur über `canonical == runtime` bewerten, sondern über Absicht und genutzten Arbeitsbaum.

## Sollfelder

- runtime_matching_worktree_count
- runtime_matching_worktrees
- active_worktree
- canonical_orientation
- active_orientation
- orientation_verdict: green | warn | fail
- orientation_reason

## Absichtsachse

- diagnose: lesen erlaubt, Drift sichtbar machen
- feature: Abweichung erlaubt, aber explizit
- runtime_deploy: nur runtime-identischer Arbeitsbaum
- cleanup: Zielarbeitsbaum und Runtime-Arbeitsbaum trennen
- merge_release: erst nach Review- und Runtime-Orientierung

## Live-Befund

Der runtime-identische Arbeitsbaum ist sauber, aber lokales `main` liegt einen Commit hinter `origin/main`.

## Blocker

Der Quellpatch konnte in diesem Lauf nicht geschrieben werden. Direkte Datei-Updates mit der nötigen bestehenden Quellmodul-Signatur wurden vom Plattformfilter blockiert. Der Branch dient daher nur als Befundanker und nicht als Implementierung.

## Entscheidung

Kein Shell-Bypass, keine verdeckte lokale Änderung, kein Deploy.
