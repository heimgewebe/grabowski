# Historical convergence backfill v1

`GRABOWSKI-OPERATOR-SURFACE-V1-T060` erzeugt eine getrennte, read-only Evidenzprojektion über einen explizit begrenzten historischen Zustand. Die Quellwahrheiten bleiben unverändert.

## Quellen und Begrenzung

Die v1-Projektion liest zwei bestehende Autoritäten:

- Operator-Obligationen aus dem create-only Obligation-Store mit Filter `attention` und maximal 100 gelesenen Records.
- Die kanonische Bureau-Attention-Klassifikation `bureau.cycle_contract.classify_task_attention()` aus der durch `bureau --json runtime-identity` verifizierten immutable Bureau-Runtime. T060 erfindet keine zweite Bureau-Attention-Semantik.

Für Bureau werden die Gruppen `stale_running`, `current_outcome_unknown`, `recent_failed`, `legacy_outcome_unavailable` und `historical_failed` übernommen. `stale_running`, `current_outcome_unknown` und `recent_failed` bleiben ausdrücklich als aktuelle Bureau-Attention markiert; die beiden übrigen Gruppen bleiben historische Diagnose. `healthy_running` und allgemeine `terminal_history` gehören nicht zum T060-Attention-Backfill.

Die Bureau-Klassifikation erhält einen expliziten `observation_unix` und einen gebundenen Attention-Horizont. Dadurch ist die zeitabhängige Einordnung mit derselben Beobachtungszeit reproduzierbar. Die Projektion bindet zusätzlich Bureau-Release-ID, Source-Commit, Manifest-SHA-256 und Package-Tree-SHA-256.

Die kombinierte Auswahl ist auf höchstens 100 Records begrenzt. Operator-Obligationen werden vor Bureau-Attention-Records sortiert, innerhalb einer Quelle nach stabiler Record-ID. Die Projektion meldet Quell-Truncation und eine bekannte Untergrenze ausgelassener Records; bei einer abgeschnittenen Quelle behauptet sie keine exakte vollständige Inventur.

Jeder ausgewählte Quellrecord enthält eine stabile Record-ID, einen Quell-Beobachtungszeitpunkt und einen SHA-256-Inhaltshinweis. Operator-Obligationen binden an die Hashes ihrer Open-/Close-Dateien. Bureau-Attention-Records binden an die kanonische Bureau-Gruppe, den bounded Task-Record, den Bureau-Source-Commit, Beobachtungszeit und Attention-Horizont.

## Klassifikation

Die T060-Projektion verwendet ausschließlich den bestehenden Grabowski-Grip `convergence-state-classify`. Sie implementiert keine zweite Konvergenzklassifikation.

Standardabbildung:

- `blocked` Operator-Obligationen liefern explizite Blocking-Evidenz aus dem create-only Close-Record.
- offene oder delegierte Obligationen werden ohne erfundene terminale Evidenz konservativ als `unknown` klassifiziert.
- Bureau `stale_running` liefert Blocking-Evidenz.
- Bureau `recent_failed` und `historical_failed` liefern Failure-Evidenz.
- Bureau `current_outcome_unknown` und `legacy_outcome_unavailable` bleiben ohne erfundene terminale Evidenz `unknown`.

Zusätzliche `expected`, `blocking`, `superseding` oder `resolution` Evidenz darf nur als expliziter, SHA-256-gebundener Override für einen Record innerhalb der ausgewählten bounded Snapshot-Menge eingespeist werden. Ein Tippfehler oder Override außerhalb der Auswahl blockiert fail-closed.

## Determinismus und Receipts

`deterministic_projection_sha256` bindet Grabowski-Runtime-Identität, Bureau-Runtime-Identität, Quellgrenzen, explizite Beobachtungszeit, ausgewählte Quellrecords, Evidenz-Overrides und den deterministischen Klassifikationsoutput. Der reine Erzeugungszeitstempel und der zeitabhängige Grip-Receipt sind absichtlich nicht Teil dieses Determinismus-Hashes.

Zusätzlich werden `classifier_parameters_sha256`, `classifier_output_sha256` und `classifier_receipt_sha256` gespeichert. Damit bleibt nachvollziehbar, welche exakte Grip-Ausführung die Projektion erzeugt hat. Eine deterministisch gebundene `summary` meldet Klassifikationszahlen, Integritätsfehler, Truncation, Konflikt-Record-IDs und die per-source Evidence-Referenzen einschließlich ihrer Quell-Hashes.

## Schreibvertrag

Die Projektion kann über `write_projection_create_only()` ausschließlich als neue private JSON-Datei veröffentlicht werden. Ein vorhandenes Ziel wird nie ersetzt; der Rückgabewert unterscheidet angefragten Inhalt und tatsächlich vorhandenen Winner per SHA-256. Die Funktion nutzt den bestehenden privaten create-only I/O-Vertrag und prüft den Winner gegen Symlinks, Hardlinks, Modusdrift und Änderungen während des Lesens.

Die Projektion begründet ausdrücklich keine Task-Vollständigkeit, keinen automatischen Closeout, keinen sicheren Retry, keine Root-Cause und keine Prioritätsänderung.
