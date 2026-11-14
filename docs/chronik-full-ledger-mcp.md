# Chronik-Vollsuche über das bestehende Grabowski-MCP

Tool: `grabowski_chronik_full_search` (READ_ONLY). Es liest die vorhandene
kanonische Chronik-Release-Suche (`tools/chronik_search.py`) und deren
`agent.ledger.jsonl` direkt. **Keine zweite Datenbank, kein neuer Importer,
kein öffentlicher Webdienst und keine neue ChatGPT-Plugininstallation.**

## Agentenaufrufe

- Vergangenen Incident zu Grabowski-PR #1717 rekonstruieren:
  `grabowski_chronik_full_search(pr_number=1717, limit=10)`.
- Früheren Hostfehler nachweisbar suchen:
  `grabowski_chronik_full_search(repo="heimgewebe/grabowski", host="heim-pc", kind="agent.run.failed")`.
- Exakten Ereignisbeleg laden:
  `grabowski_chronik_full_search(event_id="sha256:...", limit=1)`.
- Mehr Treffer laden: `next_cursor` desselben Ergebnisses als `cursor`
  mit **identischen** Filtern und Limit übergeben.

Unterstützt: event_id, repo, host, component, subject_component, kind,
operation, task_class, outcome, pr_number, bureau_task_id, run_id, task_id,
since, until, keyword. Mehrere Filter werden UND-verknüpft.
Leere Suchen sind verboten; maximal 20 Treffer je Seite.
Die Repo-Suche berücksichtigt sowohl `source.repo` als auch `subject.repo`.
Somit ist die Suche nicht auf ein begrenztes 100-Ereignis-Fenster des
älteren Tools `grabowski_chronik_history` beschränkt.

Bei erfolgreicher Suche liefert das Tool die kanonischen Ereignisse,
Event-Hashes, die geprüfte Ledger-Snapshot-SHA256, die vollständige
Trefferzahl sowie `has_more`/`next_cursor`. Cursor verfallen bei
neuem Ledger-Snapshot; dann bei Seite 1 neu beginnen. Bei fehlender
Runtime, beschädigtem Ledger, Trunkierung oder unplausiblen Belegen
wird `available=false` statt falscher Abwesenheit gemeldet.

## Abgrenzung und Betriebsanforderungen

Die vorhandene Grabowski-Berechtigung `durable_job` wird unverändert
verwendet. Chronik und ihre private Datendatei müssen aus der
Grabowski-Operator-Laufzeit lokal lesbar sein. Der Toolprozess startet
nur den lokalen Python-CLI-Leser der aktuellen, SHA-gepinnten Chronik-
Release; er führt keinen Schreib-/Ingestbefehl aus.

**Chronik ist historische Evidenz, keine aktuelle Betriebsquelle.**
Nach jedem relevanten Treffer tatsächlichen aktuellen GitHub-,
Prozess-, Auth- und Runtimezustand separat prüfen. Eine fehlende
Ereignisaufzeichnung beweist nicht, dass der Vorgang nicht stattfand.

Für neue ChatGPT-Threads steht das Tool erst nach erfolgreichem Merge
**und Operator-Runtime-Deployment** zur Verfügung. Sichtbarkeit und
automatische Nutzung in einem wirklich neuen Thread sind separat
zu prüfen; ein lokaler Modulimport reicht als Nachweis nicht aus.

Das ältere `grabowski_operator_historical_recall` bleibt unverändert.
Dieser Adapter ist ein genauerer, optional einsetzbarer Leseweg und
ändert weder dessen Semantik noch vorhandene Events.
