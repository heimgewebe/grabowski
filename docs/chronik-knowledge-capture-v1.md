# Grabowski → Chronik: automatische Hochwert-Abschlussereignisse (v1)

Abhängigkeit: Chronik `knowledge.ledger` / `chronik-knowledge-event.v1`
(siehe heimgewebe/chronik#309). Historie ist keine Live-Runtime-Wahrheit.

## Warum nur wenige Abschlüsse?

`src/grabowski_chronik.py` erfasst bei der vorhandenen
`record_task_state_safely`-Terminalisierung **automatisch** ausschließlich
`deploy`, `merge`, `recovery` in terminalen Zuständen. Routine-Starts,
Code-/Review-Tasks und Statusabfragen erzeugen keine semantischen
Wissenseinträge. Der Eintrag hat Typ `operation`, Status `observed`,
Quelle `heimgewebe/grabowski` und das **tatsächlich betroffene**
Repository beziehungsweise den Host als Subject. Er enthält die begrenzte
Task-Identität, ggf. den echten Lifecycle-Receipt-Hash, den ursprünglichen
Terminalzeitpunkt und keine argv, cwd, Prompts, Logs oder Secrets.

Ein Task mit Zustand `completed` ist **keine** produktiv bestätigte
Reparatur. Erst echte Nachweise dürfen einen separaten
`production_verified`-Wissenseintrag erzeugen.

## Persistenz, Ausfall und Lücken

Das Modul legt den kanonisch serialisierten Event mit stabiler ID unter dem
vorhandenen `grabowski/chronik-outbox/knowledge/<sha256>.json` ab. Er wird
exklusiv, unter dem vorhandenen Compaction-Lock und mit fsync geschrieben.
Doppelte identische Terminalisierung belässt denselben Eintrag unverändert.
Gleiche Identität mit anderem Inhalt wird als Konflikt gemeldet; keine
semantischen Duplikate oder blinden Retrys.

Der Status nach dem Schreiben lautet `queued_unverified`, ausdrücklich
**nicht** `ledger_verified`. Erst der neue Chronik-Importer liefert nach
dessen kanonischem Readback eine echte Bestätigung.

Bei einem fehlerhaften Schreibversuch terminalisiert der Task weiterhin.
Die Rückgabe von `record_task_state_safely` enthält
`knowledge_capture.classification=capture_missing_or_invalid`.
`grabowski_task_status` kann die Erfassung später aus der persistierten
Task-Identität rekonstruieren:

- `capture_missing`: erforderliche Quelle fehlt; Nachlieferung nötig
- `capture_invalid`: Quelle beschädigt/abweichend; nicht als Erfolg melden
- `queued_unverified`: Outbox ist korrekt, Import-Readback noch nicht geprüft
- `source_unreadable`: Statusquelle ist nicht prüfbar
- `not_required`: kein hochwertiger fachlicher Abschluss

Es wird bewusst kein neuer Worker, Timer oder Kill-Switch eingeführt.
Die bestehende `chronik-outbox-import.timer` importiert die neue Domain nur,
wenn Chronik#309 tatsächlich als laufende Release-Version ausgerollt wurde.

## Grenzen

Die reine Taskterminalisierung kennt weder Root Causes noch die Bedeutung
eines ChatGPT-Gesprächs. Sie behauptet solche Aussagen daher **nicht**.
Bestätigte Fehlerursachen, widerlegte Hypothesen und Nutzerentscheidungen
können über den autorisierten, expliziten Chronik-Wissens-CLI-Pfad erfasst
werden. Ihre automatische inhaltliche Übergabe aus beliebigen neuen
ChatGPT-Threads ist weiterhin nicht nachgewiesen.

`grabowski_task_status` macht Capture-Lücken bei abgefragten Tasks
sichtbar, ist aber keine vollständige Flottenabdeckung sämtlicher
historischer Tasks. Unbeobachtbare Vorgänge bleiben unbekannt.

## Tests

- Alle 48 Grabowski-Chronik-Agent-Outbox-Tests erfolgreich.
- Isolierter gemeinsamer Grabowski/Chronik-Durchlauf:
  `grabowski_task 62c4c0ecb8ac43f899920068`: Operation `recovery` →
  persistente Wissens-Outbox → validierter kanonischer Import →
  Readback derselben ID → zielgebundener Suchtreffer.
- Ereignis-ID:
  `sha256:02d689957fa27d203ae123a7b46629051b2a8fddf76357c6f59a28ddd7bf843d`.
- **Nicht** als produktive Abnahme zählen, bevor sowohl Chronik als auch
  Grabowski in nachgewiesenen Release-Revisionen laufen und der echte
  bestehende Importtimer die ID bestätigt.
