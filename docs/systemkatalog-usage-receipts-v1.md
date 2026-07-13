# Systemkatalog-Nutzungsbelege v1

## Zweck

Grabowski kann eine echte, deterministische Abfrage gegen den versionierten
Systemkatalog ausführen und dazu einen begrenzten Nutzungsbeleg erzeugen. Damit
wird messbar, **dass** der Katalog konsultiert wurde, welcher Katalogcommit und
welche Quellpfade verwendet wurden und wie der Operator die Verwendung des
Ergebnisses einordnet.

Der Beleg ist keine neue Autorität. Die Systemwahrheit bleibt im
Systemkatalog; Ausführung und Agentenrouting bleiben bei Grabowski.

## Wann verwenden

Ein Beleg ist sinnvoll, wenn eine Entscheidung von einer repositoryübergreifenden
Frage abhängt, insbesondere:

- Wer besitzt eine bestimmte Wahrheit?
- Welches Repository ist der richtige Arbeitsort?
- Wo verläuft eine Zuständigkeitsgrenze?
- Welcher Einstiegspunkt ist kanonisch?
- Welche stabile Beziehung besteht zwischen zwei Systemen?

Für rein lokale Codefragen ist kein Systemkatalog-Beleg nötig.

## Beispiel

```bash
python3 tools/systemkatalog_usage_receipt.py   --query truth-owner   --argument agent_routing   --reason truth_owner   --result-use used   --decision-effect confirmed   --output /tmp/systemkatalog-agent-routing.receipt.json
```

Die Ausgabe wird zusätzlich auf stdout geschrieben. Eine angegebene Datei wird
atomar mit Modus `0600` erzeugt.

## Begrenzte Felder

`reason` verwendet nur eine feste Liste:

- `truth_owner`
- `repository_selection`
- `scope_boundary`
- `entrypoint_lookup`
- `relation_lookup`
- `system_overview`

`result_use` ist `used`, `not_used` oder `unknown`.

`decision_effect` ist `changed`, `confirmed`, `none` oder `unknown`.
`changed` und `confirmed` sind nur zusammen mit `result_use=used` zulässig.

Freie Gesprächsinhalte, Prompttexte und Begründungsprosa werden nicht im Beleg
gespeichert. Der Abfrageparameter muss ein begrenzter Katalogbezeichner sein.

## Beweisgrenze

Direkt belegt sind:

- die ausgeführte Query-Form;
- der gelesene Systemkatalog-Commit;
- der Hash des vollständigen Query-Ergebnisses;
- die vom Query-Ergebnis genannten kanonischen Quellpfade;
- die Integrität des Belegs über `receipt_sha256`.

Nur vom Operator deklariert sind:

- ob das Ergebnis verwendet wurde;
- ob es eine Entscheidung änderte oder bestätigte.

Der Beleg beweist deshalb ausdrücklich nicht:

- kausale Entscheidungswirkung;
- Wahrheit jenseits des gebundenen Katalogcommits;
- Aufgabenpriorität;
- Runtime-Gesundheit;
- Merge-Reife.

## Sicherheitsgrenzen

- ausschließlich read-only Systemkatalog-Query;
- 15 Sekunden Zeitlimit;
- minimierte Prozessumgebung;
- keine Python-Bytecode-Reste;
- reguläre Query-Datei, keine Symlinks;
- nur relative, nicht ausbrechende Quellpfade;
- keine automatische Mutation, Disposition oder semantische Übernahme.
