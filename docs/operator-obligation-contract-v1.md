# Operator Obligation Contract v1

## Problem

Ein beendeter Chat-Antwortlauf ist kein Beleg dafür, dass ein beauftragter Operatorvorgang abgeschlossen ist. Ohne einen dauerhaften, maschinenlesbaren Arbeitszustand können Analyse, Teilumsetzung oder ein fehlgeschlagener Workspace fälschlich wie ein Abschluss wirken. Der Nutzer muss dann mit „weiter“ erneut anschieben.

## Vertrag

Für nichttriviale Operatorarbeit wird vor der Ausführung eine `operator-obligation` geöffnet. Sie bindet:

- eine stabile `obligation_id`;
- das Arbeitsziel;
- explizite Akzeptanzkriterien;
- optionale Herkunfts- und Referenzdaten;
- einen kanonischen Material-Hash sowie einen Record-Hash, der auch Zeit- und Bindungsfelder schützt.

Solange `open.json` existiert und keine direkte strategische v2-Resolution vorliegt, liefert der Status zwingend:

```text
continuation_required = true
response_may_end = false
work_complete = false
```

Die Antwort darf dann weder Abschluss behaupten noch die offene Arbeit verschweigen. Der Operator arbeitet weiter oder erzeugt einen zulässigen terminalen Abschluss. `continuation_required` ist das autoritative Feld. `follow_up_required` wird vorläufig als veralteter Kompatibilitätsalias mit demselben Wert ausgegeben und darf von neuen Konsumenten nicht als eigene Semantik verwendet werden.

## Zulässige Terminalzustände

`close.json` ist create-only und bindet den Hash der unveränderlichen Öffnung. Genau drei Ausgänge sind erlaubt:

1. `completed`: Für jedes Akzeptanzkriterium liegt ein eindeutiger `passed`-Beleg mit SHA-256-Bindung vor. Erst dann gilt `work_complete=true`.
2. `blocked`: Mindestens ein konkreter, SHA-256-gebundener Blocker und eine nächste sichere Aktion sind angegeben. Das Antwortende ist zulässig, behauptet aber keine Fertigstellung; `continuation_required=true` hält den Folgearbeitsbedarf sichtbar.
3. `delegated`: Der öffentliche Abschluss-Grip beobachtet den angegebenen Grabowski-Task, Agent-Workspace oder systemd-Job selbst. Nur ein tatsächlich laufender, identitäts- und receipt-gebundener Zustand wird akzeptiert. Auch dies behauptet keine Fertigstellung; die Verpflichtung bleibt im Standard-Listing sichtbar, bis eine Nachfolge-Verpflichtung die weitere Bearbeitung übernimmt.

Für jeden dieser drei `close.json`-Zustände außer `completed` gilt zunächst `continuation_required=true`; nur `completed` liefert `work_complete=true`. Eine spätere, explizite historische Resolution kann `blocked` oder `delegated` aus der aktuellen Aufmerksamkeit nehmen, ohne den ursprünglichen Abschluss oder dessen Akzeptanzstatus umzuschreiben. Ein fehlender Beleg, ein widersprüchlicher zweiter Abschluss, manipulierte Dateien, unsichere Dateirechte, unbekannte Felder oder eine unvollständige beziehungsweise widersprüchliche Statusprojektion führen fail-closed. Projektionsfehler werden im Listenaufruf als Integritätsfehler ausgewiesen und setzen `attention_required=true`; sie dürfen unfertige Arbeit nicht still ausblenden.

## Direkte strategische Resolution offener Arbeit

Eine offene Verpflichtung ist nicht technisch blockiert, nur weil ein Lösungsweg bewusst nicht weiterverfolgt werden soll. Resolution-Schema v2 darf offene Arbeit deshalb direkt `deferred` oder `superseded` historisch parken. Es entsteht kein `close.json`: `open.json` bleibt unverändert, die Resolution bindet dessen SHA-256, `close_file_sha256=null`, `state=open`, `attention_class=historical`, `work_complete=false`, `continuation_required=false` und `response_may_end=true`. `resolved` bleibt auf diesem Direktpfad verboten.

Die Resolution benötigt SHA-256-gebundene Evidenz. Eine direkte `superseded`-Resolution muss genau einen konkreten Nachfolger als `operator-obligation` binden: `reference` ist dessen Obligation-ID und `sha256` der aktuelle Hash seines unveränderten `open.json`. Eine beliebige externe Referenz genügt dafür nicht; externe Wahrheit ohne solchen Nachfolger wird nicht als Supersession ausgegeben. Sie erzeugt keine Dispatch-, Merge-, Deploy- oder sonstige Authority. Identischer Replay ist idempotent, eine abweichende zweite Entscheidung ist ein Konflikt. Wiederaufnahme erfolgt über eine neue Obligation; die alte wird nicht nachträglich geschlossen.

Reads validieren die gespeicherte Bindung erneut; manipuliertes Material oder eine falsche `open_file_sha256` scheitert fail-closed. Die Aktualität externer Quellen bleibt bei deren Primärquelle zu prüfen. Ein älterer Reader ohne diese Semantik sieht mangels `close.json` konservativ weiter offene Arbeit: Rollback kann Aufmerksamkeit wieder einblenden, nicht still ausblenden.

## Historische Resolutionen und Deferred-Parken

Eine bereits `blocked` oder `delegated` geschlossene Verpflichtung darf nur über `operator-obligation-resolve` aus Current Attention genommen werden. Der Resolve ist selbst create-only, bindet `open.json`, `close.json` und mindestens einen SHA-256-gebundenen Evidenzbeleg und ändert den ursprünglichen Terminalzustand nicht. Zulässig sind genau:

1. `resolved`: Der frühere Folgearbeitsbedarf ist durch aktuelle Evidenz historisch erledigt.
2. `superseded`: Eine andere, konkret belegte Arbeits- oder Wahrheitsquelle hat die Fortsetzung übernommen.
3. `deferred`: Die Arbeit soll aktuell ausdrücklich nicht fortgesetzt werden. Für **Resolution-Schema v2** gilt `continuation_required=false` und `attention_class=historical`; der verpflichtende `next_action` bleibt als Wiederaufnahmekontext erhalten. Dies ist **keine** Fertigstellung: `work_complete=false`, der ursprüngliche `blocked`-/`delegated`-Datensatz bleibt unverändert und ist über seinen expliziten Zustandsfilter weiter lesbar.

`deferred` darf daher nicht als stilles Wegfiltern benutzt werden. Es erfordert eine bewusste, evidenzgebundene v2-Resolution. Eine identische v2-Resolution ist idempotent; eine abweichende zweite v2-Resolution derselben Obligation ist ein Konflikt. Soll v2-deferred Arbeit später wieder aktuell werden, wird eine **neue Obligation mit neuer ID** geöffnet und auf die historische Obligation beziehungsweise deren Evidenz verwiesen. So bleibt die alte Entscheidung auditierbar, während nur der neue Arbeitsauftrag wieder Current Attention erzeugt.

### Upgrade- und Grandfather-Regel

Bereits vor Einführung dieser Parksemantik erzeugte `resolution.json`-Datensätze tragen **Resolution-Schema v1**. Ein v1-Datensatz mit `disposition=deferred` wird beim Upgrade **nicht** rückwirkend umgedeutet: Er bleibt `continuation_required=true`, `attention_class=current` und damit im Standard-Attention-Listing. Auch ein identischer Resolve-Aufruf replayt exakt diesen v1-Datensatz und migriert ihn nicht implizit.

Soll eine solche Alt-Resolution bewusst geparkt, als erledigt markiert oder superseded werden, ist eine **neue Evidenzentscheidung** erforderlich. Nur dann darf genau ein nachfolgender Resolution-Datensatz mit Schema v2 und Hashbindung an den v1-Vorgänger angelegt werden. Eine bloße Änderung von `next_action` oder Disposition reicht ausdrücklich nicht aus; mindestens ein Evidenz-Digest muss gegenüber dem **gesamten bisherigen v1-Präfix** neu sein. Der v1-Datensatz bleibt unverändert erhalten; der v2-Nachfolger ist die explizite Migrationsentscheidung. Die Kette ist fail-closed geordnet: Sie darf aus einem beliebig langen v1-Präfix und höchstens einem abschließenden v2-Datensatz bestehen. Nach dem ersten v2 ist **kein weiterer Resolution-Datensatz** zulässig; insbesondere darf ein restaurierter oder manipulierter v1-Datensatz die Projektion nicht wieder auf current zurückdrehen. Bereits historisch terminale v1-Resolutionen (`resolved` oder `superseded`) bleiben unverändert historisch.

Diese Migrationsinvarianten gelten nicht nur am Schreibpfad. Jeder Chain-Read prüft erneut, dass ein v2-Nachfolger nur auf ein noch `deferred`es v1-Präfix folgt und mindestens einen gegenüber dem gesamten v1-Präfix neuen Evidenz-Digest trägt. Ein persistierter oder manuell reparierter Nachfolger nach terminalem v1-`resolved`/`superseded` oder ohne neue Migrationsevidenz ist daher ein Integritätsfehler und darf keine Attention-Projektion erzeugen.

## Speicher- und Integritätsmodell

Der Standardpfad ist:

```text
~/.local/state/grabowski/operator-obligations/<obligation_id>/
  open.json
  close.json
  resolution.json             # optional; erste Resolution, v1 oder v2
  resolution-NNNNNN.json      # nur vorhandene v1-Ketten bzw. ein v2-Migrationsnachfolger
```

Verzeichnisse sind eigentümergebunden mit Modus `0700`, Datensätze mit `0600`. Lese- und Schreibpfade prüfen reguläre Dateien, Eigentümer, Linkzahl, Inodebindung, Größenlimits und Hashbindung. Veröffentlichung erfolgt create-only über die vorhandene private I/O-Primitive; konkurrierende Sieger werden vollständig validiert und niemals überschrieben.

Ein Interprozess-Lock serialisiert Öffnung und Abschluss. Wiederholung desselben Materials ist idempotent. Wird eine bereits terminal geschlossene Verpflichtung erneut geöffnet, bleibt ihr terminaler Status erhalten; sie wird nicht semantisch wieder auf `open` gesetzt. Dieselbe ID mit anderem Material oder ein abweichender zweiter Terminalzustand ist ein Konflikt. Zeitstempel müssen kanonisches UTC sein.

## Attention- und Due-Resurfacing

`operator-obligation-list` bleibt eine reine Projektion über die unveränderten Obligation-Datensätze. Für aktuelle Attention kann der Aufrufer einen kanonischen `as_of`-Zeitpunkt und einen begrenzten `attention_due_after_seconds`-Wert angeben; ohne Angabe gilt ein 24-Stunden-Fenster. Die Projektion verwendet bei `open` den Öffnungszeitpunkt und bei `blocked`/`delegated` den Abschlusszeitpunkt als Attention-Anker.

Jeder gelistete Datensatz erhält daraus `attention_anchor_at`, `attention_age_seconds`, `attention_due_at`, `attention_due` und `attention_priority`. Beim Standardfilter `attention` werden fällige Verpflichtungen zuerst, innerhalb derselben Klasse die ältesten zuerst ausgegeben. Die Top-Level-Projektion `attention_resurfacing` meldet Fälligkeitsfenster, Anzahl fälliger und noch frischer Current-Attention-Datensätze sowie die verwendete Ordnung. Scan- und Ergebnisgrenzen bleiben bestehen; die Due-Projektion führt keine neue persistente Zustandsquelle ein.

Diese Fälligkeit ist ausschließlich ein Wiederaufnahmehinweis. Sie setzt keine Obligation auf `completed`, `resolved`, `superseded` oder `deferred`, beobachtet keine referenzierten Tasks/Jobs/PRs live und erteilt weder Queue-, Claim-, Dispatch-, Retry- noch Mutationsautorität. Eine fällige Verpflichtung muss anhand ihrer zuständigen Primärquellen neu bewertet werden.

## Grip-Oberfläche

- `operator-obligation-list` – read-only; verwendet standardmäßig den Filter `attention` und findet damit aktuelle Verpflichtungen (`open`, `blocked`, `delegated`) begrenzt und nach Repository oder Thread gefiltert wieder. Aktuelle Attention wird über eine rein abgeleitete Due-Projektion standardmäßig nach fällig/ältest sortiert; `as_of` und `attention_due_after_seconds` machen diese Projektion deterministisch und bounded. `resolved`, `superseded` und evidenzgebunden **v2-`deferred`** resolvte Datensätze sind historisch und erscheinen dort nicht; grandfathered v1-`deferred` bleibt dagegen current. Der ursprüngliche Zustand bleibt über explizite Filter wie `state="blocked"` lesbar. Der frühere reine Open-Blick bleibt über `state="open"` unverändert verfügbar.
- `operator-obligation-open` – mutierend; legt die unveränderliche Verpflichtung an.
- `operator-obligation-status` – read-only; entscheidet, ob Fortsetzung erforderlich ist und ob die Antwort enden darf.
- `operator-obligation-close` – mutierend; akzeptiert nur `completed`, `blocked` oder `delegated` unter den beschriebenen Evidenzregeln.
- `operator-obligation-resolve` – mutierend; bindet eine bereits `blocked` oder `delegated` geschlossene Verpflichtung evidenzgebunden als `resolved`, `superseded` oder v2-`deferred` in die historische Projektion. Bei grandfathered v1-`deferred` bleibt ein identischer Replay current; nur neue Evidenz darf den einen v2-Migrationsnachfolger erzeugen. Eine spätere Wiederaufnahme einer v2-geparkten Arbeit erfolgt nicht durch Umschreiben dieser Resolution, sondern durch eine neue Obligation.

Die Agent-Anweisung nennt die exakten Aufrufe `operator-obligation-list`, `operator-obligation-open`, `operator-obligation-status`, `operator-obligation-close` und `operator-obligation-resolve` über `grip_run`. Damit ist der Lifecycle im laufenden MCP-Vertrag sichtbar und nicht nur Dokumentation. Bei `delegated` akzeptiert der Close-Grip vom Aufrufer nur Art und ID; Werkzeug, Status, Beobachtungszeit und Hash werden aus der unmittelbaren Livebeobachtung erzeugt.

## Grenzen

Der Vertrag kann die Chat-Plattform nicht physisch daran hindern, einen einzelnen Modelllauf wegen externer Limits zu beenden. Er macht einen solchen Abbruch jedoch als offene Verpflichtung dauerhaft sichtbar und verhindert einen ehrlichen Erfolgsstatus ohne Evidenz. Für echte Arbeit über das Antwortfenster hinaus ist `delegated` nur mit einem bereits gestarteten dauerhaften Task oder Workspace zulässig.

Der Vertrag erteilt keine Merge-, Deploy-, Retry-, Secret- oder Root-Autorität. Er ersetzt weder Tests noch GitHub-, Runtime- oder Bureau-Wahrheit; er bindet nur deren konkrete Belege an den Operatorabschluss.
