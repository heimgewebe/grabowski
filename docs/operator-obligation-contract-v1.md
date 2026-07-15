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

Solange nur `open.json` existiert, liefert der Status zwingend:

```text
continuation_required = true
response_may_end = false
work_complete = false
```

Die Antwort darf dann weder Abschluss behaupten noch die offene Arbeit verschweigen. Der Operator arbeitet weiter oder erzeugt einen zulässigen terminalen Abschluss.

## Zulässige Terminalzustände

`close.json` ist create-only und bindet den Hash der unveränderlichen Öffnung. Genau drei Ausgänge sind erlaubt:

1. `completed`: Für jedes Akzeptanzkriterium liegt ein eindeutiger `passed`-Beleg mit SHA-256-Bindung vor. Erst dann gilt `work_complete=true`.
2. `blocked`: Mindestens ein konkreter, SHA-256-gebundener Blocker und eine nächste sichere Aktion sind angegeben. Das Antwortende ist zulässig, behauptet aber keine Fertigstellung; `continuation_required=true` hält den Folgearbeitsbedarf sichtbar.
3. `delegated`: Der öffentliche Abschluss-Grip beobachtet den angegebenen Grabowski-Task, Agent-Workspace oder systemd-Job selbst. Nur ein tatsächlich laufender, identitäts- und receipt-gebundener Zustand wird akzeptiert. Auch dies behauptet keine Fertigstellung; die Verpflichtung bleibt im Standard-Listing sichtbar, bis eine Nachfolge-Verpflichtung die weitere Bearbeitung übernimmt.

Ein fehlender Beleg, ein widersprüchlicher zweiter Abschluss, manipulierte Dateien, unsichere Dateirechte oder unbekannte Felder führen fail-closed.

## Speicher- und Integritätsmodell

Der Standardpfad ist:

```text
~/.local/state/grabowski/operator-obligations/<obligation_id>/
  open.json
  close.json
```

Verzeichnisse sind eigentümergebunden mit Modus `0700`, Datensätze mit `0600`. Lese- und Schreibpfade prüfen reguläre Dateien, Eigentümer, Linkzahl, Inodebindung, Größenlimits und Hashbindung. Veröffentlichung erfolgt create-only über die vorhandene private I/O-Primitive; konkurrierende Sieger werden vollständig validiert und niemals überschrieben.

Ein Interprozess-Lock serialisiert Öffnung und Abschluss. Wiederholung desselben Materials ist idempotent. Wird eine bereits terminal geschlossene Verpflichtung erneut geöffnet, bleibt ihr terminaler Status erhalten; sie wird nicht semantisch wieder auf `open` gesetzt. Dieselbe ID mit anderem Material oder ein abweichender zweiter Terminalzustand ist ein Konflikt. Zeitstempel müssen kanonisches UTC sein.

## Grip-Oberfläche

- `operator-obligation-list` – read-only; findet standardmäßig alle nicht abgeschlossenen Verpflichtungen (`open`, `blocked`, `delegated`) begrenzt und nach Repository oder Thread gefiltert wieder.
- `operator-obligation-open` – mutierend; legt die unveränderliche Verpflichtung an.
- `operator-obligation-status` – read-only; entscheidet, ob Fortsetzung erforderlich ist und ob die Antwort enden darf.
- `operator-obligation-close` – mutierend; akzeptiert nur `completed`, `blocked` oder `delegated` unter den beschriebenen Evidenzregeln.

Die Agent-Anweisung nennt die exakten Aufrufe `operator-obligation-list`, `operator-obligation-open`, `operator-obligation-status` und `operator-obligation-close` über `grip_run`. Damit ist der Lifecycle im laufenden MCP-Vertrag sichtbar und nicht nur Dokumentation. Bei `delegated` akzeptiert der Grip vom Aufrufer nur Art und ID; Werkzeug, Status, Beobachtungszeit und Hash werden aus der unmittelbaren Livebeobachtung erzeugt.

## Grenzen

Der Vertrag kann die Chat-Plattform nicht physisch daran hindern, einen einzelnen Modelllauf wegen externer Limits zu beenden. Er macht einen solchen Abbruch jedoch als offene Verpflichtung dauerhaft sichtbar und verhindert einen ehrlichen Erfolgsstatus ohne Evidenz. Für echte Arbeit über das Antwortfenster hinaus ist `delegated` nur mit einem bereits gestarteten dauerhaften Task oder Workspace zulässig.

Der Vertrag erteilt keine Merge-, Deploy-, Retry-, Secret- oder Root-Autorität. Er ersetzt weder Tests noch GitHub-, Runtime- oder Bureau-Wahrheit; er bindet nur deren konkrete Belege an den Operatorabschluss.
