# Geschützte Browser-Formularaktion

`grabowski_browser_worker_stored_form_action` führt auf einem bereits laufenden
Browserworker genau eine browserverwaltete Formularaktion aus. Die Aktion ist
an Worker, kanonischen lokalen Origin und eine explizite Bestätigung gebunden.

## Sicherheitsvertrag

- Der Zielname muss ausschließlich auf Loopback-, private oder Link-Local-Adressen auflösen.
- Die aktuelle Browserseite muss exakt denselben Origin besitzen.
- Der Debug-Endpunkt stammt ausschließlich aus dem loopbackgebundenen Worker-Datensatz.
- Aufrufer liefern CSS-Selektoren und optional eine nicht geschützte Identitätsauswahl, aber keinen geschützten Feldinhalt.
- Brave oder Chromium übernimmt das gespeicherte Ausfüllen über vertrauenswürdige CDP-Eingabeereignisse.
- Toolantwort und Audit enthalten nur Boolesche Ergebnisse, kanonische Origins und SHA-256-Digests; keine Feldinhalte, Rohselektoren, Query-Strings oder Fragmente.
- Bei fehlender Füllung, Protokollfehler oder nicht beobachtbarer Submit-Wirkung werden beide Zielfelder geleert.
- Validierte Fehlversuche liefern ein strukturiertes `ok: false`-Receipt mit tatsächlichen Teilwirkungen und Cleanup-Status; interne Fehlertexte werden nicht ausgegeben.
- Nach erfolgreicher Auslösung gilt der Cleanup als erfüllt, wenn das Formular verschwunden ist oder verbliebene Zielfelder unmittelbar geleert wurden.
- Eine eigene Worker-Aktionslease verhindert parallele Formularaktionen.
- Vor dem ersten CDP-Eingriff wird ein hashgebundener Audit-Intent dauerhaft geschrieben.
- Der Action-Scope-Hash bindet Worker, Origin, alle drei Selektoren und die optionale Identitätsauswahl.

Die Bestätigung lautet auf einer Zeile:

```text
AUTHORIZE_BROWSER_STORED_FORM_ACTION <worker_id> <canonical-origin> <action-scope-sha256>
```

Ein erfolgreicher Receipt belegt die lokale Zielbindung, browserseitige Füllung,
Submit-Auslösung und eine beobachtete Seitenwirkung. Er belegt ohne
zielspezifischen Readback nicht, dass die Anmeldung fachlich erfolgreich war.

## Laufzeitvoraussetzung

Die lokale Runtime benötigt Node.js mit `fetch` und `WebSocket`. Die temporäre
CDP-Anfrage und das eingebettete Hilfsprogramm liegen ausschließlich mit Modus
`0600` im privaten Worker-Verzeichnis und werden nach jedem Pfad entfernt.
