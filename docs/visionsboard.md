# Grabowski Visionsboard

Stand: 2026-07-13

## Status und Semantik

Dieses Dokument sammelt Perspektivpunkte. Es ist keine Task-Queue, kein Prioritätsregister, keine Lease und keine Umsetzungsfreigabe.

Ein Punkt wird erst zu aktiver Arbeit, wenn neue Evidenz seinen Nutzen gegenüber Komplexität, Sicherheitsrisiko und Betriebsaufwand rechtfertigt und er separat im kanonischen Aufgabensystem registriert wird.

## Geparkte Perspektiven

### Replay- und Flight-Recorder-Projektion

Zielhypothese: Entscheidungen und Zustandsübergänge könnten nachträglich besser erklärbar werden.

Vor Aktivierung nötig:

- klarer zusätzlicher Diagnosewert gegenüber bestehenden Audit-, Task- und Job-Receipts;
- Datenschutz- und Retentionsgrenze;
- Kostenmessung;
- kein heimlicher Vollmitschnitt.

### Pre-Mortem im Schattenbetrieb

Zielhypothese: Vorhersagen über wahrscheinliche Fehler könnten spätere Regressionen reduzieren.

Vor Aktivierung nötig:

- reine Schattenauswertung ohne Blockier- oder Mutationsautorität;
- messbare Präzision und Fehlalarmrate;
- Vergleich gegen bestehende Preflight- und Review-Gates.

### Selektive Operations

Zielhypothese: Noch enger typisierte Teiloperationen könnten Connector- und Policy-Friktion weiter senken.

Vor Aktivierung nötig:

- wiederholtes reales Friktionsmuster;
- belegte Reduktion gegenüber bestehenden kleinen Operator-Programmen;
- keine Werkzeugexplosion ohne Nutzennachweis.

### Earned Autonomy

Zielhypothese: Wiederholt sichere Abläufe könnten begrenzt weniger Beaufsichtigung benötigen.

Vor Aktivierung nötig:

- formales Vertrauensmodell mit Widerruf;
- harte Autoritätsobergrenzen;
- belastbare Fehlerraten und Recovery-Evidenz;
- kein selbst erteilter Privilegienaufstieg.

Bedrohungsmodell vor Aktivierung:

- schützenswerte Werte: Repositoryzustand, Secrets, Auditkette, Deploy-Autorität und fremde Leases;
- ein sicherer Verlauf darf nur die Beaufsichtigungsdichte reduzieren, niemals Capabilities selbst erweitern;
- Vertrauensentzug muss bei Policyänderung, Integritätsfehler, Reviewfehler oder Recovery-Abweichung sofort wirksam sein;
- Erfolgsmetriken dürfen nicht vom ausführenden Agenten allein erzeugt oder bewertet werden.

### Untrusted Isolation

Zielhypothese: Stärkere Isolation könnte riskantere fremde Programme sicherer ausführbar machen.

Mögliche spätere Mittel:

- gVisor;
- MicroVMs;
- andere eng begrenzte Sandboxes.

Vor Aktivierung nötig:

- konkreter Workload, den Bubblewrap und bestehende Grenzen nicht sicher tragen;
- Betriebs- und Ressourcenmessung;
- Recovery- und Updatekonzept.

Bedrohungsmodell vor Aktivierung:

- Same-UID-Ausführung gilt nicht als Isolation gegen vollständig feindlichen Code;
- Angreifer dürfen Dateisystem, Prozessumgebung, Netzwerk und Ressourcenlimits aktiv missbrauchen;
- schützenswerte Werte sind Host-Secrets, andere Worktrees, systemd-Userzustand, Runtime-Releases und Audit-Evidence;
- die Grenze muss Escape, Persistenz, Ressourcenerschöpfung, Seiteneffekte über Netzwerk und Manipulation von Receipts abdecken;
- ein konkreter Referenz-Workload und ein kontrollierter Escape-/Recovery-Test sind Pflicht, bevor gVisor, Container oder MicroVM produktiv werden.

### Begrenzter Procedure Mode

Zielhypothese: Wiederkehrende, klar typisierte Abläufe könnten als kleine Programme statt als freie Befehlsfolgen ausgeführt werden.

Vor Aktivierung nötig:

- enges Schema;
- feste erlaubte Operationen;
- Schrittbelege und Abbruchsemantik;
- keine allgemeine Code- oder Shell-Ausführung durch die Hintertür.

### Client-Toolprofilierung

Zielhypothese: Ein Client könnte nur die für eine Aufgabe relevante Werkzeugmenge laden.

Vor Aktivierung nötig:

- nachweisbare clientseitige Steuerbarkeit;
- Snapshot-Refresh-Beleg;
- kein Verwechseln von Server-Policy und Clientanzeige.

### Agentenflotten-Leitbild

Zielhypothese: Mehrere spezialisierte Agenten könnten parallel nützliche Kontraste liefern.

Vor Aktivierung nötig:

- belegter Mehrwert gegenüber maximal zwei isolierten Kandidaten;
- eindeutiger Operator als Lane-Owner;
- Kosten-, Konflikt- und Evidenzmodell;
- keine automatische Gewinnerwahl oder Patchübernahme.

### Selbstoptimierendes Routing

Zielhypothese: Routing könnte sich anhand realer Friktion und Ergebnisqualität anpassen.

Vor Aktivierung nötig:

- stabile Metriken;
- Schattenbetrieb;
- erklärbare Entscheidungen;
- harte Grenzen gegen Autoritätsausweitung und Zielverschiebung.

## Aktivierungsregel

Ein Visionspunkt darf nur aktiviert werden, wenn mindestens folgende Fragen mit Belegen beantwortet sind:

1. Welches reale wiederholte Problem löst er?
2. Welche bestehende Komponente reicht nicht aus?
3. Welcher messbare Nutzen wird erwartet?
4. Welche neue Angriffs-, Komplexitäts- und Betriebsfläche entsteht?
5. Wie wird ein Fehlversuch gestoppt und zurückgebaut?
6. Welche kleinere Alternative wurde geprüft?

Bis dahin bleibt der Punkt geparkt.
