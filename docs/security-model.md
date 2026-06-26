# Sicherheitsmodell

Grabowski soll ein starker lokaler Operator sein.

Die Sicherheitsarchitektur basiert nicht auf möglichst wenigen Fähigkeiten,
sondern auf folgenden Eigenschaften:

- explizite Wirkungsangabe,
- explizite Access-Profile und Capabilities,
- Vorschau vor folgenreichen Aktionen,
- Hash- und Zustandsprüfungen,
- atomare Änderungen,
- Audit-Trail,
- Rollback,
- Trennung von lokalen, Git- und Remote-Mutationen.

`~/repos/merges` bleibt eine unveränderbare Evidence-Zone.

## Operator v2

Access-Policies können neben den historischen Top-Level-Feldern optionale
Profile enthalten. Das aktive Profil bestimmt Roots, Limits und Capabilities;
alte v1-Policies ohne typed Secret-/Browser-Felder werden als Legacy-Profil
interpretiert. Neue sensitive Roots gehören in eine `version: 2` Policy mit
`secret_roots`, `browser_profile_roots` und `secret_export_roots`.

Mutierende Tools fail-closed, wenn der Kill-Switch aktiv ist oder die
Auditkette nicht verifizierbar ist. Neue Auditrecords enthalten Sequenz,
Vorhash und Recordhash. Legacy-Records bleiben lesbar; sobald ein v2-Record an
sie anschließt, wird auch ihr Rohzeilenhash Teil der Kette.

Text-Ersetzungen kopieren die Vorversion in eine Quarantäne unter
`~/.local/state/grabowski/quarantine/`. Der Rollback stellt nur dann wieder her,
wenn die aktuelle Datei noch exakt dem auditierten Nachher-Hash entspricht.

Secret- und Browser-Profil-Pfade werden als explizite typed Roots modelliert.
Die generischen Dateiwerkzeuge behandeln sie nicht als normale Read-/Write-
Fläche. Stattdessen stehen dedizierte Capabilities bereit:
`secret_inspect`, `secret_reveal`, `secret_use`, `secret_export` und
`browser_profile_read`.

`secret_inspect` gibt nur Metadaten, Hashes und bounded Directory-Listings
zurück. `secret_reveal` ist der einzige rohe Secret-Textpfad und benötigt immer
einen aktuellen SHA-256-Precondition-Hash. `secret_use` startet argv-only
Kommandos und reicht das Secret über einen geerbten FD oder einen restriktiven,
aufgeräumten Tempfile-Fallback durch; das Secret erscheint nicht in argv oder
Environment und wird aus stdout/stderr in exakter, base64-, URL-safe-base64-
und URL-encodierter Form redigiert. `secret_export` erstellt lokal und
create-only mit Modus `0600` unter `secret_export_roots` und gibt keinen Inhalt
zurück. `browser_profile_read` liefert bounded Text für Textdateien; binäre
Browser-Datenbanken bleiben metadata-only.

Sensitive Dateizugriffe blocken Symlink-Komponenten, lehnen Hardlinks für
reguläre sensitive Dateien ab, binden Reads an Dev/Inode/Size/Time-Snapshots
und erzwingen Byte-Limits vor und während des Lesens. Audit und Evidence für
sensitive Mutationen enthalten nur Pfade, Hashes, Request-/Transaction-IDs,
Capability-/Profil- und Postflight-Metadaten, keine Secret-Werte.

Privilegierte Aktionen werden nicht lokal ausgeführt. Der v1-Contract unter
`contracts/privileged-action-reference.v1.schema.json` beschreibt nur
unprivilegierte Referenzen für eine spätere, getrennt autorisierte Komponente.
Jede Referenz trägt eine Ablaufzeit und eine deklarierte
`single-use-external-broker`-Replay-Policy; ein späterer privilegierter Broker
muss abgelaufene oder bereits verwendete Referenzen ablehnen.
