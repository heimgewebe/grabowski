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
Reversible Dateisystem-Entfernungen sind separat typisiert: reguläre Dateien
benötigen einen aktuellen SHA-256-Precondition-Hash, Verzeichnisse müssen leer
sein. `grabowski_remove_path` entfernt nur diese beiden Typen in eine
Quarantäne, `grabowski_restore_removed_path` stellt nur aus dem Auditrecord
und nur auf einen weiterhin fehlenden Zielpfad wieder her. Irreversibles
Entfernen ist kein Fallback dieses Pfads, sondern benötigt `file_destroy`, die
exakte Bestätigung `permanently-delete` und bleibt nicht rekursiv.

Secret- und Browser-Profil-Pfade werden als explizite typed Roots modelliert.
Die generischen Dateiwerkzeuge behandeln sie nicht als normale Read-/Write-
Fläche. Stattdessen stehen dedizierte Capabilities bereit:
`secret_inspect`, `secret_reveal`, `secret_use`, `secret_export` und
`browser_profile_read`.

`secret_inspect` gibt nur Metadaten, Hashes und bounded Directory-Listings
zurück. `secret_reveal` ist der einzige rohe Secret-Textpfad und verlangt einen
aktuellen SHA-256-Precondition-Hash, eine Begründung und die explizite
Bestätigung der Exposition im Chatkontext. Standardpfad ist `secret_use`; er startet argv-only
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

Privilegierte Aktionen bleiben von der gehärteten MCP-Runtime getrennt. Der
Contract unter `contracts/privileged-action-reference.v1.schema.json` erzeugt
kurzlebige Single-Use-Referenzen für den root-eigenen Socket-Broker. Der Broker
führt ausschließlich konfigurierte argv-Templates aus; sein Host-Bootstrap ist
eine explizite Systemoperation.

## Staged Capability Profiles

`config/access.example.json` now uses `observe` as its repository-default
profile. `observe` enables only bounded reads, audit verification, bundle
lookup, process inspection and port inspection. It deliberately excludes
`file_write`, `terminal_execute`, secret capabilities, irreversible file
destroy, process signals, durable jobs, resource leases, GitHub CLI and generic
service control.

`maintain` is intentionally conservative. Current implementation capabilities
are still coarse in several places: enabling `durable_job`, `resource_lease`,
`git_cli`, `github_cli` or `user_service_control` would also unlock mutating
tools. Therefore `maintain` does not pretend to provide safe reconcile refresh,
resource renew or checkout inventory until those paths get separate tool-level
read/write gates.

`mutate` enables bounded repository/operator mutations with audit and
preconditions, but excludes terminal execution, secret reveal/use/export,
browser profile reads, tmux input, process signals and irreversible destroy.
`break-glass` is the explicit high-risk profile for those excluded operations.
The live policy is not changed by these examples; staged profile adoption must
be a separate deployment decision with rollback evidence.

## Optimization target

`docs/operator-optimization-plan.md` narrows the next security objective:
`trusted-owner` should remain a supervised elevation profile, not the quiet
normal form for resident or self-directed autonomy.

The security optimization order is deliberately signal-first:

1. classify failed tasks and friction before changing permission surfaces,
2. make checkout/worktree state legible before cleanup,
3. standardize agent receipts before increasing delegation,
4. fix benign redaction false positives without weakening secret redaction,
5. only then propose a live profile migration from `trusted-owner` toward a
   narrower default.

A narrow profile rollout must be reversible. A roadmap entry or optimization
plan does not authorize a live policy change, fleet mutation, secret operation,
cleanup apply, merge, push or deploy.

## Trusted Owner

Für den allein kontrollierten Heim-PC ist `trusted-owner` das vorgesehene
Vollprofil. Es stellt den gesamten sichtbaren Host-Dateibaum, die vollständige
Prozessumgebung, lange Laufzeitbudgets, Fleet-Ausführung und alle implementierten
Capabilities bereit. Befehl-, Pfad- oder Programmnamen werden in diesem Profil
nicht pauschal blockiert. Auch Privilegierungs-Frontends dürfen aufgerufen
werden; ob sie erfolgreich sind, entscheidet die Hostkonfiguration.

Erhalten bleiben nur wirkungsbezogene Invarianten: Konkurrenzleases, atomare
Publikation, Audit-Provenienz, Secret-Redaktion in Ausgaben, Schutz vor stillen
Zielüberschreibungen und die kanonische Evidence-Zone. Diese Mechanismen
verhindern keine legitime Aufgabe, sondern machen parallele und folgenreiche
Operationen deterministisch überprüfbar.
