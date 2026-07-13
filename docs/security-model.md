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

## Durable Jobs und Same-UID-Vertrauensgrenze

Durable Jobs werden als bereits autorisierte lokale Kommandos im Benutzerkontext gestartet. Sie sind keine allgemeine Ausführungsfläche für vollständig untrusted Code.

Neue Job-Metadaten enthalten einen normalisierten Origin-Vertrag. Dessen SHA-256 wird vor dem Unit-Start berechnet und als systemd-Umgebungs-Precondition an den Stop-Finalizer übergeben. Der Finalizer akzeptiert ein neues Outbox-Receipt nur, wenn Unit, Job-ID, Besitzer, argv-Hash, Scope, Notification-Anforderung, Origin-Hash und Startwerkzeug zusammenpassen. Teilweise vorhandene oder nachträglich neu gehashte Origin-Verträge scheitern geschlossen.

Diese Bindung schützt gegen stille Metadatendrift und versehentliche Änderungen, solange die beim Unit-Start gesetzte Precondition nicht ebenfalls kontrolliert wird. **Sie ist keine Isolation.** Ein kompromittierter Job-Prozess, der vor dem Stop-Finalizer im selben Benutzerkontext läuft und sowohl Metadaten als auch die beim Finalizer verwendete Precondition kontrollieren kann, kann einen in sich konsistenten gefälschten Origin-Vertrag herstellen. Der Finalizer kann diesen Fall nicht von einem legitimen Start unterscheiden. Dafür wäre eine getrennte Sicherheitsdomäne nötig, etwa eigener Benutzer, root-eigener Broker, Container oder MicroVM.

Der Finalizer liest zunächst nur seine feste Environment-Allowlist, verlangt darin `GRABOWSKI_JOB_DIRECTORY` und setzt anschließend vor jedem Dateizugriff im eigenen kurzlebigen Prozess `UMask=0077`, `RLIMIT_CORE=0` sowie ein hohes, aber endliches `RLIMIT_NOFILE`. Für neue Ad-hoc-Jobs validiert er einen unveränderlichen Vertrag gegen Origin-Metadaten, Unit, Job-ID, Argument-Hash und kanonische Receipt-Pfade. Das generische `finalization.json` wird ausschließlich create-only veröffentlicht; ein vorhandener Sieger wird vollständig nach Hash, Bindung und Statussemantik geprüft und bei Konflikt weder ersetzt noch als Erfolg akzeptiert. Runtime-Deploy-Belege bleiben Eigentum des Deploy-Runners und werden vom allgemeinen Finalizer nicht überschrieben. Fehler werden strukturiert auf stderr geschrieben und durch den Unit-Vertrag im langlebigen Job-Stderr erfasst; systemd hält zusätzlich den fehlgeschlagenen `ExecStopPost`-Status fest. Ein Finalizerfehler ändert nicht den bereits ermittelten Hauptprozessausgang, verhindert aber einen gültigen Finalisierungs- oder Notification-Beleg. Der eigentliche Durable Job behält seine bisherige Umask- und Dateideskriptor-Semantik.

Das Dateipublishing ist absichtlich create-only und ersetzt niemals ein vorhandenes Ziel. Alle Dateioperationen sind an einen geöffneten privaten Verzeichnis-FD gebunden; der sichtbare Verzeichnispfad wird vor und nach der Publikation gegen denselben Inode geprüft. Modus, Inode, Linkzahl und Directory-Fsync werden validiert. Ein Same-UID-Angreifer kann eine Datei nach Abschluss dennoch löschen oder ersetzen; dieser Primitive behauptet keine Untrusted-Isolation.

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

`docs/operator-optimization-plan.md` narrows the next security objective without
turning restriction into a goal. `trusted-owner` should remain available for
supervised full-function operation; lower-authority profiles are routing targets
for read-only, resident or self-directed work when they preserve function.

The security optimization order is deliberately signal-first:

1. classify failed tasks and friction before changing permission surfaces,
2. make checkout/worktree state legible before cleanup,
3. standardize agent receipts before increasing delegation,
4. fix benign redaction false positives without weakening secret redaction,
5. only then propose function-preserving capability routing with an explicit
   elevation path where lower authority would block legitimate work.

A routing rollout must be reversible. A roadmap entry or optimization plan does
not authorize a live policy change, fleet mutation, secret operation, cleanup
apply, merge, push or deploy.

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
