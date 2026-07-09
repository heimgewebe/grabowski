# Reproduzierbares Deployment

## Ziel

Die laufende Grabowski-Runtime wird aus einem Git-Commit als integritätsgeprüftes
Release erzeugt. Nach der Aktivierung wird es durch Betriebsregel nicht mehr
verändert; technischer Schreibschutz ist nicht Teil dieser Garantie. Der stabile Hostpfad bleibt:

```text
~/.local/share/grabowski-mcp
```

Nach der einmaligen Legacy-Migration ist dieser Pfad ein Symlink auf ein
Release unter:

```text
~/.local/share/grabowski-mcp-releases/<release-id>
```

Das Tunnelprofil muss dadurch nicht umgeschrieben werden. Ein Profilbefehl wie

```text
~/.local/share/grabowski-mcp/.venv/bin/python -m grabowski_mcp
```

wird beim Dienstneustart über den stabilen Symlink auf das ausgewählte Release
aufgelöst.

## Runtimevertrag

Der versionierte Entry-Point steht in:

```text
config/runtime-entrypoint.json
```

Für diesen Branch beschreibt er den Runtime-Wrapper:

```text
python -m grabowski_operator
```

Außerdem enthält er die erwartete Werkzeugliste, inklusive
`grabowski_rollback_text`, `grabowski_verify_audit`,
`grabowski_remove_path`, `grabowski_restore_removed_path`,
`grabowski_destroy_path`, `grabowski_context`, `grabowski_git_branch` und
`grabowski_privileged_action_reference`. Das Deployment liest Entry-Point,
supporting sources und Tool-Gate ausschließlich aus diesem Contract. Der
Modulmodus bleibt der einzige Entry-Point-Modus.

Auf dem aktuellen Host muss das Live-Profil exakt dazu passen:

```text
python -m grabowski_operator
```

Ein produktives `--apply` muss vor jeder Dienst- oder Runtime-Mutation
fail-closed abbrechen, solange Live-Profil und Runtimevertrag nicht exakt
zusammenpassen. Dieses Repository ändert keine Live-Profile oder Services.

## Prüfung ohne Runtime-Mutation

```bash
make deploy-check
```

Der Check darf auch auf einem veränderten Arbeitsbaum laufen. Er kopiert die
aktuellen Eingaben genau einmal in einen isolierten Checkbereich und verwendet
danach nur diese Snapshots. Er:

- erzeugt eine Venv direkt am finalen Check-Releasepfad,
- installiert ausschließlich die versionierten, gehashten Runtime-Abhängigkeiten,
- verwendet `pip --isolated --require-hashes --no-deps --only-binary=:all:`,
- führt `pip check` aus,
- gleicht installierte Distributionen gegen den Lock ab,
- installiert den deklarierten Modul-Entry-Point in die Release-Venv,
- führt `initialize` und `tools/list` aus,
- prüft die erwarteten Werkzeuge aus dem Runtimevertrag,
- erzeugt und validiert ein Deployment-Manifest,
- verändert weder produktive Runtime noch Profil noch Dienst.

## Produktives Deployment

```bash
make deploy
```

Das produktive Deployment verlangt:

- sauberen Git-Arbeitsbaum,
- fixierten Git-HEAD,
- Entry-Point-Kompatibilität zwischen Live-Profil und Branchvertrag,
- einen strukturiert bestätigten aktiven systemd-Zustand,
- einen exklusiven, inodegebundenen Deployment-Lock,
- erneute Prüfung von HEAD, Arbeitsbaum, Release-Snapshots und Profil nach dem Stop und unmittelbar vor der Pointermutation.

Apply materialisiert Source, `runtime.in`, Lock und Runtimevertrag aus dem
erfassten Git-Commit. Danach werden Hashes, Installation, Manifest und Probe
nur aus den Release-Snapshots abgeleitet.

## Verzögerter Self-Deploy

Ein Deployment, das Operator und Tunnel neu startet, darf nicht an den Lebenszyklus des aufrufenden MCP-Requests gebunden sein. Dafür existiert das typisierte Werkzeug `grabowski_runtime_deploy_schedule(expected_head, delay_seconds=8)`.

Es akzeptiert weder einen Repositorypfad noch beliebige Befehle. Vor dem Start werden der kanonische Checkout, `main`, `HEAD`, `origin/main`, ein sauberer Arbeitsbaum und der versionierte Runner geprüft. Anschließend startet das Werkzeug einen eigenständigen dauerhaften systemd-Job und gibt dessen Unit und Logpfade zurück. Der Runner wartet zunächst, prüft den Checkout erneut, führt `make validate` und danach `make deploy` aus und verifiziert abschließend das Live-Manifest.

Die Verzögerung ist Teil des Antwortvertrags: Der MCP-Request kann abgeschlossen werden, bevor Operator und Tunnel neu starten. Nach der Wiederverbindung liefern `grabowski_job_status` und `grabowski_job_logs` den dauerhaften Nachweis. Job-Status enthält eine eigene `terminalization_evidence`; akzeptierte Starts werden als `launch_submitted` markiert, und ungültige oder fehlende `systemctl show`-Daten ergeben `missing_finalization_evidence`. Optionale `notify_on_done`-Metadaten senden in diesem Slice nichts und dürfen fehlende oder fehlgeschlagene Finalisierung nicht verdecken.

## Integritätsgeprüfte Releases

Ein Release wird direkt an seinem endgültigen Pfad gebaut:

```text
~/.local/share/grabowski-mcp-releases/<release-id>/
├── .venv/
├── inputs/
│   ├── runtime-entrypoint.json
│   ├── runtime.in
│   ├── runtime.lock.txt
│   └── src/
│       ├── grabowski_runtime.py
│       ├── grabowski_operator.py
│       ├── grabowski_mcp.py
│       ├── grabowski_capabilities.py
│       └── grabowski_runtime_extensions.py
└── deployment-manifest.json
```

Die Venv wird niemals nachträglich verschoben oder umbenannt. Das Manifest wird
erst als letzter Abschlussmarker geschrieben. Unvollständige Releases erhalten
einen `deployment-incomplete.json`-Marker und bleiben für Diagnose erhalten.

Der Live-Befund vor dieser Korrektur zeigte eine relokierte Venv mit einer
alten Konsolenskript-Shebang:

```text
#!/home/alex/.local/share/.grabowski-autonomy-stage-20260625-075230/.venv/bin/python
```

Das belegt, dass Venvs nicht als verschiebbare Verzeichnisse behandelt werden
dürfen.

## Atomare Aktivierung

Bei einem bereits migrierten System wird ein temporärer Symlink neben dem
stabilen Runtimepfad angelegt und per `os.replace()` atomar auf
`~/.local/share/grabowski-mcp` geschaltet.

Bei der einmaligen Legacy-Migration wird ein reales Runtime-Verzeichnis nach
bestätigter Dienstinaktivität innerhalb desselben Parents nach
`grabowski-mcp.legacy.<timestamp>` verschoben. Ein Rollback stellt dieses
Verzeichnis exakt am ursprünglichen Pfad wieder her, damit vorhandene absolute
Venv-Pfade gültig bleiben.

Das Deployment schreibt keine Tunnelprofile neu und serialisiert keine
Profilinhalte.

## Runtime-Identität

Ein grüner HTTP-Listener genügt nicht als Identitätsbeleg. Nach dem Start wird
zusätzlich geprüft:

- systemd-MainPID verwendet exakt den erwarteten Tunnel-Client und Profilnamen,
- der MCP-Prozess gehört zum Prozessbaum der systemd-MainPID,
- der Prozess verwendet den vertraglich erwarteten Modul-Entry-Point,
- `/proc/<pid>/exe` löst auf das Pythonbinary des ausgewählten Releases,
- das deklarierte Modul liegt innerhalb der Release-Venv oder des Releases,
- der stabile Runtime-Symlink zeigt exakt auf dieses Release,
- Manifest, Sourcehash, Lockhash und Entry-Point-Contract stimmen.

Rohe Prozessargumente werden nicht als Statusdaten ausgegeben.

## Rollback

Rollback ist für behandelbare Fehler innerhalb des laufenden Deploymentprozesses
eine explizite Zustandsmaschine. Sie erfasst ursprünglichen Fehler, Phase,
Pointerzustand, Stop-/Start-Ergebnisse, Dienstinaktivität,
Pointerwiederherstellung, Readiness und finalen Zustand. Diese Garantie ist
exception-sicher, aber nicht crash-sicher gegen SIGKILL, Stromausfall oder
Rechnerneustart zwischen zwei Mutationen.

Regeln:

1. Stop versuchen.
2. Tatsächliche Inaktivität unabhängig vom Returncode prüfen.
3. Pointer nur bei bestätigter Inaktivität ändern.
4. Bei aktivem Dienst keine Dateisystemmutation im Rollback.
5. Alten Symlink oder Legacy-Pfad wiederherstellen.
6. Dienst starten.
7. Health, Readiness und Identität prüfen.
8. Original- und Rollbackfehler gemeinsam melden.

## Statusprovenienz

`grabowski_status` trennt drei Aussagen:

- `artifact_integrity_valid`: Manifeststruktur und gebundene Releaseartefakte,
- `runtime_binding_valid`: kanonischer Stable-Pfad, Pointer, Modul und Pythonbinary,
- `environment_compatibility_valid`: aktuelle Python- und Plattformgleichheit.

`provenance_valid` ist nur wahr, wenn alle drei Aggregate wahr sind. Das Manifest
darf den kanonischen Stable-Pfad nicht selbst bestimmen. Snapshotpfade werden
vor dem Lesen exakt an reguläre Dateien im realen Release gebunden; Symlinks,
Hardlinks, fremde Dateitypen und übergroße Contractdateien werden abgelehnt.

## Dependency-Lock

Die direkte Runtime-Abhängigkeit steht in:

```text
requirements/runtime.in
```

Der vollständige, gehashte Auflösungsstand steht in:

```text
requirements/runtime.lock.txt
```

Der Lockvalidator lehnt URL-, VCS-, Editable-, Constraint-, Index- und sonstige
Pip-Optionen ab. Jeder Block muss genau ein gepinntes Paket und eine oder
mehrere SHA-256-Hashzeilen enthalten. Paketnamen werden PEP-503-konform
normalisiert; Dubletten sind verboten.

Bewusste Lock-Refreshes verwenden die lokal gepinnte uv-Version:

```bash
make runtime-lock-refresh
```

Der Target-Pin lautet `uv 0.9.18`. CI führt keinen zeitabhängigen
Online-Resolververgleich aus, sondern prüft Lockformat, Hashes und
installierbare Closure.

## Bewusste Grenzen

Das Werkzeug:

- verändert keine Tunnel-ID,
- verändert keine Zugriffspolicy,
- liest keine Runtime-Secrets,
- führt kein Git-Push aus,
- löscht alte Releases nicht automatisch,
- schreibt keine Profile um.

Retention alter Releases und ein separates Deployment-Eventlog bleiben eigene
Folgetasks.

## Operator-v2-Metadaten

Der Access-Policy-Contract unterstützt optionale Profile und Capabilities, ohne
das v1-Top-Level-Format zu entfernen. Typed Secret-/Browser-Roots sind ein
v2-Policy-Feldsatz (`secret_roots`, `browser_profile_roots`,
`secret_export_roots`) und werden nicht in die Live-Policy geschrieben. Das
Standardbeispiel bleibt `bounded-read-write`; das Home-weite Operatorprofil
liegt separat als Repository-Beispiel vor und ist keine Live-Konfiguration.

Der Runtime-Entrypoint deklariert die dedizierten sensitiven Tools
`grabowski_secret_inspect`, `grabowski_secret_reveal`,
`grabowski_secret_use`, `grabowski_secret_export` und
`grabowski_browser_profile_read`, damit Deployment-Metadaten nicht auf einer
schwächeren Toolliste attestieren.

Der Kill-Switch ist eine Runtime-Bremse für mutierende Tools und benötigt keine
Deployment-Mutation. Ein vorhandener
`~/.local/state/grabowski/operator-kill-switch` oder
`GRABOWSKI_OPERATOR_KILL_SWITCH=1` reicht, damit Mutationen fail-closed
abbrechen.

## Verbleibende Grenze

Ein persistentes Deployment-Transaktionsjournal mit Recovery nach SIGKILL,
Stromausfall oder Neustart ist nicht Bestandteil von GRABOWSKI-DEPLOY-001.
Dieser PR implementiert daher keinen halben Crash-Recovery-Mechanismus; der
Folgetask GRABOWSKI-DEPLOY-002 trägt diese eigene Zustandsmaschine.
