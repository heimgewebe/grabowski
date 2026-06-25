# Reproduzierbares Deployment

## Ziel

Die laufende Grabowski-Runtime wird aus einem Git-Commit als unveränderliches
Release erzeugt. Der stabile Hostpfad bleibt:

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

Für diesen Branch beschreibt er den Basisserver:

```text
python -m grabowski_mcp
```

Außerdem enthält er die erwartete Werkzeugliste. Das Deployment liest Entry-
Point und Tool-Gate ausschließlich aus diesem Contract. Der Modulmodus ist der
einzige Entry-Point-Modus in PR #8.

Auf dem aktuellen Host startet das Live-Profil noch:

```text
python -m grabowski_operator
```

Ein produktives `--apply` aus PR #8 muss deshalb vor jeder Dienst- oder
Runtime-Mutation fail-closed abbrechen. Die Operator-Runtime wird erst nach dem
Merge von PR #8 und einem Rebase/Härtung des gestapelten Operator-Slices
migriert.

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
- exklusiven Deployment-Lock,
- unveränderten HEAD und sauberen Arbeitsbaum unmittelbar vor Aktivierung.

Apply materialisiert Source, `runtime.in`, Lock und Runtimevertrag aus dem
erfassten Git-Commit. Danach werden Hashes, Installation, Manifest und Probe
nur aus den Release-Snapshots abgeleitet.

## Immutable Releases

Ein Release wird direkt an seinem endgültigen Pfad gebaut:

```text
~/.local/share/grabowski-mcp-releases/<release-id>/
├── .venv/
├── inputs/
│   ├── runtime-entrypoint.json
│   ├── runtime.in
│   ├── runtime.lock.txt
│   └── src/grabowski_mcp.py
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

Rollback ist eine explizite Zustandsmaschine. Sie erfasst ursprünglichen Fehler,
Phase, Pointerzustand, Stop-/Start-Ergebnisse, Dienstinaktivität,
Pointerwiederherstellung, Readiness und finalen Zustand.

Regeln:

1. Stop versuchen.
2. Tatsächliche Inaktivität unabhängig vom Returncode prüfen.
3. Pointer nur bei bestätigter Inaktivität ändern.
4. Bei aktivem Dienst keine Dateisystemmutation im Rollback.
5. Alten Symlink oder Legacy-Pfad wiederherstellen.
6. Dienst starten.
7. Health, Readiness und Identität prüfen.
8. Original- und Rollbackfehler gemeinsam melden.

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

## Härtungsnachtrag

Dienstzustände werden strukturiert geprüft; unbekannte oder transitive Zustände blockieren Pointermutationen. Rollback wartet begrenzt auf bestätigte Inaktivität. Legacy-Verzeichnisse werden zusätzlich über Geräte- und Inode-Identität verifiziert. Statusprovenienz bindet Manifest, Release, Runtime-Input, Lock, Source-Snapshot, Modul, Contract, Entry-Point, Python und Plattform. Der Deployment-Lock ist auf den Grabowski-State-Root begrenzt, symlinksicher geöffnet und auf eine reguläre Datei des aktuellen Benutzers mit Modus 0600 beschränkt. Runtime- und Tooling-Locks verwenden dieselbe strikte Pin- und Hashsemantik; die Tooling-Venv wird vor der Closure-Prüfung geleert.
