# Grabowski

Grabowski ist der lokale MCP-Operator für den Heim-PC.

Er verbindet ChatGPT über einen OpenAI Secure MCP Tunnel mit lokalen Datei-,
Repo-, Diagnose- und späteren Operationsfunktionen.

## Status

Dieses Repository enthält den belegten Ausgangsstand der aktuell laufenden
Grabowski-MCP-Runtime.

Die produktive Runtime wird zunächst weiterhin aus folgendem Pfad gestartet:

```text
~/.local/share/grabowski-mcp/
```

Das Repository ist noch nicht automatisch der Deployment-Pfad. Die Umstellung
auf reproduzierbares Deployment erfolgt in einem eigenen, getesteten Slice.

## Aktuelle Fähigkeiten

- begrenztes Lesen und Schreiben
- Dateistatistik und Hashes
- Verzeichnisauflistung
- Textdateien erstellen und ersetzen
- Lenskit-/repoLens-Bundle-Registry lesen
- read-only Repo-Proof-Bundles mit Branch-/Head-Gate, Hashes und Provenance
- `~/repos/merges` als unveränderbare Evidence-Zone

## Harte Invarianten

1. Secrets werden weder gelesen noch an ChatGPT ausgegeben.
2. `~/repos/merges` wird niemals verändert.
3. Keine stillen Git-, Service- oder Systemmutationen.
4. Änderungen müssen belegbar und möglichst reversibel sein.
5. Symlink-Fluchten und konkurrierende Dateiänderungen müssen scheitern.
6. Runtime-Konfiguration und Zugangsdaten gehören nicht ins Repository.
7. Evidence, Handlung und Entscheidung bleiben getrennt.

## Lokale Evidence-Bundles

Ein begrenzter CLI-Builder erzeugt aus einem lokalen Git-Arbeitsbaum ein
gehashtes Zustands-, Diff- und Referenzbundle, ohne das Repo zu verändern:

```bash
python3 tools/build_local_evidence.py --job JOB.json --output BUNDLE_DIR
```

Die Referenzlisten sind bewusst nur Kandidaten und tragen keine
Vollständigkeitsbehauptung. Details und Statussemantik stehen in
[`docs/local-evidence.md`](docs/local-evidence.md).

## Validierung

```bash
make validate
```

## Roadmap

Siehe [`docs/roadmap.md`](docs/roadmap.md).

## Deployment aus dem Repository

Reproduzierbarkeit ohne Runtime-Mutation prüfen:

```bash
make deploy-check
```

Produktive Runtime mit exception-sicherem Rollback aktualisieren:

```bash
make deploy
```

Auf dem aktuellen Host stoppt dieser Branch erwartungsgemäß vor jeder
Runtime-Mutation, solange das Live-Profil `python -m grabowski_operator`
verlangt und der PR-#8-Vertrag `python -m grabowski_mcp` liefert.

Details: [`docs/deployment.md`](docs/deployment.md).

Die Runtime-Abhängigkeiten sind in `requirements/runtime.lock.txt` vollständig
versioniert und gehasht. Das Deployment prüft außerdem den exklusiven Lock,
die gestartete Prozessidentität und das Provenienzmanifest.

## Restart- und Watchdog-Härtung

`Restart=on-failure` schützt nur den Tunnel-Hauptprozess. Da `/healthz` und
`/readyz` auch nach dem Tod des MCP-Kindprozesses grün bleiben können, ergänzt
ein systemd-Timer einen semantischen Prozessbaumcheck mit Fehlerschwelle und
persistierendem Restart-Budget.

Details: [`docs/restart-watchdog.md`](docs/restart-watchdog.md).

## Operator-Fähigkeiten

Der Operator-Einstiegspunkt `grabowski_operator` ergänzt die kuratierten
Dateiwerkzeuge um:

- nicht-interaktive Kommandos,
- systemd-basierte Hintergrundjobs,
- Git und GitHub CLI,
- User-Service-Steuerung,
- tmux-Capture und tmux-Eingaben,
- Prozess- und Portdiagnose.

Direkter Zugriff auf beliebige grafische Terminalfenster ist nicht möglich.
Bestehende tmux-Sitzungen können dagegen gezielt gelesen und bedient werden.
