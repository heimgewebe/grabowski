# Grabowski

Grabowski ist der lokale MCP-Operator für den Heim-PC.

Er verbindet ChatGPT über einen OpenAI Secure MCP Tunnel mit lokalen Datei-,
Repo-, Diagnose- und Operationsfunktionen.

## Status

Dieses Repository enthält den reproduzierbaren Quell- und Deploymentvertrag
der Grabowski-MCP-Runtime. Die produktive Runtime wird über einen atomaren
Symlink aus folgendem Pfad gestartet:

```text
~/.local/share/grabowski-mcp/
```

Ein Repository-Stand ist erst dann als live zu behandeln, wenn
`grabowski_status` eine gültige Deployment-Provenienz für genau diesen Commit
meldet.

## Aktuelle Fähigkeiten

- begrenztes Lesen und Schreiben
- Dateistatistik und Hashes
- Verzeichnisauflistung
- Textdateien erstellen und atomar ersetzen
- nicht-interaktive Kommandos und dauerhafte Hintergrundjobs
- Git, typisierte Branch-Operationen und GitHub CLI
- User-Service-, tmux-, Prozess- und Portoperationen
- Lenskit-/repoLens-Bundle-Registry lesen
- live erzeugter Operator-Kontext mit Runtime-/Checkout-Drift
- `~/repos/merges` als unveränderbare Evidence-Zone

## Harte Invarianten

1. Secrets werden weder gelesen noch an ChatGPT ausgegeben.
2. `~/repos/merges` wird niemals verändert.
3. Keine stillen Git-, Service- oder Systemmutationen.
4. Änderungen müssen belegbar und möglichst reversibel sein.
5. Symlink-Fluchten und konkurrierende Dateiänderungen müssen scheitern.
6. Runtime-Konfiguration und Zugangsdaten gehören nicht ins Repository.
7. Evidence, Handlung und Entscheidung bleiben getrennt.

## Operator-Kontext

[`GRABOWSKI.md`](GRABOWSKI.md) ist der stabile Einstieg. Der
maschinenlesbare Fähigkeitskatalog und die generierte Repository-Sicht werden
aus Runtime-Vertrag und tatsächlichen MCP-Deklarationen erzeugt:

```bash
make context-refresh
make context-check
```

Die laufende Instanz liefert mit `grabowski_context` bei jedem Aufruf den
aktuellen Runtime-, Policy- und Checkout-Zustand. `make validate` schlägt fehl,
wenn der generierte Kontext veraltet ist oder Toolvertrag, Deklarationen und
Risikoprofile auseinanderlaufen.

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

Das Live-Modul bleibt `grabowski_operator`. Dessen neue kleine Wrapper-Quelle
lädt den bisherigen Operator als `grabowski_operator_core` und anschließend die
separat prüfbaren Kontext- und Branch-Erweiterungen. Tunnelprofil, Watchdog und
Rollbackvertrag behalten dadurch denselben Entry-Point. Das Deployment prüft
MCP-Handshake, erwartete Toolliste, Runtime-Identität, Source-Hashes,
Lockfile, Plattform-Provenienz und Rollbackbedingungen.

Details: [`docs/deployment.md`](docs/deployment.md).

## Restart- und Watchdog-Härtung

`Restart=on-failure` schützt nur den Tunnel-Hauptprozess. Da `/healthz` und
`/readyz` auch nach dem Tod des MCP-Kindprozesses grün bleiben können, ergänzt
ein systemd-Timer einen semantischen Prozessbaumcheck mit Fehlerschwelle und
persistierendem Restart-Budget.

Details: [`docs/restart-watchdog.md`](docs/restart-watchdog.md).

## Operator-Fähigkeiten

Der Runtime-Einstiegspunkt `grabowski_operator` umfasst:

- nicht-interaktive Kommandos,
- systemd-basierte Hintergrundjobs,
- Git und GitHub CLI,
- typisierte lokale Branch-Erstellung und Branchwechsel,
- User-Service-Steuerung,
- tmux-Capture und tmux-Eingaben,
- Prozess- und Portdiagnose,
- einen taskorientierten Live-Kontext.

Direkter Zugriff auf beliebige grafische Terminalfenster ist nicht möglich.
Bestehende tmux-Sitzungen können dagegen gezielt gelesen und bedient werden.
