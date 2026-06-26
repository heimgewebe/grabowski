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
- dedizierte Secret-Root-Inspektion, hash-gebundene Reveals,
  strukturierte Secret-Nutzung per FD und lokale Secret-Exports
- dedizierter Browser-Profil-Lesezugriff mit Metadaten/Text und
  metadata-only Behandlung binärer Browser-Datenbanken
- transaktionale Text-Rollbacks mit Quarantänebelegen
- tamper-evidente Audit-Verifikation
- nicht-interaktive Kommandos und dauerhafte Hintergrundjobs
- Git, typisierte Branch-Operationen und GitHub CLI
- User-Service-, tmux-, Prozess- und Portoperationen
- Lenskit-/repoLens-Bundle-Registry lesen
- read-only Repo-Proof-Bundles mit Branch-/Head-Gate, Hashes und Provenance
- live erzeugter Operator-Kontext mit Runtime-/Checkout-Drift
- `~/repos/merges` als unveränderbare Evidence-Zone

## Harte Invarianten

1. Secrets werden nicht über generische Dateiwerkzeuge gelesen; dedizierte
   Secret-Werkzeuge sind capability-gebunden, hash-gebunden und schreiben
   keine Secret-Werte in Audit, Evidence, argv oder Environment.
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

## Operator v2 Foundation

Die Runtime lädt bestehende v1-Policies ohne neue Secret-Felder weiter. Neue
typed Secret-/Browser-Felder liegen in `version: 2` Policies:
`secret_roots`, `browser_profile_roots` und `secret_export_roots`.
`config/access.example.json` hält den bisherigen bounded-read-write-Default;
`config/access.home-wide-operator.example.json` zeigt ein nicht-live
Home-weites Operatorprofil für eine spätere bewusste Umstellung.

Die dedizierten sensitiven Tools sind:

- `grabowski_secret_inspect`: nur Metadaten, Hashes und bounded Listings.
- `grabowski_secret_reveal`: roher bounded Text nur mit aktuellem SHA-256.
- `grabowski_secret_use`: argv-only Prozess mit Secret über FD oder
  restriktiven Tempfile-Fallback; Secret-Werte werden aus Ausgaben redigiert.
- `grabowski_secret_export`: lokaler create-only Export nach
  `secret_export_roots`, Modus `0600`, mit Quellhash-Vorbedingung.
- `grabowski_browser_profile_read`: Browser-Profil-Metadaten und bounded Text;
  binäre Browser-Datenbanken bleiben metadata-only.

Mutierende Werkzeuge prüfen einen Kill-Switch unter
`~/.local/state/grabowski/operator-kill-switch` oder
`GRABOWSKI_OPERATOR_KILL_SWITCH=1`. Schreiboperationen erzeugen
Quarantänebelege unter dem Grabowski-State, hängen hash-verkettete Auditrecords
an und können ersetzte Textdateien über `grabowski_rollback_text`
wiederherstellen. `grabowski_remove_path` entfernt reguläre Dateien oder leere
Verzeichnisse typisiert in eine Quarantäne und
`grabowski_restore_removed_path` stellt diese Audit-Transaktionen wieder her.
Irreversibles Entfernen bleibt getrennt hinter `grabowski_destroy_path` und der
separaten `file_destroy`-Capability.

## Operator-Fähigkeiten

Der Runtime-Einstiegspunkt `grabowski_operator` umfasst die kuratierten
Dateiwerkzeuge und Erweiterungen für:

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
