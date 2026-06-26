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
- dedizierte Secret-Root-Inspektion, explizite hash-gebundene Reveals,
  strukturierte Secret-Nutzung per FD und lokale Secret-Exports
- dedizierter Browser-Profil-Lesezugriff mit Metadaten/Text und
  metadata-only Behandlung binärer Browser-Datenbanken
- Textdateien erstellen und ersetzen
- transaktionale Text-Rollbacks mit Quarantänebelegen
- tamper-evidente Audit-Verifikation
- Lenskit-/repoLens-Bundle-Registry lesen
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

Produktive Runtime mit automatischem Rollback aktualisieren:

```bash
make deploy
```

Details: [`docs/deployment.md`](docs/deployment.md).

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
wiederherstellen.
