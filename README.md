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
- `~/repos/merges` als unveränderbare Evidence-Zone

## Harte Invarianten

1. Secrets werden weder gelesen noch an ChatGPT ausgegeben.
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
