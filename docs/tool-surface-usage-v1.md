# Tool-Surface Usage v1

`tools/tool_surface_usage.py` ist der read-only M1-Analyzer für die spätere P9-Entscheidung über Grabowskis öffentliche Tool-Oberfläche.

## Zweck

Der Analyzer beantwortet zunächst nur die belastbare Teilfrage:

> Welche **mutierenden** öffentlichen Tools wurden in einem revisions- und zeitgebundenen Fenster tatsächlich zur Mutation zugelassen?

Dafür verwendet er ausschließlich die bestehende verifizierte Grabowski-Auditkette. Er erzeugt keinen neuen Ledger, keinen Daemon und keine zweite Telemetrie-Wahrheit.

## Evidenzmodell

`effect-admission` enthält den Toolnamen im unveränderten Auditdatensatz. Die allgemeine öffentliche Audit-Projektion gibt dieses Feld absichtlich nicht aus. Der Analyzer arbeitet deshalb innerhalb eines bereits verifizierten Audit-Snapshots auf den gebundenen Segmentbytes:

- aktive Segmentbytes stammen direkt aus dem verifizierten Snapshot;
- archivierte Segmente werden vor Verwendung erneut gegen ihren Snapshot-SHA-256 geprüft;
- ausgegeben werden ausschließlich aggregierte Toolnamen und Zähler;
- Argumente, Rückgaben und sonstige private Auditfelder werden nicht in den Report übernommen.

Die Toolklassifikation `read_only` / `mutating` wird statisch aus den vorhandenen MCP-Deklarationen und `config/runtime-entrypoint.json` abgeleitet. Unbekannte Annotationen bleiben unbekannt und werden als Lücke ausgewiesen.

## Bewusste Grenze

Ordentliche read-only Toolaufrufe erzeugen derzeit keinen `effect-admission`-Datensatz. Deshalb ist ihre historische Nutzung mit dieser Quelle **nicht** messbar.

Insbesondere gilt nicht:

```text
kein effect-admission
        ↓
Tool unbenutzt
        ↓
Tool darf entfernt werden
```

Ein Tool ohne Mutations-Admission kann ein häufig genutzter read-only Pfad oder ein bewusst seltener Recovery-/Break-glass-Pfad sein.

Der Report führt deshalb `read_only_tool_usage` als `evidence_gap` und nennt `safe public tool removal` ausdrücklich unter `does_not_establish`.

Auch `grabowski_recovery_provenance_repair` ist absichtlich nicht vollständig über `effect-admission` messbar: ein erfolgreicher Integritäts-Reparaturlauf umgeht den normalen Transportnachweis und erzeugt deshalb keine Mutation-Admission. Der Analyzer führt diesen Pfad als eigene `mutation_tool_usage`-Evidenzlücke und nimmt ihn weder in die beobachteten noch in die unbeobachteten Mutations-Tools auf.

## Repository-Bindung

Ein Report wird nur aus einem sauberen Git-Checkout erzeugt. Der Analyzer bindet den Ausgangs-HEAD vor der Audit-Auswertung und prüft nach der Auswertung erneut, dass Checkout und HEAD unverändert und sauber sind. Bei Dirty-State oder HEAD-Drift bricht er ohne Report ab. Damit bleibt die statische Toolklassifikation später auf den angegebenen Commit rekonstruierbar.

## Nutzung

Mit dem bereits installierten Grabowski-Runtime-Python:

```bash
~/.local/share/grabowski-mcp/.venv/bin/python \
  tools/tool_surface_usage.py --repo . --window-hours 168
```

Optional kann der kanonische JSON-Report zusätzlich geschrieben werden:

```bash
~/.local/share/grabowski-mcp/.venv/bin/python \
  tools/tool_surface_usage.py \
  --repo . \
  --window-hours 168 \
  --output /tmp/grabowski-tool-surface-usage.json
```

Für reproduzierbare Tests oder historische Vergleiche kann `--now-unix` gesetzt werden. Das Zeitfenster ist beidseitig gebunden: nur Records mit `cutoff_unix <= timestamp_unix <= observed_at_unix` werden gezählt.

## P9-Regel

Dieser Report ist Eingangsevidenz, keine Löschentscheidung. Ein öffentliches Tool darf erst reduziert, internalisiert oder deprecatet werden, wenn zusätzlich seine Semantik, Compatibility-Rolle, Recovery-Relevanz, Toolketten und gegebenenfalls read-only Nutzung ausreichend belegt sind.

Damit bleibt P9 der Restplanregel treu: **nicht Toolzahl um ihrer selbst willen reduzieren, sondern einen alten öffentlichen Entscheidungsweg nur dann entfernen, wenn ein klarerer Pfad ihn tatsächlich ersetzt.**
