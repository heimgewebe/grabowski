# Provider-Quota-Observability v1

Status: implementierter Runtime-Vertrag
Datum: 2026-08-02

## Zweck

Der Coding-Agent-Router besitzt bereits dynamische Poolfelder für `remaining_ratio`, `reset_at`, `status`, Reservegrenzen und Cooldowns. Dieser Vertrag ergänzt die fehlende automatische Evidenzzufuhr. Er erfindet keine Quote und erweitert keine Ausführungs- oder Kostenautorität.

## Evidenzhierarchie

1. Ein frisches, lokal gespeichertes Provider-Receipt mit explizitem Verbrauch und Resetzeit.
2. Ein manuell gesetzter, validierter `set-quota`-Stand.
3. Zugang, Tarif oder Modellverfügbarkeit ohne Quotenmetadaten.
4. Unbekannte Quote.

Ein bloßer Login, ein Abonnementname oder eine erfolgreiche Modellliste wird niemals in eine Restquote umgerechnet.

## Codex-Collector

Der Probe-Scheduler liest unter `%h/.codex/sessions` höchstens vier aktuelle Tagesverzeichnisse und 128 ownergebundene `0600`-Rollout-Dateien. Pro durchlaufenem Verzeichnis werden höchstens 512 Einträge aufgelistet; beschreibbare oder fremde Verzeichnisse werden verworfen. Pro Datei werden höchstens die letzten 256 KiB gelesen; über einen Lauf werden höchstens 32 MiB ausgewertet, und die Gesamtdatei darf höchstens 16 MiB groß sein. Symlinks, Mehrfachlinks, fremde Eigentümer, unsichere Dateimodi, veränderte Dateien und unplausible Werte werden verworfen.

Akzeptiert werden ausschließlich frische `event_msg`-Receipts mit:

- `limit_id = codex`
- mindestens eines der Fenster `primary`, `secondary` oder `individual_limit`
- je Fenster `used_percent` zwischen 0 und 100
- je Fenster positive `window_minutes` und eine plausible zukünftige Unix-Resetzeit `resets_at`
- höchstens 36 Stunden alter, zeitzonengebundener Beobachtungszeit

Der Scheduler normalisiert:

- für jedes vorhandene Fenster `remaining_ratio = 1 - used_percent / 100`
- als Routerwert das Fenster mit der kleinsten Restquote; bei Gleichstand das später zurückgesetzte Fenster
- `status = exhausted`, sobald irgendein Fenster 100 Prozent, ein Rate-Limit-Typ oder ein Spend-Control-Limit gemeldet wird
- andernfalls `status = available`
- alle Fenster im Receipt und das begrenzende Fenster als `limiting_window`
- `reset_at` des begrenzenden Fensters als UTC-RFC3339

Die Beobachtung wird SHA-256-gebunden und über den bestehenden `agent-route set-quota`-Vertrag in `openai-agentic` geschrieben. Danach müssen Router-State und `agent-route status` exakt denselben Poolstand bestätigen. Historie, Katalog, Routen und andere Pools dürfen sich nicht ändern.

## Andere Provider

Claude, Grok, Antigravity, Jules, OpenCode und OpenHands liefern in den aktuell installierten, metadata-only verwendbaren Oberflächen keine belastbare Restquote samt Resetzeit. Für diese Pools wird deshalb kein synthetischer Wert geschrieben. Ihr Zustand bleibt `opaque` beziehungsweise `unknown`, bis ein gleichwertiges Provider-Receipt verfügbar ist.

## Kosten- und Sicherheitsgrenzen

- keine Modellinvokation
- keine API-Key-Nutzung
- keine Autorisierung gekaufter Credits
- kein PAYG- oder Overage-Fallback
- kein automatisches Umschalten auf kostenpflichtige Routen
- keine Aussage über Quote nach dem Beobachtungszeitpunkt
- keine Provider-Authentizitätsbehauptung über die ownergebundene lokale Receipt-Ablage hinaus

Ein beobachteter Restwert unterhalb der statischen `reserve_floor` sperrt nichtkritische externe Nutzung über die bestehende Routerlogik. Kritische Ausnahmen behalten ihre bisherigen, separat geprüften Regeln.

## Betriebsfolge

`grabowski-coding-agent-probe.timer` führt weiterhin ausschließlich metadata-only Arbeit aus. Nach der Zugangssonde wird die lokale Quotenbeobachtung ausgewertet. Fehlt frische Evidenz, bleibt ein vorhandener Poolstand unverändert und das Receipt meldet `quota_state_updated=false`. Ist dessen gebundene `reset_at`-Zeit jedoch bereits abgelaufen, setzt der Scheduler den Pool über `set-quota` auf `unknown` zurück und entfernt den alten Restwert. Dadurch entsteht weder eine Verfügbarkeitsbehauptung noch eine dauerhafte Scheinsperre durch eine abgelaufene `remaining_ratio=0`.
