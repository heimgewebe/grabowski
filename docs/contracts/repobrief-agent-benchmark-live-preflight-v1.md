# RepoBrief Agent Benchmark Live Preflight v1

Status: Ausführungs- und Evidenzvertrag für `RAB-V1-T002B`  
Autorität: read-only, nicht anwendend  
Standardaktivierung: `false`

## Zweck

Der Preflight prüft, ob der separat qualifizierte Grabowski-Runner mit dem
tatsächlichen Claude-Provider und dem gebundenen RepoBrief-MCP funktioniert.
Er führt genau ein bereits von Lenskit geplantes Paar aus:

- eine Baseline ohne RepoBrief;
- eine Behandlung mit denselben read-only Werkzeugen plus RepoBrief.

Der Preflight ist kein verkleinerter Nutzenbenchmark. Zwei Läufe können weder
einen allgemeinen Vorteil noch eine Aufgabenklassenwirkung belegen.

## Feste Begrenzung

- genau eine `pair_id` aus dem unveränderten Lenskit-Planverzeichnis;
- genau ein Baseline- und ein Treatment-Auftrag;
- keine Änderung von Prompt, Modell, Sampling, Budgets, Commit oder Toolpolicy;
- maximal `1.00 USD` je Providerprozess;
- maximal `2.00 USD` autorisierte Gesamtkosten;
- kein Retry, keine Sitzungsfortsetzung und keine automatische Fortsetzung mit
  weiteren Fällen;
- jeder Fehler beendet den Preflight.

Der Runner übergibt die Operatorgrenze vor dem Prozessstart als
`--max-budget-usd` an Claude. Zusätzlich muss das Providerresultat ein
endliches, nichtnegatives `total_cost_usd` liefern, das dieselbe Grenze nicht
überschreitet.

## Vorbereitung und Freshness

Der Preflight erzeugt keinen Snapshot. Er prüft den bereits gebundenen
Manifestpfad und dessen SHA-256 und kennzeichnet den Stand deshalb als:

- `snapshot_reused=true`;
- `snapshot_rebuilt=false`.

Vor dem Treatment wird derselbe request-gebundene MCP-Befehl direkt gestartet.
Der Preflight führt `initialize` und anschließend `live_freshness` aus. Nur
`status=fresh` erlaubt den Providerstart. `stale`, `unknown`,
`not_comparable`, MCP-Fehler oder Timeout beenden den Lauf ohne Retry.

Die Zeiten werden getrennt erfasst:

- `snapshot_preparation_ms` — Manifest- und Digestprüfung;
- `freshness_check_ms` — MCP-Start und Freshness-Aufruf;
- `agent_execution_ms` — beide Providerprozesse zusammen;
- `total_time_to_answer_ms` — gesamter Preflight.

Dadurch wird Snapshot- oder Freshnessaufwand nicht als vermeintlich schnelle
Agentenzeit verborgen.

## Paar- und Isolationsvertrag

Baseline und Treatment müssen übereinstimmen bei:

- Fall, Wiederholung und Taskset;
- Repository und Commit;
- Prompt;
- Modell und Sampling;
- Budgets.

Sie müssen unterschiedliche Session- und Workspace-Identitäten besitzen.
Jeder Runnerlauf erzeugt einen frischen, create-only Checkout des gebundenen
Commits. Der Quellcheckout wird vor und nach dem Paar über folgende Werte
gebunden:

- `HEAD`;
- Clean-Status;
- SHA-256 des Statusauszugs;
- SHA-256 des Git-Index.

Jede Abweichung macht den Preflight ungültig.

## Lenskit-Validierung

Jeder reale Receipt wird über den gemergten Lenskit-Befehl
`agent_benchmark validate-receipt` gegen den exakten Auftrag und das
Transcript-Verzeichnis geprüft. Ein formal ähnlicher Grabowski-Receipt reicht
nicht aus.

Die Behandlung muss mindestens einen normalisierten RepoBrief-Aufruf enthalten:

- `ask_context`;
- `grounding_verify`;
- `live_freshness`;
- oder `repobrief_resource_read`.

Die Baseline darf keinen dieser Aufrufe enthalten.

## Evidenz

Der Bericht bindet:

- beide Auftrag- und Receipt-SHA-256;
- beide Transcriptpfade, -größen und -SHA-256;
- Claude-Version und Laufzeitumgebung;
- exakte Modell- und Tokenbelege in den Receipts;
- beobachtete und autorisierte Kosten;
- Snapshot- und Freshnessstatus;
- getrennte Zeitwerte;
- Quellzustand vor und nach dem Paar.

Der endgültige Bericht wird zusammen mit Receipts und Transkripten als
reviewbares Artefakt veröffentlicht und außerhalb des Berichts erneut per
SHA-256 gebunden.

## Stopregeln

Der Preflight endet ohne Retry bei:

- Provider- oder Claude-CLI-Ausfall;
- Kosten-, Zeit-, Token-, Tool- oder Bytegrenze;
- fehlendem oder widersprüchlichem Modell-/Session-/Usage-Beleg;
- ungültigem Lenskit-Receipt;
- fehlendem RepoBrief-Aufruf im Treatment;
- RepoBrief-Aufruf in der Baseline;
- nicht frischem Snapshot;
- Quellmutation;
- unvollständigem Transcript.

In jedem dieser Fälle bleibt `RAB-V1-T002` geplant und gesperrt.

## Synthetische Prüfung

Für Unit-Tests dürfen zwei lokale Streaming-Fixtures verwendet werden. Das
Ergebnis trägt den eigenen Typ
`repobrief.agent_benchmark_preflight_fixture_report` und den Zustand
`synthetic_only`. Es enthält keine beobachteten Providerkosten und kann den
Live-Preflight nicht erfüllen.

## Nichtaussagen

Der Preflight belegt nicht:

- RepoBrief-Nutzen;
- Abschluss des 96-Lauf-Benchmarks;
- Providerzuverlässigkeit jenseits der zwei Läufe;
- Antwortkorrektheit außerhalb des gewählten Falls;
- Standardbeförderung;
- Erlaubnis, den Vollbenchmark automatisch zu starten.
