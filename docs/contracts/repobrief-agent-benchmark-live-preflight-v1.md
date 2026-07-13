# RepoBrief Agent Benchmark Live Preflight v1

Status: Ausführungs- und Evidenzvertrag für `RAB-V1-T002B`  
Autorität: read-only, nicht anwendend  
Standardaktivierung: `false`

## Zweck

Der Preflight prüft, ob der qualifizierte Grabowski-Runner mit dem tatsächlichen
Claude-Provider und dem gebundenen RepoBrief-MCP funktioniert. Er verarbeitet
genau ein bereits durch Lenskit geplantes Paar:

- eine Baseline mit `Read`, `Glob` und `Grep` sowie leerer MCP-Konfiguration;
- ein Treatment mit denselben read-only Werkzeugen und ausschließlich dem
  gebundenen RepoBrief-MCP.

Zwei Läufe können keinen allgemeinen RepoBrief-Nutzen belegen.

## Feste Grenzen

- genau eine unveränderte `pair_id` aus dem Lenskit-Planverzeichnis;
- genau ein Baseline- und ein Treatment-Auftrag;
- keine Änderung von Prompt, Modell, Sampling, Budgets, Commit oder Toolpolicy;
- maximal `1.00 USD` je Providerprozess;
- maximal zwei Providerprozesse und `2.00 USD` autorisierte Gesamtkosten;
- kein Retry, keine Sitzungsfortsetzung und kein automatischer Vollbenchmark;
- jeder Fehler beendet den Preflight.

Die Kostenobergrenze wird vor dem Prozessstart als `--max-budget-usd` an
Claude übergeben. Danach muss das Providerresultat ein endliches,
nichtnegatives `total_cost_usd` liefern, das dieselbe Grenze nicht
überschreitet. Eine bereits laufende Provideranfrage kann geringfügig über die
Grenze hinauslaufen; deshalb prüft der Orchestrator zusätzlich die beobachteten
Paar-Gesamtkosten und wiederholt den Lauf nicht.

## Live-Providerbindung

Ein echter Preflight benötigt zusätzlich:

- `--claude-command` als absoluten Pfad zu einer regulären, ausführbaren und
  nicht symbolisch verlinkten Datei;
- `--claude-command-sha256` als erwarteten SHA-256 dieses Programms;
- `--claude-credential-file` als reguläre, nicht symbolisch verlinkte und nur
  für den Eigentümer lesbare OAuth-Datei.

Der Runner prüft Programm und Credentialdatei vor jedem Liveaufruf gegen
Größe, Typ, Änderungsrennen und Digest. Die Credentialdatei wird in ein
frisches privates auth-only `CLAUDE_CONFIG_DIR` kopiert und nach dem Lauf
entfernt. Nutzer-, Projekt- und lokale Claude-Einstellungen, Hooks, Skills,
Workflows, Browserintegration und Claude.ai-Connectoren werden deaktiviert.

Fixtureläufe dürfen weder Credentialdatei noch Programm-SHA erhalten. Ihr
Ergebnis trägt den eigenen Typ
`repobrief.agent_benchmark_preflight_fixture_report` und den Zustand
`synthetic_only`.

## Paar- und Isolationsvertrag

Baseline und Treatment müssen übereinstimmen bei:

- Fall, Wiederholung und Taskset;
- Repository und Commit;
- Prompt;
- Modell und Sampling;
- Budgets.

Sie müssen unterschiedliche Session- und Workspace-Identitäten besitzen.
Jeder Runnerlauf erzeugt einen frischen create-only Checkout des gebundenen
Commits. Der Quellcheckout wird vor und nach dem Paar gebunden über:

- `HEAD`;
- Clean-Status;
- SHA-256 des Statusauszugs;
- SHA-256 des Git-Index.

Jede Abweichung macht den Preflight ungültig.

## Snapshot und Freshness

Der Preflight erzeugt keinen Snapshot. Er prüft den gebundenen Manifestpfad,
die Größenbegrenzung und dessen SHA-256. Der Bericht trägt deshalb:

- `snapshot_reused=true`;
- `snapshot_rebuilt=false`.

Vor dem Treatment wird der request-gebundene MCP-Befehl direkt gestartet. Der
Preflight führt `initialize` und `live_freshness` aus. Nur `status=fresh`
erlaubt den Providerstart. `stale`, `unknown`, `not_comparable`, MCP-Fehler oder
Timeout beenden den Lauf ohne Retry.

Freshness- und Lenskit-Prüfprozesse erhalten keine Anthropic-Zugangsdaten und
ein nicht reales `HOME`.

## Zeitmessung

Der Bericht trennt:

- `snapshot_preparation_ms` — Manifest- und Digestprüfung;
- `freshness_check_ms` — MCP-Start und Freshness-Aufruf;
- `agent_execution_ms` — Providerlaufzeiten aus den Receipts;
- `runner_execution_ms` — vollständige Runneraufrufe einschließlich Checkout
  und Evidenzpublikation;
- `total_time_to_answer_ms` — gesamter Preflight.

Damit werden Snapshot-, Freshness- und Isolationskosten nicht als vermeintlich
schnelle Agentenzeit verborgen.

## Lenskit-Validierung und Werkzeuge

Jeder reale Receipt wird über den gemergten Lenskit-Befehl
`agent_benchmark validate-receipt` gegen den exakten Auftrag und das
Transcript-Verzeichnis geprüft. Der Validator läuft ohne Providergeheimnisse.

Das Treatment muss mindestens einen normalisierten RepoBrief-Aufruf enthalten:

- `ask_context`;
- `grounding_verify`;
- `live_freshness`;
- oder `repobrief_resource_read`.

Die Baseline darf keinen dieser Aufrufe enthalten. Ihre MCP-Konfiguration ist
leer und `mcp__*` ist ausdrücklich untersagt.

## Evidenz

Der Bericht bindet:

- beide Auftrag- und Receipt-SHA-256;
- beide Transcriptpfade, -größen und -SHA-256;
- Claude-Version sowie Pfad, Größe und SHA-256 des gestarteten Programms;
- Digest des Lenskit-Validatorbefehls und der Validatorergebnisse;
- Provider-gemeldete Modell-, Token-, Tool- und Kostenwerte;
- Snapshot- und Freshnessstatus;
- getrennte Zeitwerte;
- Quellzustand vor und nach dem Paar.

Bericht und gleichnamige `.sha256`-Datei werden gemeinsam create-only
veröffentlicht. Bei einem Fehler werden beide entfernt.

## Stopregeln

Der Preflight endet ohne Retry bei:

- Provider-, Claude-CLI- oder Authentifizierungsfehler;
- Kosten-, Zeit-, Token-, Tool- oder Bytegrenze;
- fehlendem oder widersprüchlichem Modell-, Session- oder Usage-Beleg;
- ungültigem Lenskit-Receipt;
- fehlendem RepoBrief-Aufruf im Treatment;
- RepoBrief-Aufruf in der Baseline;
- nicht frischem Snapshot;
- Quellmutation;
- unvollständigem Transcript;
- Programm-, Credential- oder Digestabweichung.

In jedem dieser Fälle bleibt `RAB-V1-T002` geplant und gesperrt.

## Nichtaussagen

Der Preflight belegt nicht:

- RepoBrief-Nutzen;
- Abschluss des 96-Lauf-Benchmarks;
- Providerzuverlässigkeit jenseits der zwei Läufe;
- Antwortkorrektheit außerhalb des gewählten Falls;
- Standardbeförderung;
- Erlaubnis, den Vollbenchmark automatisch zu starten.
