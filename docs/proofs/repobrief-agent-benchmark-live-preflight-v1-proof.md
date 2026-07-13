# RepoBrief Agent Benchmark Live Preflight v1 — Implementierungsnachweis

Status: Implementierungskandidat; kein Live-Providerbeleg  
Bureau: `RAB-V1-T002B`  
Pull Request: `heimgewebe/grabowski#186`

## Integrationsstand

Der Runner-, Authentifizierungs- und Livefreigabevertrag stammt unverändert aus
dem gemergten PR `heimgewebe/grabowski#182`. Der kanonische Preflight-Starter
ist ein kleiner Adapter vor dem unveränderten Orchestrator-Core:

- Fixture: `allow_live_provider=false`, kein Providerbudget;
- echter Lauf: `allow_live_provider=true`, operatorgebundenes
  `max_budget_usd`;
- Preflightobergrenze: höchstens `1.00 USD` je Prozess.

Dadurch existiert keine zweite Runnerimplementierung und keine Umgehung der in
PR #182 eingeführten Livefreigabe.

## Gelieferte Fläche

- hartes operatorseitiges Kostenlimit je Claude-Prozess;
- Weitergabe als `--max-budget-usd` vor Prozessstart;
- nachträgliche Prüfung von `total_cost_usd`;
- genau ein eingefrorenes Baseline-/Treatment-Paar;
- Manifest- und Digestprüfung ohne impliziten Snapshot-Rebuild;
- direkte MCP-Freshness-Prüfung vor dem Treatment;
- getrennte Snapshot-, Freshness-, Provider-, Runner- und Gesamtzeiten;
- verpflichtende RepoBrief-Nutzung im Treatment;
- externe Lenskit-Receipt-Prüfung;
- Quellcheckout-Readback vor und nach dem Paar;
- hashgebundene Programm-, Auftrags-, Receipt- und Transcript-Evidenz;
- synthetischer Fixturebericht, der keinen Realreceipt darstellt.

## Sicherheitsgrenzen

- maximal `1.00 USD` je Preflight-Prozess;
- maximal zwei Providerprozesse;
- kein Retry und keine Sitzungsfortsetzung;
- kein automatischer Vollbenchmark;
- kein Schreiben, Committen, Pushen, Mergen oder Deployen;
- Anthropic-Zugangsdaten werden nur dem Claude-Prozess zugänglich gemacht;
- Freshness- und Lenskit-Prüfprozesse laufen ohne Providergeheimnisse und mit
  nicht realem `HOME`;
- jeder widersprüchliche oder unvollständige Beleg beendet den Preflight.

## Synthetische Prüfung

Lokale Ersatzprozesse prüfen:

- JSON-RPC-Freshness;
- Baseline-/Treatment-Trennung;
- Kosten-, Tool- und Transcriptgrenzen;
- Lenskit-Validatorverkabelung;
- Quellintegrität;
- gemeinsame Veröffentlichung von Bericht und SHA-256-Begleitdatei;
- Autorisierungsadapter zwischen Preflight-Core und gehärtetem Runner.

Diese Fixtures tragen `synthetic_only` und belegen keine Providerverfügbarkeit.

## Offener Livebeleg

Nach Merge ist genau ein realer Preflight auf einem Operatorrechner mit bereits
vorhandener Claude-Anmeldung zulässig. Er darf den 96-Lauf-Benchmark nicht
automatisch starten. Der Livebeleg muss beide gültigen Receipts, beide
Transkripte, beobachtete Kosten, Freshnessstatus, Zeitzerlegung und
Quellintegrität enthalten.

## Nichtaussagen

Dieser Implementierungsnachweis belegt nicht:

- RepoBrief-Nutzen;
- Claude-Liveverfügbarkeit des eingefrorenen Paars;
- reale Token- oder Kostenwerte des eingefrorenen Paars;
- Abschluss von `RAB-V1-T002B`;
- Erlaubnis für `RAB-V1-T002`;
- Standardbeförderung.
