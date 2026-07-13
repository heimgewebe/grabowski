# RepoBrief Agent Benchmark Live Preflight v1 — Implementierungsnachweis

Status: Implementierungskandidat; kein eingefrorenes Live-Paar  
Bureau: `RAB-V1-T002B`  
Pull Request: `heimgewebe/grabowski#186`

## Integrationsstand

Die Runner-, Authentifizierungs- und Providergrenze stammt unverändert aus den
gemergten PRs `#182` und `#185`. PR #186 ergänzt keine zweite
Runnerimplementierung. Er liefert:

- einen kanonischen Autorisierungsadapter;
- einen davon getrennten, umfangreich getesteten Preflight-Core;
- Preflighttests, Betriebsvertrag und diesen Nachweis.

Der Adapter übersetzt ausschließlich die Orchestratorgrenze in den finalen
Runnervertrag:

- Fixture: keine Livefreigabe, kein Providerbudget, keine Credentials und kein
  Programm-SHA;
- echter Lauf: `allow_live_provider=true`, operatorgebundenes
  `max_budget_usd`, private OAuth-Datei und SHA-256-gebundenes absolutes
  Claude-Programm;
- Preflightobergrenze: höchstens `1.00 USD` je Prozess.

Ein direkter Start der Core-Datei bleibt fail-closed, weil dort die
providerbezogenen Adapterbindungen fehlen.

## Gelieferte Fläche

- genau ein eingefrorenes Baseline-/Treatment-Paar;
- Manifest-, Größen- und Digestprüfung ohne impliziten Snapshot-Rebuild;
- direkte MCP-Freshness-Prüfung vor dem Treatment;
- getrennte Snapshot-, Freshness-, Provider-, Runner- und Gesamtzeiten;
- verpflichtende RepoBrief-Nutzung im Treatment und Verbot in der Baseline;
- externe Lenskit-Receipt-Prüfung ohne Providergeheimnisse;
- Quellcheckout-Readback vor und nach dem Paar;
- hashgebundene Programm-, Auftrags-, Receipt-, Validator- und
  Transcript-Evidenz;
- gemeinsame create-only Veröffentlichung von Bericht und SHA-256-Datei;
- synthetischer Fixturebericht, der keinen Realreceipt darstellt.

## Sicherheitsgrenzen

- maximal `1.00 USD` je Preflight-Prozess;
- maximal zwei Providerprozesse;
- kein Retry und keine Sitzungsfortsetzung;
- kein automatischer Vollbenchmark;
- kein Schreiben, Committen, Pushen, Mergen oder Deployen;
- OAuth-Daten werden nur in ein frisches privates auth-only
  `CLAUDE_CONFIG_DIR` kopiert und danach entfernt;
- Claude-Programm und Credentialdatei werden gegen Typ, Rechte, Größe,
  Änderungsrennen und SHA-256 geprüft;
- Baseline erhält eine leere MCP-Konfiguration; Treatment ausschließlich den
  request-gebundenen RepoBrief-Server;
- Freshness- und Lenskit-Prüfprozesse laufen ohne Providergeheimnisse und mit
  nicht realem `HOME`;
- jeder widersprüchliche oder unvollständige Beleg beendet den Preflight.

## Synthetische Prüfung

Lokale Ersatzprozesse prüfen:

- JSON-RPC-Freshness und Stale-Stop;
- Baseline-/Treatment-Trennung;
- Kosten-, Tool-, Credential-, Programm- und Transcriptgrenzen;
- Lenskit-Validatorverkabelung;
- Quellintegrität;
- gemeinsame Bericht-/Digestpublikation;
- Adapterbindung an den finalen Runnervertrag.

Diese Fixtures tragen `synthetic_only` und belegen keine Providerverfügbarkeit.

## Repositoryprüfung

Der integrierte Kandidat bestand auf Python 3.10 und 3.12:

- vollständige Grabowski-Repositoryvalidierung;
- sämtliche Runner- und Preflighttests;
- Policy-, Secret- und generierte-Kontextprüfungen;
- reproduzierbares Deployment-Staging.

Der endgültige Head, Diff-SHA-256 und die kritische Self-Review werden als
PR-Metadaten nach dem letzten Main-Sync gebunden.

## Offener Livebeleg

Nach Merge ist genau ein realer Preflight auf einem Operatorrechner mit bereits
vorhandener Claude-Anmeldung zulässig. Er darf den 96-Lauf-Benchmark nicht
automatisch starten. Der Livebeleg muss beide gültigen Receipts, beide
Transkripte, beobachtete Kosten, Freshnessstatus, Zeitzerlegung,
Programm-/Credentialbindung und Quellintegrität enthalten.

## Nichtaussagen

Dieser Implementierungsnachweis belegt nicht:

- RepoBrief-Nutzen;
- Claude-Liveverfügbarkeit des eingefrorenen Paars;
- reale Token- oder Kostenwerte des eingefrorenen Paars;
- Abschluss von `RAB-V1-T002B`;
- Erlaubnis für `RAB-V1-T002`;
- Standardbeförderung.
