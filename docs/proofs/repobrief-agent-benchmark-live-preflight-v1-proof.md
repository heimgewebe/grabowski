# RepoBrief Agent Benchmark Live Preflight v1 — Implementierungsnachweis

Status: T002C-Implementierungskandidat; ausschließlich synthetisch geprüft
Bureau: `RAB-V1-T002C`
Pull Request: `heimgewebe/grabowski#186`

## Integrationsstand

Die Runner-, Authentifizierungs- und Providergrenze stammt unverändert aus den
gemergten PRs `#182` und `#185` (`1975c3f5c63fcb0e50f3f3d1101a34583d5a9fbd`).
PR #186 ist mit Grabowski-`main` `e72e012818525ee785a3cc76c0c05b741b72b2eb`
synchronisiert und ergänzt keine zweite Runnerimplementierung. Er liefert:

- einen kanonischen Autorisierungsadapter;
- einen davon getrennten, umfangreich getesteten Preflight-Core;
- einen create-only, paar- und codegebundenen Dispatch-Ledger;
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
- create-only Autorisierung und hashverkettete Dispatch-, Erfolgs- und
  Fehlerereignisse vor und nach jedem möglichen Prozessstart;
- dauerhafte Sperre nach Erfolg, Fehler, unklarem Start oder unterbrochener
  Berichtspublikation;
- Erhalt providerseitig beobachteter Kosten einschließlich Budgetüberschreitung;
- synthetischer Fixturebericht, der keinen Realreceipt darstellt.

## Sicherheitsgrenzen

- maximal `1.00 USD` je Preflight-Prozess;
- maximal zwei Providerprozesse;
- kein dritter Claude-Prozess für eine Versionsprobe; die Programmidentität wird ausschließlich aus Pfad, Größe und SHA-256 gebildet;
- kein Retry und keine Sitzungsfortsetzung;
- maximal ein Baseline- und ein Treatmentintent; vorhandener oder unvollständiger
  Ledger blockiert jeden weiteren Start;
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

- JSON-RPC-Freshness und Stale-Stop ohne Prozessintent;
- Baseline-/Treatment-Trennung;
- erfolgreiche One-shot-Ausführung mit hashverkettetem Ledger;
- erneuten Start bei identischer oder geänderter Bindung;
- Auftrags- und Credentialmutation zwischen Baseline und Treatment;
- unklaren Prozessstart und fehlendes Transcript;
- Budgetstopp mit erhaltener beobachteter Überschreitung;
- doppeltes Bedingungsintent, drittes Prozessintent und Artefaktüberschreibung;
- Quellmutation nach beiden Läufen;
- vorbestehenden Receipt- oder Reportpfad vor jedem Prozessintent;
- unterbrochene Abschlussveröffentlichung durch Wiederanlauf nach Core-Erfolg;
- vollständigen synthetischen CLI-Pfad mit gebundenem Report und Digest;
- Kosten-, Tool-, Credential-, Programm- und Transcriptgrenzen;
- Lenskit-Validatorverkabelung;
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

## Separat gesperrter Livebeleg

PR #186 und `RAB-V1-T002C` autorisieren keinen Providerstart. Erst der getrennte
Bureau-Task `RAB-V1-T002D` darf nach geprüftem Merge und Main-Readback eine neue,
exakt gebundene Einmalfreigabe für höchstens einen Baseline- und einen
Treatmentprozess erhalten. Der alte T002B-Fehlversuch darf weder fortgesetzt
noch als Teil dieses Paars wiederverwendet werden.

Ein späterer T002D-Livebeleg muss beide gültigen Receipts, beide Transkripte,
beobachtete Kosten, Freshnessstatus, Zeitzerlegung, Programm-/Credentialbindung,
Dispatch-Ledger und Quellintegrität enthalten. Jeder Fehler beendet T002D ohne
Retry und lässt `RAB-V1-T002` gesperrt.

## Nichtaussagen

Dieser Implementierungsnachweis belegt nicht:

- RepoBrief-Nutzen;
- Claude-Liveverfügbarkeit des eingefrorenen Paars;
- reale Token- oder Kostenwerte des eingefrorenen Paars;
- einen gültigen Ersatz für den fehlgeschlagenen `RAB-V1-T002B`;
- Autorisierung oder Abschluss von `RAB-V1-T002D`;
- Erlaubnis für `RAB-V1-T002`;
- Standardbeförderung.
