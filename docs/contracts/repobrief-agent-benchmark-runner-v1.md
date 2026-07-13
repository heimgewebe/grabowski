# RepoBrief Agent Benchmark Runner v1

Status: Implementierungs- und Qualifikationsvertrag für `RAB-V1-T002A`  
Autorität: read-only, nicht anwendend  
Standardaktivierung: `false`

## Zweck

Der Runner verbindet einen einzelnen, bereits durch Lenskit geplanten
Benchmark-Lauf mit Claude Code. Er verändert weder das Benchmark-Taskset noch
die Auswertungsregeln. Seine Aufgabe ist ausschließlich:

1. einen unveränderten Laufauftrag zu prüfen;
2. einen frischen Checkout des exakt registrierten Commits zu erzeugen;
3. nur die für Baseline oder Behandlung erlaubten read-only-Werkzeuge
   bereitzustellen;
4. das vollständige begrenzte Claude-Streamingprotokoll aufzubewahren;
5. Modell, Provider-Nutzung und Toolschritte in den Lenskit-Receipt-Vertrag zu
   normalisieren.

Der Runner ist kein MCP-Operatorwerkzeug. Er besitzt keine Berechtigung zum
Schreiben, Committen, Pushen, Mergen, Deployen, Wiederaufnehmen oder stillen
Wiederholen eines Laufs.

## Eingabe

Der Prozess liest genau ein JSON-Objekt von Standard Input. Es muss dem
Lenskit-Vertrag `repobrief.agent_benchmark_run_request` Version `1.0`
entsprechen.

Zusätzlich prüft der Runner streng:

- nur bekannte Felder;
- Bedingung `baseline` oder `treatment`;
- vollständigen Repositorybezug mit 40-stelligem Commit;
- Provider `anthropic-claude-code`;
- eine exakte Modell-ID mit Präfix `claude-`;
- den ausdrücklich leeren Samplingvertrag `{}` der Claude-CLI;
- Zeit-, Token-, Tool- und Bytegrenzen;
- frische Sitzung und frischen Arbeitsraum;
- keine Wiederverwendung zwischen Bedingungen;
- exakt die registrierte abstrakte Tool-Allowlist;
- bei Behandlung eine vollständige RepoBrief-Manifest- und MCP-Bindung.

Unbekannte oder nachträglich ergänzte Felder werden nicht ignoriert.

Zusätzlich ist `--request-root` verpflichtend. Dieses Verzeichnis enthält die
von Lenskit erzeugten JSON-Aufträge. Der Runner sucht genau eine Datei mit
derselben `request_id` und verlangt kanonische Inhaltsgleichheit mit dem
Standard-Input. Das Planverzeichnis ist damit die lokale Vertrauensquelle für
Taskset-Hash, Modell, Budget, Repository-Commit und MCP-Argumentliste. Es muss
operatorverwaltet, unverändert und nicht symbolisch verlinkt sein.

## Lokale Repository-Zuordnung

Der Runner nimmt keine frei gewählten Checkoutpfade aus dem Modellauftrag an.
Ein separat verwaltetes JSON-Dokument bindet die im Taskset verwendete
Repository-ID an den erwarteten Namen und einen lokalen Quellcheckout:

```json
{
  "lenskit": {
    "repository": "heimgewebe/lenskit",
    "root": "/home/alex/repos/lenskit"
  },
  "grabowski": {
    "repository": "heimgewebe/grabowski",
    "root": "/home/alex/repos/grabowski"
  },
  "weltgewebe": {
    "repository": "heimgewebe/weltgewebe",
    "root": "/home/alex/repos/weltgewebe"
  }
}
```

Repository-ID und `owner/name` müssen auf beiden Seiten übereinstimmen.

## Isolierter Checkout

Für jeden Auftrag wird aus der `workspace_id` ein eindeutiger, nicht
rückrechenbarer Verzeichnisname gebildet. Das Verzeichnis wird exklusiv mit
privaten Rechten angelegt. Existiert es bereits, bricht der Runner ab.

Danach wird lokal mit deaktivierten Hooks und ohne Hardlinks geklont, der
registrierte Commit detached ausgecheckt und ein sauberer Working Tree
verlangt. Dadurch gelangen keine Änderungen, unversionierten Dateien oder
Ergebnisse des Quellcheckouts in die Agentensitzung.

Der Runner löscht den Arbeitsraum nach dem Lauf nicht automatisch. Das erhält
forensische Evidenz. Bereinigung ist ein eigener Operatorvorgang.

## Baseline

Die Baseline stellt Claude ausschließlich diese eingebauten Werkzeuge bereit:

- `Read` → `read_file`;
- `Glob` → `glob`;
- `Grep` → `grep` beziehungsweise abstrakte Suche.

Nicht verfügbar sind unter anderem:

- `Bash`;
- `Write`;
- `Edit`;
- Webzugriff;
- Memory;
- fremde MCP-Server;
- RepoBrief-Werkzeuge.

## Behandlung

Die Behandlung erhält dieselben eingebauten read-only-Werkzeuge und genau einen
über den Laufauftrag gebundenen stdio-MCP-Server `repobrief`.

Zulässige zusätzliche Flächen sind:

- MCP-Ressourcen auflisten und lesen;
- `ask_context`;
- `grounding_verify`;
- `live_freshness`.

Der MCP-Startbefehl wird als Argumentliste übernommen, nicht als
Shell-Zeichenkette. `--strict-mcp-config` verhindert das Laden weiterer
Projekt-, Nutzer- oder Plugin-Server.

## Claude-Prozess

Der Livepfad startet Claude nicht interaktiv und ohne Sitzungsfortsetzung:

- `--safe-mode` zum Deaktivieren von Projekt- und Nutzeranpassungen bei erhaltener Authentisierung;
- `--no-chrome` zum Ausschalten der Browserintegration;
- `--disable-slash-commands` zum Ausschalten von Skills und Slash-Kommandos;
- Print-Modus `-p`;
- exakte `--model`-Bindung;
- `--output-format stream-json`;
- `--verbose`;
- partielle Nachrichten eingeschlossen;
- `--no-session-persistence`;
- `--permission-mode dontAsk`;
- strukturierte Ausgabe über den fest eingebauten JSON-Schema-Vertrag;
- explizite Tool- und Allowed-Tool-Listen;
- eine ausdrückliche Live-Freigabe über `--allow-live-provider`;
- eine pro Einzelaufruf verpflichtende Provider-Kostenschwelle über
  `--max-budget-usd`.

Fixture-Ausführung und Live-Freigabe schließen sich gegenseitig aus. Der Runner
prüft diese Grenze vor Request-Root, Repository-Map, Checkout und Transcript,
damit eine fehlende Freigabe keine einmalige Workspace-Identität verbraucht.

Die Umgebung wird auf eine kleine Allowlist reduziert. Der Runner übernimmt
nur Pfad-, Home-, Sprach-, Temp- und explizite Anthropic-API-Umgebungswerte.

Der Safe-Mode erhält die vom Claude-Client verwaltete Authentisierung, aktiviert
aber keine Projekt-Hooks, Skills, Plugins, MCP-Server oder Memory-Flächen. Die
weiterhin mögliche Auflistung installierter Katalogmetadaten im `system/init`
belegt keine Aktivierung; maßgeblich ist die streng validierte Tool-Liste.

Prozesszeit, Standardausgabe und Standardfehler sind begrenzt. Überschreitung,
Timeout, Startfehler oder nichtleerer Standardfehler führen zum Abbruch. Es
gibt keinen automatischen Retry.

Die Kostenschwelle wird an Claude weitergereicht und der gemeldete
`total_cost_usd`-Wert nach dem Lauf erneut gegen dieselbe Schwelle geprüft. Ein
Provider-Budgetfehler erzeugt keinen Erfolgsreceipt. Da eine bereits laufende
Provideranfrage die Schwelle technisch geringfügig überschreiten kann, ist die
Schwelle kein mathematisch harter Ausgabenstopp; der Live-Preflight muss deshalb
ein günstiges exaktes Modell, kleine Aufgaben und einen zusätzlichen
Gesamtbudget-Abbruch verwenden.

## Provider-Streamingprotokoll

Die vollständige JSONL-Standardausgabe wird als create-only Datei mit privaten
Rechten abgelegt. Der Receipt bindet:

- relativen Artefaktnamen;
- SHA-256;
- exakte Bytezahl.

Ein gültiger Stream benötigt genau:

- eine `system/init`-Nachricht;
- eine erfolgreiche `result`-Nachricht;
- dieselbe exakte Modell-ID wie im Auftrag;
- alle verpflichtenden read-only-Werkzeuge und keine unbekannten Werkzeuge;
- ganzzahlige, nichtnegative, vom Provider gemeldete Input- und Output-Tokens;
- eine strukturierte Abschlussantwort;
- zu jedem Toolaufruf genau ein zugehöriges Toolresultat.

Doppelte Tool-IDs, verwaiste Resultate, unbekannte Tools, fehlende Nutzung oder
Budgetüberschreitungen machen den Lauf ungültig.

Die Einzelwerkzeugdauer bleibt in v1 `0`, weil der gebundene CLI-Stream keinen
vertraglich stabilen Dauerwert pro Toolschritt garantiert. Die gesamte
Laufzeit wird gemessen und begrenzt. Das Rohprotokoll bleibt für spätere
Nachprüfung erhalten.

## Ausgabe

Bei Erfolg schreibt der Runner genau einen
`repobrief.agent_benchmark_run_receipt` Version `1.0` nach Standard Output.
Der Receipt enthält:

- Auftrag-ID und kanonischen Auftrag-SHA-256;
- Provider- und exakte Modellkennung;
- Provider-gemeldete Input- und Output-Tokens;
- normalisierte Toolaufrufe in Reihenfolge;
- strukturierte Antwort, Pfade, Symbole, Belege und Claim-Labels;
- Start, Ende, Gesamtdauer und Exitstatus;
- hashgebundenes Transcript-Artefakt;
- ausdrückliche Nichtaussagen.

Bei Fehler schreibt der Prozess eine kleine strukturierte Fehlermeldung nach
Standard Error und endet mit Status `2`. Er erzeugt keinen erfundenen
Erfolgsreceipt.

## Synthetischer Fixturemodus

`--stream-fixture` ersetzt ausschließlich den Claude-Prozess durch eine lokale
JSONL-Datei. Repositoryprüfung, isolierter Checkout, Transcript-Publikation und
Receipt-Normalisierung bleiben aktiv.

Dieser Modus gibt keinen Lenskit-Erfolgsreceipt aus. Er erzeugt einen
`repobrief.agent_benchmark_fixture_report`; dessen eingebetteter Kandidat trägt
absichtlich `provider.name=synthetic-fixture` und
`token_source=synthetic` und ist dadurch mit dem Real-Receipt-Vertrag
unvereinbar.

Dieser Modus belegt:

- Parser- und Vertragsverhalten;
- Fail-closed-Grenzen;
- Checkout-Isolierung;
- Transcript- und Receipt-Bindung.

Er belegt ausdrücklich nicht:

- vorhandene Providerzugänge;
- Liveverfügbarkeit der Claude-CLI;
- das tatsächliche aktuelle Provider-Envelope;
- reale Tokenwerte oder Kosten;
- Agentennutzen;
- Benchmarkabschluss;
- Standardbeförderung.

## Live-Preflight und Kosten

Nach gemergter T002A-Implementierung ist ein eigener, überprüfter Live-Preflight
notwendig. Dieser muss mindestens einen kleinen Baseline- und einen kleinen
Behandlungslauf ausführen und belegen:

- exakte Modellbindung;
- tatsächliches `system/init`-Format;
- tatsächliche kumulative Provider-Nutzung;
- tatsächliche Tool- und MCP-Ereignisse;
- gültigen Lenskit-Receipt;
- begrenzte Kosten;
- unveränderten Quellcheckout.

Der Dispatch muss die Kostenschwelle pro Lauf vorab festlegen, die im Transcript
gemeldeten tatsächlichen Kosten summieren und vor jedem weiteren Lauf prüfen.
Ein Lauf mit Budgetfehler oder gemeldeten Kosten oberhalb der Schwelle zählt
nicht als erfolgreicher Preflight.

Der Preflight und der vollständige 96-Lauf-Benchmark gehören nicht zu T002A.
Sie benötigen eine separate Dispatch-Entscheidung und ein explizites
Kostenlimit.

## Aufruf

Der Runner wird als Pythonprozess in die Lenskit-Runner-Konfiguration
aufgenommen:

```json
[
  "python3",
  "/absolute/path/to/tools/repobrief_agent_benchmark_runner.py",
  "--request-root",
  "/absolute/path/to/benchmark-plan/requests",
  "--repository-map",
  "/absolute/path/to/repositories.json",
  "--state-root",
  "/private/path/to/benchmark-state",
  "--transcript-root",
  "/private/path/to/benchmark-transcripts",
  "--allow-live-provider",
  "--max-budget-usd",
  "0.05"
]
```

Der vollständige Benchmarkauftrag wird vom Lenskit-Harness über Standard Input
übergeben.
