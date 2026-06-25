# Reproduzierbares Deployment

## Ziel

Die laufende Grabowski-Runtime wird aus dem Git-Repository erzeugt. Ein
freigegebener Commit soll eine dependency-locked Runtime erzeugen, deren
Provenienz und tatsächlich gestartete Prozessidentität nachweisbar sind.

## Prüfung ohne Runtime-Mutation

```bash
make deploy-check
```

Der Check darf auch auf einem veränderten Arbeitsbaum laufen, weil er zur
Vorabvalidierung eines noch nicht committeten Patches dient. Er:

- erzeugt eine isolierte virtuelle Umgebung,
- installiert ausschließlich die versionierten, gehashten Runtime-Abhängigkeiten,
- führt `pip check` aus,
- kompiliert den MCP-Server,
- führt `initialize` und `tools/list` aus,
- prüft die erwarteten Werkzeuge,
- erzeugt und validiert ein Deployment-Manifest,
- verändert weder Runtime noch Dienst.

## Dependency-Lock

Die direkte Runtime-Abhängigkeit steht in:

```text
requirements/runtime.in
```

Der vollständige, gehashte Auflösungsstand steht in:

```text
requirements/runtime.lock.txt
```

Die Installation verwendet `pip --require-hashes`. Direkte URL-, VCS- und
editierbare Anforderungen sind im Lock-Vertrag verboten. Der Lock ist für
Python 3.10 auf Linux x86_64 aufgelöst; Python- und Plattform-Provenienz werden
im Manifest festgehalten.

Der Begriff `reproduzierbar` bedeutet hier: gleicher geprüfter Lock,
gleicher Quellstand und gleiche Zielplattform. Eine bitidentische virtuelle
Umgebung über beliebige Plattformen hinweg wird nicht behauptet.

## Produktives Deployment

```bash
make deploy
```

Das produktive Deployment verlangt einen sauberen Git-Arbeitsbaum. Der Ablauf:

1. exklusiven Deployment-Lock erwerben,
2. Repository-HEAD, Source-Hash und Lockfile-Hash erfassen,
3. neue Runtime isoliert im Staging erzeugen,
4. Syntax, MCP-Handshake und Werkzeugliste prüfen,
5. Provenienzmanifest schreiben,
6. Dienst stoppen,
7. vorhandene Runtime in einen datierten Rollback-Pfad verschieben,
8. Staging-Verzeichnis atomar an den Runtime-Pfad verschieben,
9. Dienst starten,
10. Health und Readiness prüfen,
11. deployten Source-Hash gegen den Repo-Source-Hash prüfen,
12. Tunnelprofil, systemd-ExecStart und laufenden MCP-Kindprozess prüfen,
13. Manifest-HEAD, Source-Hash und Lockfile-Hash zurücklesen und vergleichen.

## Deployment-Lock

Der exklusive Lock liegt unter:

```text
~/.local/state/grabowski/deploy.lock
```

Ein paralleler zweiter Lauf scheitert vor jeder Mutation. Der Dateiname eines
Rollback-Verzeichnisses ist kein Konkurrenzschutz; die Zustandsmaschine selbst
muss exklusiv sein.

## Runtime-Identität

Ein grüner HTTP-Listener genügt nicht als Identitätsbeleg. Nach dem Start wird
zusätzlich geprüft:

- die systemd-Unit startet den erwarteten Tunnel-Client mit Profil `grabowski`,
- das Tunnelprofil verweist auf die erwartete Runtime,
- ein Kindprozess der systemd-MainPID verwendet genau das deployte Python und
  `grabowski_mcp.py`,
- das Deployment-Manifest stimmt mit Repo-HEAD, Source-Hash und Lockfile-Hash
  überein.

`grabowski_status` gibt die nicht geheimen Manifestfelder aus, damit der
laufende Server seine Herkunft selbst belegen kann.

## Rollback

Scheitert ein Gate nach dem Runtime-Wechsel:

1. Dienst stoppen,
2. fehlerhafte Runtime unter einem datierten Failed-Pfad sichern,
3. vorherige Runtime zurückverschieben,
4. Dienst wieder starten,
5. Health und Readiness der wiederhergestellten Runtime prüfen.

Ein Fehler vor dem eigentlichen Runtime-Swap verändert die bestehende Runtime
nicht. Scheitert auch die Wiederherstellung oder wird sie nicht ready, endet
der Lauf mit einem explizit kritischen Fehler.

Die Tests injizieren Fehler vor und nach dem Swap sowie Readiness- und
Rollback-Fehler. Sie prüfen den Kontrollfluss, nicht nur das Vorkommen von
Quelltextfragmenten.

## Bewusste Grenzen

Das Werkzeug:

- verändert keine Tunnel-ID,
- verändert keine Zugriffspolicy,
- liest keine Runtime-Secrets,
- führt kein Git-Push aus,
- löscht alte Rollback-Runtimes nicht automatisch.

Eine spätere Retention-Regel muss Rollback- und Failed-Verzeichnisse explizit
und nachvollziehbar verwalten.

## Python-Kompatibilität

Der produktive Zielhost verwendet Python 3.10. Das Projekt unterstützt deshalb
Python ab Version 3.10. Die CI validiert Python 3.10 als Betriebsbaseline und
Python 3.12 als zusätzlichen Kompatibilitätspfad.
