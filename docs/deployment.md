# Reproduzierbares Deployment

## Ziel

Die laufende Grabowski-Runtime wird aus dem Git-Repository erzeugt und nicht
mehr manuell gepflegt.

## Prüfung ohne Runtime-Mutation

```bash
make deploy-check
```

Der Check darf auch auf einem veränderten Arbeitsbaum laufen, weil er zur
Vorabvalidierung eines noch nicht committeten Patches dient. Er:

- erzeugt eine isolierte virtuelle Umgebung,
- installiert das Repository,
- kompiliert den MCP-Server,
- führt `initialize` und `tools/list` aus,
- prüft die erwarteten Werkzeuge,
- verändert weder Runtime noch Dienst.

## Produktives Deployment

```bash
make deploy
```

Das produktive Deployment verlangt einen sauberen Git-Arbeitsbaum. Der Ablauf:

1. Repository-HEAD und Source-Hash erfassen,
2. neue Runtime isoliert im Staging erzeugen,
3. Syntax, MCP-Handshake und Werkzeugliste prüfen,
4. Dienst stoppen,
5. vorhandene Runtime in einen datierten Rollback-Pfad verschieben,
6. Staging-Verzeichnis atomar an den Runtime-Pfad verschieben,
7. Dienst starten,
8. Health und Readiness prüfen,
9. deployten Source-Hash gegen den Repo-Source-Hash prüfen.

## Rollback

Scheitert ein Gate nach dem Runtime-Wechsel:

1. Dienst stoppen,
2. fehlerhafte Runtime unter einem datierten Failed-Pfad sichern,
3. vorherige Runtime zurückverschieben,
4. Dienst wieder starten,
5. Health und Readiness der wiederhergestellten Runtime prüfen.

Ein Fehler vor dem eigentlichen Runtime-Swap verändert die bestehende Runtime
nicht.

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
