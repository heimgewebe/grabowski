# Security Policy

## Schutzgüter

- lokale Zugangsdaten,
- Git-Repositories,
- unveränderbare Evidence unter `~/repos/merges`,
- Benutzerkonfiguration,
- laufende Dienste,
- GitHub-Remotes und Versionsgeschichte.

## Unerlässliche Grenzen

- keine Secret-Ausgabe über generische Werkzeuge; dedizierte Secret-Reveals
  sind capability- und SHA-256-gebunden,
- keine Secret-Werte in Audit, Evidence, Prozess-argv oder Environment,
- keine Mutation von Evidence,
- kein automatisches `sudo`,
- keine irreversible Löschung ohne Backup oder Papierkorb,
- kein Force-Push auf geschützte Hauptbranches,
- keine Mutation bei abweichendem Ausgangshash,
- Bestätigung für folgenreiche System- und Remote-Aktionen.

## Meldung eines Problems

Keine Secrets oder vollständigen Zugangsdaten in Issues veröffentlichen.
