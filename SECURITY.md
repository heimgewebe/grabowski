# Security Policy

## Schutzgüter

- lokale Zugangsdaten,
- Git-Repositories,
- unveränderbare Evidence unter `~/repos/merges`,
- Benutzerkonfiguration,
- laufende Dienste,
- GitHub-Remotes und Versionsgeschichte.

## Unerlässliche Grenzen

- keine Ausgabe von Secrets,
- keine Mutation von Evidence,
- kein automatisches `sudo`,
- keine irreversible Löschung ohne Backup oder Papierkorb,
- kein Force-Push auf geschützte Hauptbranches,
- keine Mutation bei abweichendem Ausgangshash,
- Bestätigung für folgenreiche System- und Remote-Aktionen.

## Meldung eines Problems

Keine Secrets oder vollständigen Zugangsdaten in Issues veröffentlichen.
