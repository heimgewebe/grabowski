# Agent Instructions

## Arbeitsregel

Erst diagnostizieren, dann ändern.

Vor jeder Mutation müssen mindestens vorliegen:

- konkreter Zielpfad,
- belegter Ist-Zustand,
- erwarteter Zielzustand,
- passende Tests oder Validierung,
- Stop-Kriterium,
- Rückrollpfad.

## Verbotene Abkürzungen

- keine erfundenen Dateien oder Pfade,
- kein stilles Überschreiben fremder Änderungen,
- keine Secrets in Logs, Commits oder Ausgaben,
- keine Mutation von `repos/merges`,
- kein Force-Push auf geschützte Hauptbranches,
- kein Deaktivieren von Guards, um Tests grün zu machen.

## Repository-Rolle

Dieses Repo verantwortet:

- Grabowski-MCP-Code,
- Zugriffspolicy-Contract,
- sichere lokale Operationen,
- Tests,
- Deployment-Artefakte,
- Audit- und Rollbackmechanismen.

Die Heimgewebe-Fleet-Zugehörigkeit wird nicht lokal erfunden. Eine spätere
Registrierung muss über die kanonische Fleet-Source-of-Truth im Metarepo
erfolgen.
