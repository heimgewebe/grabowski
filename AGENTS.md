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

## Adaptive Einstiegskapsel

Bei nicht trivialer, breiter, transportempfindlicher oder mutierender Arbeit zuerst den frischen Runtime- und Connector-Zustand lesen und anschließend `grabowski_agent_bootstrap` verwenden.

Vor einem Toolaufruf mit mehreren Befehlen, mehreren unabhängigen Absichten, großer erwarteter Ausgabe oder möglicher Mutation `grabowski_call_shape_check` verwenden. Ein abgelehnter Shape wird vor Ausführung zerlegt.

Es gilt:

- genau eine unabhängige Absicht pro Toolaufruf,
- breite Reads begrenzen und getrennt ausführen,
- typed tool vor Grip, Grip vor Durable Task, Terminal nur ohne engeren Vertrag,
- pro Versuch höchstens eine Mutation,
- nach Mutationen den Zielzustand unmittelbar erneut lesen,
- bei Plattformfilter, Policy-Stop oder Operator-Stop kein unveränderter Retry,
- nach Transportabbruch mit möglicher Mutation den Ausgang als unbekannt behandeln und zuerst den Zielzustand lesen,
- Outcome-Daten nur aus beobachteten Ergebnissen schreiben.

Adaptive Hinweise bleiben Shadow-Vorschläge. Sie dürfen Benutzerabsicht, Autorisierung, Leases, Secret-Behandlung, Recovery, Kill-Switch, Review, Merge, Deployment oder privilegierte Ausführung nicht verändern.

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