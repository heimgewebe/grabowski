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
## Agent Workspace role ownership

- One operator may coordinate the Captain, Writer, Tests, Review and optional Observer workflow.
- Coordination does not collapse role evidence: the Writer remains the only mutating role; Tests and Review remain separately started, read-only and bound to the frozen writer head and diff.
- A single unisolated agent response may not substitute for Writer, Tests and Review evidence. This prevents self-confirming success.
- Prefer deterministic commands for Tests. Review must consume the frozen diff and emit a structured receipt; use a separate model or process when available, but technical read-only isolation is mandatory either way.
- The Observer is optional and read-only. It reports facts, inferences and proposals separately and cannot retry, close, merge, deploy or mutate Bureau.
- Cross-workspace optimization requires at least two immutable reports and remains proposal-only. Accepted changes follow the normal task, review, test and rollback path.

## Adaptive workspace and external programming

- Do not use the full Agent Workspace for every edit. Small low-risk fixes, simple documentation changes and bounded deterministic edits may use a normal isolated worktree with tests and diff-bound review.
- Use the full Workspace for runtime/security changes, long or multi-file work, parallel or foreign state, and connector or execution-state uncertainty.
- External agents are optional competitor or contrast programmers, not sovereign writers. Use them when novelty, architecture, security, schema or concurrency risk creates multiple plausible implementations.
- Run at most two external candidates for one decision. Prefer one independent competitor and one deliberate contrast programmer rather than duplicate prompts.
- Export only explicitly selected UTF-8 context files. Never include secrets, credentials, browser data or unrestricted environment values.
- External patches are advisory. They may not modify the repository, commit, push, merge, deploy or update Bureau. The normal isolated Writer must explicitly integrate selected insights.
- Generate a contrast matrix from bound receipts. Convert shared risks and tests into deterministic validation; investigate divergent boundaries instead of voting by majority.
- External agreement is not proof of correctness, and no automatic winner selection is permitted.
