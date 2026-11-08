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

## Chronik First – historische Evidenz vor Heimgewebe-Arbeit

Bei jedem neuen relevanten Heimgewebe-Arbeitsauftrag, bei Statusfragen und bei
Fortsetzung einer früheren Diagnose zuerst die bestehende schreibfreie
grabowski_chronik_full_search gezielt auf das Repository, den Host, die
Komponente, den PR oder die Aufgabe anwenden. Die Repository-Slugform muss
vollständig sein (beispielsweise heimgewebe/grabowski). Belegte frühere
Erkenntnisse und Fehlschläge vor erneuter Untersuchung berücksichtigen.

Danach den Ist-Zustand über Git, GitHub, CI, Runtime oder andere zuständige
Live-Primärquellen frisch prüfen. Chronik ist historische Evidenz, kein
Deploymentnachweis und keine Mutations- oder Retry-Autorität. Bei Ausfall den
fehlenden Historienabgleich transparent machen und regulär weiterarbeiten.
Bei sachfremden Aufgaben keine Chronik-Abfrage. Grabowski ist alleiniger
autorisierter Writer/Operator.

Der Agent-Bootstrap kann bei expliziter Zielbindung einen wirklichen
historischen Kurzkontext abrufen. Dokumentation:
docs/chronik-first-agent-start.md.

## Adaptive Einstiegskapsel

Für konkrete Statusfragen nur den engsten fachlich zuständigen, **nachweislich schreibfreien** Zugriff verwenden. Eine `READ_ONLY`-Annotation allein ist kein Nachweis: **Vor jedem Werkzeugaufruf** dessen mögliche direkte, bedingte und transitive Schreibeffekte prüfen. `grabowski_task_status` kann Task-Zustand und Leases ändern, `grabowski_task_list` Terminalisierungs-Recovery ausführen und `grabowski_resource_list` die Ressourcen-Datenbank anlegen oder migrieren. **Diese Werkzeuge sind keine schreibfreien Statusleser.** Für sie sowie jedes andere Werkzeug mit möglichen Schreibeffekten gelten **vor jedem Aufruf** sämtliche für diese Effekte erforderlichen Arbeits-, Lease-, Audit-, Kill-Switch- und Mutations-Gates – unabhängig davon, ob der Aufruf als Statusabfrage bezeichnet wird. Fehlt eine Voraussetzung, **nicht aufrufen**; stattdessen einen nachweislich schreibfreien und zulässigen Zugriff wählen oder die Abfrage abbrechen. `grabowski_context(profile="concise")` dient der quellenübergreifenden Orientierung, `grabowski_current_work` der kombinierten Arbeitslage aus Tasks, Leases, Checkouts und Prozessen; für beide gelten dieselben Prüfregeln, ihre Bezeichnung macht sie nicht schreibfrei. Eine Statusabfrage erteilt niemals Mutationsfreigabe. Review-, Captain- und Deployment-Gates bleiben zusätzlich an die jeweils von ihnen erfassten Aktionen gebunden.

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

## Systemkatalog-Konsultation

Bei repositoryübergreifenden Fragen zu Wahrheitsbesitz, Systemrolle, Zuständigkeitsgrenze, kanonischem Einstiegspunkt oder stabiler Beziehung zuerst den Systemkatalog abfragen. Für rein lokale Codefragen ist kein Katalogabruf nötig.

Wenn das Ergebnis eine Entscheidung ändert oder bestätigt, `tools/systemkatalog_usage_receipt.py` verwenden und einen hashgebundenen Nutzungsbeleg sichern. Nur feste Query-, Grund- und Wirkungskategorien verwenden; keine Gesprächsinhalte oder freie Begründungsprosa in den Beleg schreiben. `result_use` und `decision_effect` sind Operatorangaben und beweisen keine Kausalität. Vertrag und Beispiel: `docs/systemkatalog-usage-receipts-v1.md`.

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
- A canonical lane-backed `scoped_writer` is distinct from an advisory competitor or contrast agent. It may mutate only when the canonical route selects `executor=scoped_writer`, declares `route_role=scoped-writer`, sets `execution_eligible_if_separately_authorized=true`, is not `contrast_only`, and the exact Work Lane grants the requested write scope. Competition and `contrast_only` routes remain advisory.
- Generate a contrast matrix from bound receipts. Convert shared risks and tests into deterministic validation; investigate divergent boundaries instead of voting by majority.
- External agreement is not proof of correctness, and no automatic winner selection is permitted.


### Automatic hard-case second opinion: existing Source frontdoor

For each nontrivial source-bound task, independently assess repeated failures,
conflicting primary observations, and material architecture risk *before* reusing
a failed approach. Never wait for another user prompt solely to request a
read-only second perspective.

When invoking agent-execution-happy-path in Source mode, provide the optional
hard_case_advisory signal only when grounded in real event/readback evidence:

- repeated_failure: kind, two distinct evidence_refs for failures with the
  same normalized error identity, and one actual error_fingerprint (SHA-256).
  Include the existing prior-attempt-failed risk flag. Never synthesize receipts.
- contradictory_evidence: kind and two distinct evidence_refs from materially
  inconsistent current observations. Use novelty=high.
- material_architecture: kind and at least one concrete evidence_ref for a
  high-novelty architecture or migration decision with the high-risk flag.

The normal Source frontdoor selects the best eligible subscription-backed Claude
or Grok reviewer through the existing canonical model router and starts one
idempotent, advisory-only contrast Candidate. The contract fixes
max_budget_usd=0 and paid_execution_authorized=false. It exports only the
committed, redaction-checked README, not arbitrary workspaces, credentials
or private context. It never imposes a mandatory external PR review, selects
a winning patch, mutates a repository, or introduces a provider usage quota.

Read the returned competition_id with grabowski_agent_competition_status
before acting on any findings. A start receipt is not a completed second
opinion. Unavailable or ambiguous provider starts must be surfaced as such;
continue safe primary work and never blindly repeat unknown effects.

For ordinary investigations or existing threads that do not enter the AEF
Source frontdoor, the controller must still classify the same evidence and
call the existing advisory starter when warranted. The source-frontdoor
dispatch is automated but does not guarantee invocation in unrelated tools.
